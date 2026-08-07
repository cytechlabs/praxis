"""PRA-150: agent identity service.

Owns the M13 thin agent's lifecycle on the control-plane side:

    not_enrolled -> active <-> disabled
                       |
                       v
                    revoked  (terminal — cert serial blocklisted)

The Vault PKI mount ``praxis-agent-ca`` (provisioned in init-vault.sh)
mints short-lived (1h) mTLS certs for agents. This service orchestrates:

  * ``issue_for_bootstrap`` — first-time enrollment. Caller has already
    proven identity out-of-band (M13: SSH-once bootstrap; M14 will switch
    to activation-token bootstrap). Moves the system from
    ``not_enrolled`` to ``active``.

  * ``renew`` — agent re-CSRs every ~45 min over the live tunnel.
    Backend signs if status is ``active``. A 24h grace window covers
    short offline periods: if the existing cert expired up to 24h ago,
    we still re-sign. Beyond grace, agent must re-enroll.

  * ``disable`` / ``enable`` — reversible operator pause. ``disabled``
    refuses CSR renewal but the existing cert lives until its TTL
    expires (max 1h).

  * ``revoke`` — terminal. Status flips to ``revoked``, serial recorded
    as the last-used identity. Existing tunnel must be killed by the
    caller (PRA-151 will wire that into the tunnel registry).

Every state transition emits an ``agent.*`` audit event via
``audit_event_service.safe_emit`` so cert lifecycle is captured in the
same audit chain as session/access actions (PRA-143 schema).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session

from ..db.models import System
from .vault_service import VaultConnectionError, VaultSecretError, VaultService

logger = logging.getLogger(__name__)

# Renewal grace: backend will re-sign for this long after a cert expires,
# provided agent_status is still active. Covers short offline windows.
RENEWAL_GRACE = timedelta(hours=24)

# Default cert lifetime requested from Vault (role caps at 1h).
DEFAULT_TTL_SECONDS = 3600

# Backend-controlled CN domain. The Vault role is constrained to subdomains
# of this name so CSR-supplied CNs cannot influence cert identity. Real
# identity lives in URI SAN = praxis://system/<id>.
AGENT_CN_DOMAIN = "agent.praxis.internal"


def _agent_cn(system_id: int) -> str:
    return f"system-{system_id}.{AGENT_CN_DOMAIN}"


class AgentIdentityError(Exception):
    """Raised for any agent identity operation failure."""


class AgentIdentityService:
    """Orchestrates agent cert issue / renew / revoke and status lifecycle."""

    def __init__(self, db: Session):
        self.db = db
        self.vault = VaultService(db)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _fingerprint(cert_pem: str) -> str:
        """SHA-256 fingerprint of a PEM cert as lowercase hex (no colons)."""
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def _expiration_to_datetime(epoch_or_iso: Any) -> datetime:
        """Vault returns expiration as a unix epoch int — coerce to a naive
        UTC datetime so comparisons against datetime.utcnow() are valid."""
        if isinstance(epoch_or_iso, (int, float)):
            return datetime.utcfromtimestamp(int(epoch_or_iso))
        # Defensive: some Vault versions return iso strings. Normalize to
        # naive UTC by stripping tzinfo after conversion.
        parsed = datetime.fromisoformat(str(epoch_or_iso).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed

    def _load_system(self, system_id: int) -> System:
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise AgentIdentityError(f"System {system_id} not found")
        return system

    def _sign(self, system: System, csr_pem: str) -> Dict[str, Any]:
        """Call Vault to sign a CSR for this system. Returns parsed metadata.

        CN is backend-controlled (system-<id>.agent.praxis.internal); the
        Vault role discards the CSR's own CN/SANs (use_csr_common_name=
        use_csr_sans=false). Real identity is the URI SAN.
        """
        common_name = _agent_cn(system.id)
        uri_san = f"praxis://system/{system.id}"
        try:
            signed = self.vault.sign_agent_csr(
                csr_pem=csr_pem,
                common_name=common_name,
                uri_san=uri_san,
                ttl_seconds=DEFAULT_TTL_SECONDS,
            )
        except (VaultConnectionError, VaultSecretError) as e:
            raise AgentIdentityError(f"Vault signing failed: {e}") from e

        cert_pem = signed["certificate"]
        return {
            "certificate": cert_pem,
            "serial_number": signed["serial_number"],
            "fingerprint": self._fingerprint(cert_pem),
            "expires_at": self._expiration_to_datetime(signed["expiration"]),
            "ca_chain": signed.get("ca_chain") or [],
            "issuing_ca": signed.get("issuing_ca"),
        }

    # ------------------------------------------------------------------ public

    def get_ca_bundle(self) -> Optional[str]:
        """Return the agent CA root cert (PEM) for client trust distribution."""
        try:
            return self.vault.get_agent_ca_bundle()
        except (VaultConnectionError, VaultSecretError) as e:
            raise AgentIdentityError(f"Cannot fetch agent CA bundle: {e}") from e

    def issue_for_bootstrap(
        self,
        system_id: int,
        csr_pem: str,
        actor_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """First-time enrollment. Caller has already authenticated the request
        out-of-band (SSH-once in M13). Transitions ``not_enrolled`` or
        ``disabled`` -> ``active``. Refuses ``revoked``.
        """
        system = self._load_system(system_id)
        if system.agent_status == "revoked":
            self._audit(
                "agent.cert.issued",
                outcome="denied",
                system=system,
                actor_user_id=actor_user_id,
                context={"reason": "system revoked"},
            )
            raise AgentIdentityError(f"System {system_id} is revoked; bootstrap denied")

        result = self._sign(system, csr_pem)

        system.agent_status = "active"
        system.agent_cert_serial = result["serial_number"]
        system.agent_cert_fingerprint = result["fingerprint"]
        system.agent_cert_expires_at = result["expires_at"]
        # Clear any prior revocation metadata if we're transitioning out of
        # disabled (revoked is terminal so we never reach here).
        system.agent_revoked_at = None
        system.agent_revocation_reason = None
        system.agent_status_reason = None
        self.db.commit()

        logger.info(
            "agent bootstrap issued for system %s (serial=%s)",
            system_id,
            result["serial_number"],
        )
        self._audit(
            "agent.cert.issued",
            system=system,
            actor_user_id=actor_user_id,
            context={
                "serial_number": result["serial_number"],
                "fingerprint": result["fingerprint"],
                "expires_at": result["expires_at"].isoformat() + "Z",
            },
        )
        return self._response(system, result)

    def renew(
        self,
        system_id: int,
        csr_pem: str,
        actor_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Renew an agent cert. Requires status ``active``. Honors a 24h
        grace window past expiry so brief offline periods don't force
        re-enrollment.
        """
        system = self._load_system(system_id)
        if system.agent_status != "active":
            self._audit(
                "agent.cert.renewed",
                outcome="denied",
                system=system,
                actor_user_id=actor_user_id,
                context={"reason": f"status {system.agent_status}"},
            )
            raise AgentIdentityError(
                f"System {system_id} status is {system.agent_status}; renewal denied"
            )

        # Grace window check: if cert expired more than RENEWAL_GRACE ago,
        # require re-enrollment via bootstrap path.
        now = datetime.utcnow()
        if system.agent_cert_expires_at is not None:
            grace_deadline = system.agent_cert_expires_at + RENEWAL_GRACE
            if now > grace_deadline:
                self._audit(
                    "agent.cert.renewed",
                    outcome="denied",
                    system=system,
                    actor_user_id=actor_user_id,
                    context={"reason": "expired beyond grace"},
                )
                raise AgentIdentityError(
                    f"System {system_id} cert expired beyond grace window; "
                    f"re-enrollment required"
                )

        result = self._sign(system, csr_pem)

        system.agent_cert_serial = result["serial_number"]
        system.agent_cert_fingerprint = result["fingerprint"]
        system.agent_cert_expires_at = result["expires_at"]
        self.db.commit()

        logger.info(
            "agent cert renewed for system %s (serial=%s)",
            system_id,
            result["serial_number"],
        )
        self._audit(
            "agent.cert.renewed",
            system=system,
            actor_user_id=actor_user_id,
            context={
                "serial_number": result["serial_number"],
                "fingerprint": result["fingerprint"],
                "expires_at": result["expires_at"].isoformat() + "Z",
            },
        )
        return self._response(system, result)

    def disable(
        self,
        system_id: int,
        reason: Optional[str] = None,
        actor_user_id: Optional[int] = None,
    ) -> System:
        """Pause agent (reversible). active -> disabled.

        ``reason`` is stored in ``agent_status_reason`` (cleared on
        re-enable). ``agent_revocation_reason`` is reserved for terminal
        revocation only.
        """
        system = self._load_system(system_id)
        if system.agent_status not in ("active", "disabled"):
            raise AgentIdentityError(
                f"Cannot disable from status {system.agent_status}"
            )
        system.agent_status = "disabled"
        system.agent_status_reason = reason
        self.db.commit()
        logger.info("agent disabled for system %s (reason=%s)", system_id, reason)
        self._audit(
            "agent.disabled",
            system=system,
            actor_user_id=actor_user_id,
            context={"reason": reason},
        )
        return system

    def enable(self, system_id: int, actor_user_id: Optional[int] = None) -> System:
        """Resume agent. disabled -> active. The next renewal call from the
        agent will be honored. If the cert expired during the disabled
        period and is past grace, the agent must re-bootstrap.
        """
        system = self._load_system(system_id)
        if system.agent_status != "disabled":
            raise AgentIdentityError(f"Cannot enable from status {system.agent_status}")
        system.agent_status = "active"
        system.agent_status_reason = None
        self.db.commit()
        logger.info("agent enabled for system %s", system_id)
        self._audit("agent.enabled", system=system, actor_user_id=actor_user_id)
        return system

    def revoke(
        self,
        system_id: int,
        reason: str,
        actor_user_id: Optional[int] = None,
    ) -> System:
        """Terminal revoke. {active,disabled} -> revoked. Existing tunnel
        is the caller's responsibility to terminate (PRA-151)."""
        system = self._load_system(system_id)
        if system.agent_status == "revoked":
            return system  # idempotent
        if system.agent_status == "not_enrolled":
            raise AgentIdentityError("Cannot revoke a never-enrolled system")
        prior_serial = system.agent_cert_serial
        system.agent_status = "revoked"
        system.agent_revoked_at = datetime.utcnow()
        system.agent_revocation_reason = reason
        self.db.commit()
        logger.warning(
            "agent revoked for system %s (serial=%s, reason=%s)",
            system_id,
            prior_serial,
            reason,
        )
        self._audit(
            "agent.cert.revoked",
            system=system,
            actor_user_id=actor_user_id,
            context={"reason": reason, "serial_number": prior_serial},
        )
        return system

    def is_serial_active(self, serial: str) -> bool:
        """Tunnel-admission gate (PRA-151): True iff a System currently has
        agent_status=active, this serial as its cert, and the cert has not
        expired. Renewal grace is intentionally NOT applied here — grace
        belongs in renew(), not in tunnel admission.
        """
        if not serial:
            return False
        system = (
            self.db.query(System).filter(System.agent_cert_serial == serial).first()
        )
        if not system or system.agent_status != "active":
            return False
        if not system.agent_cert_expires_at:
            return False
        return system.agent_cert_expires_at > datetime.utcnow()

    # ------------------------------------------------------------------ audit

    def _audit(
        self,
        action: str,
        *,
        system: System,
        outcome: str = "success",
        actor_user_id: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit an agent.* audit event. Lazy import keeps this module light
        and matches the pattern used by other services."""
        try:
            from .audit_event_service import safe_emit  # local import on hot path

            safe_emit(
                db=self.db,
                action=action,
                outcome=outcome,
                actor_user_id=actor_user_id,
                target_kind="system",
                target_system_id=system.id,
                target_id=str(system.id),
                context=context or {},
            )
        except Exception:  # pylint: disable=broad-except
            # safe_emit already swallows errors, but keep belt-and-suspenders.
            pass

    # ------------------------------------------------------------------ output

    @staticmethod
    def _response(system: System, signed: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "system_id": system.id,
            "hostname": system.hostname,
            "certificate": signed["certificate"],
            "ca_chain": signed.get("ca_chain") or [],
            "serial_number": signed["serial_number"],
            "fingerprint": signed["fingerprint"],
            "expires_at": signed["expires_at"].isoformat() + "Z",
            "agent_status": system.agent_status,
        }
