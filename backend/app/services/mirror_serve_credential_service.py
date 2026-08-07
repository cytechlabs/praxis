"""Per-(host, mirror) bearer credential issuance + verification
(PRA-159 slice #2).

Hosts authenticate to ``GET /mirrors/{slug}/serve/{path:path}`` with
``Authorization: Bearer <token>``. Tokens are issued by Praxis
control-plane operators (or by the slice #3 apply orchestrator) and
embedded in the host's apt ``/etc/apt/auth.conf.d/...`` or dnf
``.repo`` (mode 0600 root) so they never leak into world-readable
``.list`` / ``.repo`` files.

Locked semantics:
  * Plaintext returned ONCE at issue, never stored or logged.
  * ``token_hash`` is passlib pbkdf2_sha256 — same scheme used by
    activation tokens (PRA-154) so the verify path is idiomatic.
    pbkdf2_sha256 is per-row salted, so there is no lookup-by-hash
    path. PRA-180 MIRROR-01: tokens are minted as
    ``<token_id>.<secret>`` and the public ``token_id`` is stored in
    its own indexed column, so verify() resolves the single matching
    row and runs ``pbkdf2_sha256.verify`` once instead of scanning
    every active credential. Legacy tokens (no ``.`` separator,
    ``token_id IS NULL``) fall back to a bounded scan over only the
    legacy rows.
  * Multiple active credentials per ``(host_id, mirror_id)`` are
    legal — the apply orchestrator (PRA-159 #3) issues a new
    credential, writes the host's ``auth.conf`` / ``.repo`` to use
    it, and ONLY THEN calls ``revoke_other_active_for_pair`` to
    take the prior bearer out of service. During the write window
    BOTH bearers verify, which is what preserves the host's
    last-good package access if any apply step fails.
  * ``verify(plaintext) -> Optional[HostMirrorServeCredential]``
    scans active candidates, refuses revoked / expired. Caller
    updates ``last_used_at`` best-effort.
  * Default TTL 365d, overridable per call. Renewal = issue (does
    NOT revoke the old; the caller is expected to call
    ``revoke_other_active_for_pair`` after the host config is in
    place).
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from passlib.hash import pbkdf2_sha256
from sqlalchemy.orm import Session

from ..db.models import HostMirrorServeCredential, MirrorRepo, System

logger = logging.getLogger(__name__)


DEFAULT_TTL_DAYS = 365

# 32 bytes of entropy → 43-char base64url (no padding). Roomy under
# the 255-char token_hash column even after passlib's hash framing.
TOKEN_BYTES = 32


@dataclass(frozen=True)
class IssueResult:
    """Outcome of a successful issue. Plaintext is single-use:
    return it to the operator and forget it."""

    plaintext: str
    credential_id: int
    host_id: int
    mirror_id: int
    issued_at: datetime
    expires_at: datetime


class MirrorServeCredentialError(Exception):
    """Domain error from the issue/revoke surface (caller maps to HTTP)."""


class MirrorServeCredentialService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ---- issue ------------------------------------------------------------

    def issue(
        self,
        *,
        host_id: int,
        mirror_id: int,
        ttl_days: int = DEFAULT_TTL_DAYS,
    ) -> IssueResult:
        """Generate a new credential for ``(host_id, mirror_id)``.

        Does NOT revoke any prior active credential — that's the
        caller's responsibility AFTER the host's ``auth.conf`` /
        ``.repo`` is updated to use the new bearer. Multiple active credentials for the same pair coexist
        cleanly; the verifier scans candidates and accepts any
        valid bearer.

        Validates that both rows exist (host + non-deleted mirror)
        before inserting.
        """
        if ttl_days <= 0:
            raise MirrorServeCredentialError("ttl_days must be positive")

        host = self.db.query(System).filter(System.id == host_id).one_or_none()
        if host is None:
            raise MirrorServeCredentialError(f"host {host_id} not found")
        mirror = (
            self.db.query(MirrorRepo)
            .filter(MirrorRepo.id == mirror_id, MirrorRepo.deleted_at.is_(None))
            .one_or_none()
        )
        if mirror is None:
            raise MirrorServeCredentialError(
                f"mirror {mirror_id} not found or soft-deleted"
            )

        now = datetime.utcnow()
        # PRA-180 MIRROR-01: mint ``<token_id>.<secret>``. ``token_id`` is a
        # public, non-secret lookup key stored in its own indexed column so
        # verify() finds the single matching row instead of scanning every
        # active credential. Only ``secret`` is hashed — it carries the entropy
        # that gates acceptance. Neither base16 ``token_id`` nor base64url
        # ``secret`` contains ".", so the single separator is unambiguous.
        token_id = secrets.token_hex(16)
        secret = secrets.token_urlsafe(TOKEN_BYTES)
        plaintext = f"{token_id}.{secret}"
        token_hash = pbkdf2_sha256.hash(secret)
        expires_at = now + timedelta(days=ttl_days)

        row = HostMirrorServeCredential(
            host_id=host_id,
            mirror_id=mirror_id,
            token_hash=token_hash,
            token_id=token_id,
            issued_at=now,
            expires_at=expires_at,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)

        # Note: plaintext is in this scope only. Logger gets identity
        # + lifecycle, NEVER the token bytes.
        logger.info(
            "issued mirror serve credential id=%d host_id=%d mirror_id=%d " "(ttl=%dd)",
            row.id,
            host_id,
            mirror_id,
            ttl_days,
        )
        return IssueResult(
            plaintext=plaintext,
            credential_id=row.id,
            host_id=host_id,
            mirror_id=mirror_id,
            issued_at=row.issued_at,
            expires_at=row.expires_at,
        )

    def revoke_other_active_for_pair(
        self, *, host_id: int, mirror_id: int, except_id: int
    ) -> List[int]:
        """Revoke every active credential for ``(host_id, mirror_id)``
        except ``except_id``.

        Called by the apply orchestrator AFTER the host's
        ``auth.conf`` / ``.repo`` has been updated to use the new
        bearer. The post-write call ensures last-good package access
        is preserved if anything in the apply path fails (the host
        keeps using the old bearer until the next successful apply
        revokes it).

        Returns the list of credential ids that were revoked. Empty
        list if there were no other active rows (e.g. fresh host).
        """
        now = datetime.utcnow()
        rows = (
            self.db.query(HostMirrorServeCredential)
            .filter(
                HostMirrorServeCredential.host_id == host_id,
                HostMirrorServeCredential.mirror_id == mirror_id,
                HostMirrorServeCredential.revoked_at.is_(None),
                HostMirrorServeCredential.id != except_id,
            )
            .all()
        )
        revoked_ids: List[int] = []
        for row in rows:
            row.revoked_at = now
            revoked_ids.append(row.id)
        if revoked_ids:
            self.db.commit()
            logger.info(
                "revoke_other_active_for_pair: host_id=%d mirror_id=%d "
                "kept=%d revoked=%s",
                host_id,
                mirror_id,
                except_id,
                revoked_ids,
            )
        return revoked_ids

    # ---- verify -----------------------------------------------------------

    def verify(self, plaintext: str) -> Optional[HostMirrorServeCredential]:
        """Verify a presented bearer.

        Returns the credential row when accepted, ``None`` otherwise
        (callers map None → 401).

        PRA-180 MIRROR-01: tokens minted as ``<token_id>.<secret>`` resolve in
        O(1) — look the single active row up by the indexed, public
        ``token_id`` and run ``pbkdf2_sha256.verify(secret, ...)`` against it.
        Tokens issued before this column existed have no ``.`` separator; they
        fall back to a bounded scan over only the legacy (``token_id IS NULL``)
        rows, which drains as those credentials expire/rotate. The secret is
        always what gates acceptance — ``token_id`` is a non-secret lookup key.
        """
        if not isinstance(plaintext, str) or not plaintext:
            return None

        now = datetime.utcnow()
        active = self.db.query(HostMirrorServeCredential).filter(
            HostMirrorServeCredential.revoked_at.is_(None),
            HostMirrorServeCredential.expires_at > now,
        )

        if "." in plaintext:
            # New format: O(1) lookup by the public token_id prefix.
            token_id, _, secret = plaintext.partition(".")
            if not token_id or not secret:
                return None
            candidates = active.filter(
                HostMirrorServeCredential.token_id == token_id
            ).all()
            return self._match(candidates, secret)

        # Legacy format (pre-MIRROR-01): the whole plaintext was hashed and no
        # token_id was stored. Bounded scan over legacy rows only.
        candidates = active.filter(HostMirrorServeCredential.token_id.is_(None)).all()
        return self._match(candidates, plaintext)

    @staticmethod
    def _match(
        candidates: List[HostMirrorServeCredential], secret: str
    ) -> Optional[HostMirrorServeCredential]:
        """Return the first candidate whose hash verifies ``secret``.

        A malformed hash on one row must not poison the loop for the others.
        """
        for row in candidates:
            try:
                if pbkdf2_sha256.verify(secret, row.token_hash):
                    return row
            except Exception:  # pylint: disable=broad-except
                logger.exception(
                    "malformed token_hash on credential id=%d (ignored)", row.id
                )
                continue
        return None

    def stamp_used(self, credential: HostMirrorServeCredential) -> None:
        """Best-effort ``last_used_at`` update.

        Called by the serve route after a successful verify. Failures
        are swallowed — last_used_at is a diagnostic, not a security
        signal; the request shouldn't fail because the timestamp
        write hit a deadlock.
        """
        try:
            credential.last_used_at = datetime.utcnow()
            self.db.commit()
        except Exception:  # pylint: disable=broad-except
            logger.warning(
                "failed to stamp last_used_at for credential id=%d", credential.id
            )
            self.db.rollback()

    # ---- revoke -----------------------------------------------------------

    def revoke(self, credential_id: int) -> bool:
        """Revoke a credential by id. Returns True on a fresh
        revocation, False if the row was already revoked or missing.
        """
        row = (
            self.db.query(HostMirrorServeCredential)
            .filter(HostMirrorServeCredential.id == credential_id)
            .one_or_none()
        )
        if row is None or row.revoked_at is not None:
            return False
        row.revoked_at = datetime.utcnow()
        self.db.commit()
        logger.info(
            "revoked mirror serve credential id=%d host_id=%d mirror_id=%d",
            row.id,
            row.host_id,
            row.mirror_id,
        )
        return True

    # ---- list / inspect ---------------------------------------------------

    def list_for_host(
        self, host_id: int, *, include_revoked: bool = False
    ) -> List[HostMirrorServeCredential]:
        q = self.db.query(HostMirrorServeCredential).filter(
            HostMirrorServeCredential.host_id == host_id
        )
        if not include_revoked:
            q = q.filter(HostMirrorServeCredential.revoked_at.is_(None))
        return q.order_by(HostMirrorServeCredential.issued_at.desc()).all()

    def get(self, credential_id: int) -> Optional[HostMirrorServeCredential]:
        return (
            self.db.query(HostMirrorServeCredential)
            .filter(HostMirrorServeCredential.id == credential_id)
            .one_or_none()
        )
