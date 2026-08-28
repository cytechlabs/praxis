"""Lifecycle for guided onboarding drafts.

Owns every write to ``system_onboarding_drafts``: creation, the per-step
version protocol, the finalization claim, the finalization transaction itself,
cancellation, and the sweeper that keeps the table bounded.

Three properties hold no matter how a session ends.

*Nothing permanent exists until Finish.* A draft holds intent and evidence, not
a host. Failing, cancelling, expiring or simply closing the tab leaves no
``System``, no metadata, no host-key row, and no consumed license seat, because
the capacity gate and the inserts live together inside one transaction that
runs once, at the end.

*A draft belongs to one operator.* It carries a host-key approval and a
verification result, so a second actor adopting it would be inheriting
decisions they never made. Resumption is bound to the creating user, and to the
authority that user held when the draft was opened: a changed role or fleet
scope invalidates the draft rather than quietly finalizing under authority the
operator no longer has.

*Concurrency is settled in the database, not in a worker.* Step writes carry
the version they read and lose if it moved. Finalization is a single atomic
claim, so of two tabs racing to finish, exactly one proceeds and the other is
told why. What survives both is the ``systems`` uniqueness the database
enforces on hostname and address.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import text as sa_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..api.schemas import onboarding as schemas
from ..db.models import Credential, Distro, Group, System, SystemMetadata, User
from ..db.onboarding_models import (
    DRAFT_STATUS_ACTIVE,
    DRAFT_STATUS_CANCELED,
    DRAFT_STATUS_COMPLETED,
    DRAFT_STATUS_EXPIRED,
    DRAFT_STATUS_FINALIZING,
    HOST_KEY_PENDING,
    HOST_KEY_TRUSTED,
    SCOPE_SCOPED,
    SCOPE_TENANT_WIDE,
    STEP_CONNECT,
    SystemOnboardingDraft,
)
from ..db.ssh_security_models import SSHSecurityPolicy
from . import license_service
from .access_authorization_service import scoped_system_ids
from .onboarding_preflight_service import policy_requires_host_key_verification
from .ssh_service import SSHConnectionError, persist_verified_host_key
from .system_audit_service import record_audit, snapshot_system
from .system_tag_service import set_system_tags

logger = logging.getLogger(__name__)

# A draft slides forward on each step so an operator working through the wizard
# is never timed out mid-flow, but can never renew past the absolute ceiling.
DRAFT_TTL_MINUTES = 60
DRAFT_ABSOLUTE_TTL_HOURS = 8

# Completed, canceled and expired drafts are kept briefly so the UI can still
# explain what happened, then removed. The durable record is the audit trail.
DRAFT_RETENTION_DAYS = 7

# A finalization claim is held only while one synchronous transaction runs. This
# bound is far longer than that work takes, so releasing a lease means the
# worker holding it died, not that it was slow.
FINALIZE_LEASE_MINUTES = 10

# Domain separation: the digest of a finalization token is useless anywhere else,
# and a digest from another subsystem can never be replayed as one of these.
_FINALIZE_TOKEN_DOMAIN = b"praxis.onboarding.finalize_token.v1"
_AUTHORITY_DOMAIN = "praxis.onboarding.authority.v1"

# The group every host lands in unless the operator picks another.
DEFAULT_GROUP_NAME = "All Systems"
DEFAULT_POLICY_NAME = "Default"


class DraftError(Exception):
    """A draft operation failed with a structured, operator-safe code."""

    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# Actor authority                                                              #
# --------------------------------------------------------------------------- #


def scope_kind(db: Session, user: User) -> str:
    """Whether the user currently holds tenant-wide fleet scope."""
    return SCOPE_TENANT_WIDE if scoped_system_ids(db, user) is None else SCOPE_SCOPED


def authority_digest(db: Session, user: User) -> str:
    """Digest of the actor's canonical role set and scope kind.

    Roles are sorted so the digest depends on which roles are held, not on the
    order the ORM happened to return them. Comparing the digest, rather than
    re-running a permission check alone, catches a role that was added as well
    as one that was removed.
    """
    roles = sorted({(role.name or "") for role in (user.roles or [])})
    material = json.dumps(
        {
            "domain": _AUTHORITY_DOMAIN,
            "user_id": user.id,
            "roles": roles,
            "scope": scope_kind(db, user),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def assert_authority_unchanged(db: Session, draft: SystemOnboardingDraft, user: User):
    """Fail closed when the actor's authority no longer matches the draft."""
    if not hmac.compare_digest(
        draft.actor_authority_digest, authority_digest(db, user)
    ):
        raise DraftError(
            "authority_changed",
            "Your roles or fleet access changed after this setup was started. "
            "Start it again so it runs with your current access.",
            status_code=409,
        )


# --------------------------------------------------------------------------- #
# Finalization token                                                           #
# --------------------------------------------------------------------------- #


def _hash_finalize_token(token: str) -> str:
    """Domain-separated digest of a finalization token."""
    return hmac.new(
        _FINALIZE_TOKEN_DOMAIN, token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _verify_finalize_token(draft: SystemOnboardingDraft, token: str) -> bool:
    """Constant-time comparison against the stored digest."""
    if not draft.finalize_token_hash:
        return False
    return hmac.compare_digest(draft.finalize_token_hash, _hash_finalize_token(token))


# --------------------------------------------------------------------------- #
# Creation and loading                                                         #
# --------------------------------------------------------------------------- #


def _now() -> datetime:
    return datetime.utcnow()


def create_draft(db: Session, user: User) -> SystemOnboardingDraft:
    """Open a new draft owned by ``user``."""
    now = _now()
    draft = SystemOnboardingDraft(
        public_id=secrets.token_urlsafe(32),
        actor_user_id=user.id,
        actor_authority_digest=authority_digest(db, user),
        actor_scope_kind=scope_kind(db, user),
        status=DRAFT_STATUS_ACTIVE,
        current_step=STEP_CONNECT,
        state_version=0,
        expires_at=now + timedelta(minutes=DRAFT_TTL_MINUTES),
        absolute_expires_at=now + timedelta(hours=DRAFT_ABSOLUTE_TTL_HOURS),
        connection={},
        organization={"tags": []},
        host_key_decision=HOST_KEY_PENDING,
        verification_skipped=False,
        created_at=now,
        updated_at=now,
    )
    db.add(draft)
    db.commit()
    db.refresh(draft)
    return draft


def load_draft(
    db: Session, user: User, public_id: str, *, require_active: bool = True
) -> SystemOnboardingDraft:
    """Load a draft the caller owns.

    A draft belonging to somebody else is reported as missing rather than
    forbidden: whether another operator is setting up a host is not information
    this endpoint should confirm.
    """
    draft = (
        db.query(SystemOnboardingDraft)
        .filter(
            SystemOnboardingDraft.public_id == public_id,
            SystemOnboardingDraft.actor_user_id == user.id,
        )
        .first()
    )
    if draft is None:
        raise DraftError("draft_not_found", "Setup not found.", status_code=404)

    if draft.status in (DRAFT_STATUS_EXPIRED,) or (
        draft.status == DRAFT_STATUS_ACTIVE and draft.expires_at <= _now()
    ):
        if draft.status != DRAFT_STATUS_EXPIRED:
            draft.status = DRAFT_STATUS_EXPIRED
            db.commit()
        if require_active:
            raise DraftError(
                "draft_expired",
                "This setup expired. Nothing was added, so you can start again.",
                status_code=409,
            )
        return draft

    if require_active and draft.status == DRAFT_STATUS_CANCELED:
        raise DraftError("draft_canceled", "This setup was canceled.", status_code=409)
    if require_active and draft.status == DRAFT_STATUS_COMPLETED:
        raise DraftError(
            "already_finalized",
            "This setup already finished.",
            status_code=409,
        )
    if require_active and draft.status == DRAFT_STATUS_FINALIZING:
        raise DraftError(
            "finalization_in_progress",
            "This setup is being finished already.",
            status_code=409,
        )
    return draft


# --------------------------------------------------------------------------- #
# Step writes                                                                  #
# --------------------------------------------------------------------------- #


def _assert_json_bounds(name: str, payload: Optional[Dict[str, Any]]) -> None:
    """Refuse a payload large enough to make drafts a storage surface."""
    if payload is None:
        return
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(encoded) > schemas.MAX_JSON_BYTES:
        raise DraftError(
            "payload_too_large",
            f"The {name} for this setup is too large.",
            status_code=400,
        )


def apply_step(
    db: Session,
    draft: SystemOnboardingDraft,
    *,
    expected_version: Optional[int],
    changes: Dict[str, Any],
    next_step: Optional[str] = None,
    rotate_finalize_token: bool = True,
) -> SystemOnboardingDraft:
    """Apply one step's changes under optimistic concurrency.

    ``expected_version`` of ``None`` means the caller did not read a version and
    accepts the current one. Any other value must still match, so two tabs
    cannot interleave into a draft that reflects neither.

    Mutating a draft invalidates any outstanding finalization token: a
    confirmation the operator gave before the change no longer describes what
    would be created.
    """
    for name in ("connection", "organization", "verification", "discovery"):
        if name in changes:
            _assert_json_bounds(name, changes[name])

    if expected_version is not None and expected_version != draft.state_version:
        raise DraftError(
            "draft_stale",
            "This setup changed in another tab. Reload it and try again.",
            status_code=409,
        )

    assignments = dict(changes)
    if next_step is not None:
        assignments["current_step"] = next_step
    if rotate_finalize_token:
        assignments["finalize_token_hash"] = None

    result = db.execute(
        sa_text("""
            UPDATE system_onboarding_drafts
               SET state_version = state_version + 1,
                   updated_at = :now,
                   expires_at = LEAST(:slide, absolute_expires_at)
             WHERE id = :id
               AND status = :active
               AND state_version = :version
               AND expires_at > :now
            RETURNING id
            """),
        {
            "id": draft.id,
            "active": DRAFT_STATUS_ACTIVE,
            "version": draft.state_version,
            "now": _now(),
            "slide": _now() + timedelta(minutes=DRAFT_TTL_MINUTES),
        },
    ).fetchone()

    if result is None:
        db.rollback()
        raise DraftError(
            "draft_stale",
            "This setup changed or expired. Reload it and try again.",
            status_code=409,
        )

    for key, value in assignments.items():
        setattr(draft, key, value)
    db.commit()
    db.refresh(draft)
    return draft


def issue_finalize_token(db: Session, draft: SystemOnboardingDraft) -> str:
    """Mint the confirmation token, storing only its digest.

    Returned once, when the Confirm step is built. It is not recoverable from
    the database afterwards, so a database read cannot be turned into the
    ability to finalize somebody's draft.
    """
    token = secrets.token_urlsafe(32)
    draft.finalize_token_hash = _hash_finalize_token(token)
    draft.updated_at = _now()
    db.commit()
    return token


# --------------------------------------------------------------------------- #
# Cancellation and cleanup                                                     #
# --------------------------------------------------------------------------- #


def cancel_draft(db: Session, draft: SystemOnboardingDraft) -> SystemOnboardingDraft:
    """Cancel a draft. Nothing permanent exists, so nothing is undone."""
    draft.status = DRAFT_STATUS_CANCELED
    draft.canceled_at = _now()
    draft.finalize_token_hash = None
    draft.updated_at = _now()
    db.commit()
    db.refresh(draft)
    return draft


def sweep_drafts(db: Session, *, now: Optional[datetime] = None) -> Dict[str, int]:
    """Expire, release and prune drafts. Safe to run from any worker.

    Returns per-action counts so the scheduler log says what actually happened.
    """
    now = now or _now()

    released = db.execute(
        sa_text("""
            UPDATE system_onboarding_drafts
               SET status = :active, finalizing_since = NULL, updated_at = :now
             WHERE status = :finalizing
               AND finalizing_since IS NOT NULL
               AND finalizing_since < :lease_cutoff
            """),
        {
            "active": DRAFT_STATUS_ACTIVE,
            "finalizing": DRAFT_STATUS_FINALIZING,
            "now": now,
            "lease_cutoff": now - timedelta(minutes=FINALIZE_LEASE_MINUTES),
        },
    ).rowcount

    expired = db.execute(
        sa_text("""
            UPDATE system_onboarding_drafts
               SET status = :expired, finalize_token_hash = NULL, updated_at = :now
             WHERE status IN (:active, :finalizing)
               AND expires_at <= :now
            """),
        {
            "expired": DRAFT_STATUS_EXPIRED,
            "active": DRAFT_STATUS_ACTIVE,
            "finalizing": DRAFT_STATUS_FINALIZING,
            "now": now,
        },
    ).rowcount

    pruned = db.execute(
        sa_text("""
            DELETE FROM system_onboarding_drafts
             WHERE status IN (:expired, :canceled, :completed)
               AND updated_at < :retention_cutoff
            """),
        {
            "expired": DRAFT_STATUS_EXPIRED,
            "canceled": DRAFT_STATUS_CANCELED,
            "completed": DRAFT_STATUS_COMPLETED,
            "retention_cutoff": now - timedelta(days=DRAFT_RETENTION_DAYS),
        },
    ).rowcount

    db.commit()
    return {"released": released, "expired": expired, "pruned": pruned}


# --------------------------------------------------------------------------- #
# Finalization                                                                 #
# --------------------------------------------------------------------------- #


def claim_for_finalization(db: Session, draft: SystemOnboardingDraft) -> bool:
    """Atomically take the right to finalize this draft.

    The claim is the ``UPDATE ... RETURNING`` itself, so two workers racing on
    the same draft resolve in the database. Exactly one sees a row.
    """
    claimed = db.execute(
        sa_text("""
            UPDATE system_onboarding_drafts
               SET status = :finalizing, finalizing_since = :now, updated_at = :now
             WHERE id = :id
               AND status = :active
               AND expires_at > :now
            RETURNING id
            """),
        {
            "id": draft.id,
            "finalizing": DRAFT_STATUS_FINALIZING,
            "active": DRAFT_STATUS_ACTIVE,
            "now": _now(),
        },
    ).fetchone()
    db.commit()
    if claimed is None:
        return False
    db.refresh(draft)
    return True


def release_claim(db: Session, draft: SystemOnboardingDraft) -> None:
    """Return a claimed draft to active after a failed finalization."""
    try:
        db.rollback()
        db.execute(
            sa_text("""
                UPDATE system_onboarding_drafts
                   SET status = :active, finalizing_since = NULL, updated_at = :now
                 WHERE id = :id AND status = :finalizing
                """),
            {
                "id": draft.id,
                "active": DRAFT_STATUS_ACTIVE,
                "finalizing": DRAFT_STATUS_FINALIZING,
                "now": _now(),
            },
        )
        db.commit()
    except Exception:  # pylint: disable=broad-except
        logger.exception("failed to release onboarding finalization claim")


def resolve_default_group(db: Session) -> Optional[Group]:
    """The group a host lands in when the operator did not choose one."""
    group = db.query(Group).filter(Group.name == DEFAULT_GROUP_NAME).first()
    if group is not None:
        return group
    return db.query(Group).order_by(Group.id).first()


def resolve_default_policy(db: Session) -> Optional[SSHSecurityPolicy]:
    """The SSH policy a host uses when the operator did not choose one."""
    return (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.name == DEFAULT_POLICY_NAME)
        .first()
    )


def resolve_hostname(draft: SystemOnboardingDraft) -> Optional[str]:
    """The hostname a finished host is registered under.

    The operator's proposal wins, then what the host called itself, then the
    address when it was a name rather than a number.
    """
    connection = draft.connection or {}
    discovery = draft.discovery or {}
    for candidate in (
        connection.get("hostname"),
        discovery.get("effective_hostname"),
        connection.get("address"),
    ):
        if not candidate:
            continue
        try:
            ipaddress.ip_address(str(candidate))
        except ValueError:
            return str(candidate)
    return None


def resolve_ip(draft: SystemOnboardingDraft) -> Optional[str]:
    """The concrete address to register.

    Verification records what it actually connected to, so a name that has since
    started resolving elsewhere does not silently register a different host.
    """
    connection = draft.connection or {}
    if connection.get("resolved_ip"):
        return str(connection["resolved_ip"])
    address = connection.get("address")
    if not address:
        return None
    try:
        ipaddress.ip_address(str(address))
    except ValueError:
        return None
    return str(address)


def build_finalization_preview(
    db: Session, draft: SystemOnboardingDraft
) -> Dict[str, Any]:
    """What Finish would create, for the Confirm step to display."""
    organization = draft.organization or {}
    group = None
    if organization.get("group_id"):
        group = db.query(Group).filter(Group.id == organization["group_id"]).first()
    if group is None:
        group = resolve_default_group(db)

    policy = None
    if draft.ssh_security_policy_id:
        policy = (
            db.query(SSHSecurityPolicy)
            .filter(SSHSecurityPolicy.id == draft.ssh_security_policy_id)
            .first()
        )
    if policy is None:
        policy = resolve_default_policy(db)

    verified = bool((draft.verification or {}).get("verified"))
    return {
        "hostname": resolve_hostname(draft),
        "ip_address": resolve_ip(draft),
        "ssh_port": (draft.connection or {}).get("ssh_port"),
        "group": {"id": group.id, "name": group.name} if group else None,
        "ssh_security_policy": (
            {"id": policy.id, "name": policy.name} if policy else None
        ),
        "environment": organization.get("environment") or "Production",
        "description": organization.get("description"),
        "tags": organization.get("tags") or [],
        "transport_preference": organization.get("transport_preference") or "auto",
        "update_policy": organization.get("update_policy"),
        "status": "Active" if verified else "Inactive",
        "verified": verified,
        "verification_skipped": bool(draft.verification_skipped),
        "host_key_fingerprint": draft.host_key_fingerprint,
        "host_key_decision": draft.host_key_decision,
    }


def _validate_references(
    db: Session, draft: SystemOnboardingDraft
) -> Tuple[Credential, Group, Optional[SSHSecurityPolicy], Optional[Distro]]:
    """Re-resolve everything the draft points at, at finalization time."""
    credential = (
        db.query(Credential).filter(Credential.id == draft.credential_id).first()
        if draft.credential_id
        else None
    )
    if credential is None:
        raise DraftError(
            "reference_missing",
            "The credential chosen for this host is no longer available. "
            "Choose another and finish again.",
            status_code=409,
        )

    organization = draft.organization or {}
    group = None
    if organization.get("group_id"):
        group = db.query(Group).filter(Group.id == organization["group_id"]).first()
        if group is None:
            raise DraftError(
                "reference_missing",
                "The group chosen for this host no longer exists.",
                status_code=409,
            )
    else:
        group = resolve_default_group(db)
    if group is None:
        raise DraftError(
            "reference_missing",
            "No group is available to place this host in.",
            status_code=409,
        )

    policy = None
    if draft.ssh_security_policy_id:
        policy = (
            db.query(SSHSecurityPolicy)
            .filter(SSHSecurityPolicy.id == draft.ssh_security_policy_id)
            .first()
        )
        if policy is None:
            raise DraftError(
                "reference_missing",
                "The SSH policy chosen for this host no longer exists.",
                status_code=409,
            )
    else:
        policy = resolve_default_policy(db)

    distro = None
    if draft.distro_id:
        distro = db.query(Distro).filter(Distro.id == draft.distro_id).first()
        if distro is None:
            raise DraftError(
                "reference_missing",
                "The distribution chosen for this host no longer exists.",
                status_code=409,
            )

    return credential, group, policy, distro


def _assert_finalizable(
    db: Session,
    draft: SystemOnboardingDraft,
    user: User,
    finalize_token: str,
) -> Tuple[bool, Any, Any, Any, Any]:
    """Recheck everything that could have changed since Confirm.

    Returns ``(verified, credential, group, policy, distro)``. Raises
    ``DraftError`` with the operator-facing code for the first failed gate.
    """
    if not _verify_finalize_token(draft, finalize_token):
        raise DraftError(
            "replay_rejected",
            "This confirmation is no longer valid. Review the details and "
            "confirm again.",
            status_code=409,
        )

    assert_authority_unchanged(db, draft, user)

    verification = draft.verification or {}
    verified = bool(verification.get("verified"))
    if not verified and not draft.verification_skipped:
        raise DraftError(
            "verification_required",
            "Verify this host, or explicitly choose to skip verification, "
            "before finishing.",
            status_code=409,
        )

    credential, group, policy, distro = _validate_references(db, draft)

    if (
        verified
        and policy_requires_host_key_verification(policy)
        and draft.host_key_decision != HOST_KEY_TRUSTED
    ):
        raise DraftError(
            "host_key_not_trusted",
            "The host key has not been approved for this host.",
            status_code=409,
        )

    return verified, credential, group, policy, distro


def _resolve_target_identity(
    db: Session, draft: SystemOnboardingDraft
) -> Tuple[str, str]:
    """Resolve the hostname and address, refusing a duplicate of either."""
    hostname = resolve_hostname(draft)
    if not hostname:
        raise DraftError(
            "hostname_required",
            "This host needs a name. Provide one and finish again.",
            status_code=400,
        )
    ip_address = resolve_ip(draft)
    if not ip_address:
        raise DraftError(
            "address_unresolved",
            "Praxis could not determine this host's address. Verify the host "
            "and finish again.",
            status_code=409,
        )

    duplicate = (
        db.query(System)
        .filter((System.hostname == hostname) | (System.ip_address == ip_address))
        .first()
    )
    if duplicate is not None:
        raise DraftError(
            "duplicate_host",
            f"A system with this hostname or address already exists "
            f"({duplicate.hostname}).",
            status_code=409,
        )
    return hostname, ip_address


def _build_system(
    draft: SystemOnboardingDraft,
    user: User,
    *,
    verified: bool,
    hostname: str,
    ip_address: str,
    group: Any,
    credential: Any,
    policy: Any,
    distro: Any,
    now: datetime,
) -> System:
    """The managed host row this draft describes, not yet added to the session."""
    organization = draft.organization or {}
    return System(
        hostname=hostname,
        ip_address=ip_address,
        distro_id=distro.id,
        os_version=(draft.discovery or {}).get("distro_version") or distro.version,
        status="Active" if verified else "Inactive",
        group_id=group.id,
        credentials_id=credential.id,
        ssh_security_policy_id=policy.id if policy else None,
        transport_preference=organization.get("transport_preference") or "auto",
        update_policy=organization.get("update_policy"),
        description=organization.get("description"),
        registered_at=now,
        registered_by=user.id,
        created_at=now,
        updated_at=now,
    )


def _persist_system_rows(
    db: Session,
    draft: SystemOnboardingDraft,
    system: System,
    user: User,
    *,
    verified: bool,
    now: datetime,
) -> None:
    """Write metadata, tags, the audit row and the approved host key.

    Runs inside the caller's transaction, after ``system`` has been flushed so
    its id exists.
    """
    organization = draft.organization or {}
    connection = draft.connection or {}

    metadata = SystemMetadata(
        system_id=system.id,
        environment_type=organization.get("environment") or "Production",
        owner_contact=user.email,
        ssh_port=connection.get("ssh_port") or schemas.DEFAULT_SSH_PORT,
        cpu_arch=(draft.discovery or {}).get("architecture"),
        connection_status="connected" if verified else "Pending",
        last_connection=now if verified else None,
        created_at=now,
        updated_at=now,
    )
    db.add(metadata)

    set_system_tags(db, system, organization.get("tags") or [], created_by=user.id)

    record_audit(
        db,
        system_id=system.id,
        user_id=user.id,
        operation="create",
        audit_type="system",
        old_value=None,
        new_value=snapshot_system(system),
    )

    # The approved key is written through the shared host-key writer, inside
    # this transaction rather than after it. A host that requires host-key
    # verification must not be able to exist without the exact key the
    # operator approved: the two are one fact, so they commit together or
    # not at all. ``commit=False`` keeps the row bound to this transaction;
    # the helper still flushes, so a write failure surfaces here.
    if draft.host_key_public and draft.host_key_decision == HOST_KEY_TRUSTED:
        persist_verified_host_key(
            db,
            system=system,
            key_type=draft.host_key_type or "",
            public_key=draft.host_key_public,
            fingerprint=draft.host_key_fingerprint or "",
            commit=False,
        )


def _mark_draft_completed(
    draft: SystemOnboardingDraft, system: System, now: datetime
) -> None:
    """Retire the draft against the host it produced."""
    draft.status = DRAFT_STATUS_COMPLETED
    draft.finalized_system_id = system.id
    draft.completed_at = now
    draft.finalizing_since = None
    draft.finalize_token_hash = None
    draft.current_step = "finish"
    draft.updated_at = now


def finalize_draft(
    db: Session, draft: SystemOnboardingDraft, user: User, *, finalize_token: str
) -> Tuple[System, bool]:
    """Create the managed host this draft describes.

    Returns ``(system, created)``. ``created`` is ``False`` when the draft had
    already finished, which is what makes a repeated Finish safe: the operator
    gets the same host back rather than a second one.

    Caller must hold the finalization claim. Everything that could have changed
    since Confirm is rechecked here, and the capacity gate runs immediately
    before the insert, so a draft can never reserve a license seat it does not
    use. The host, its metadata, tags, audit row, approved host key and the
    draft's own retirement all commit together or not at all.
    """
    if draft.finalized_system_id:
        existing = (
            db.query(System).filter(System.id == draft.finalized_system_id).first()
        )
        if existing is not None:
            return existing, False

    verified, credential, group, policy, distro = _assert_finalizable(
        db, draft, user, finalize_token
    )
    hostname, ip_address = _resolve_target_identity(db, draft)

    if distro is None:
        raise DraftError(
            "distro_required",
            "Confirm this host's distribution before finishing.",
            status_code=409,
        )

    # Capacity is checked here and nowhere earlier, so an abandoned draft never
    # holds a seat.
    license_service.assert_can_add_host(db, actor_user_id=user.id)

    now = _now()
    system = _build_system(
        draft,
        user,
        verified=verified,
        hostname=hostname,
        ip_address=ip_address,
        group=group,
        credential=credential,
        policy=policy,
        distro=distro,
        now=now,
    )
    db.add(system)

    try:
        db.flush()
        _persist_system_rows(db, draft, system, user, verified=verified, now=now)
        _mark_draft_completed(draft, system, now)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        # The database is the last arbiter of uniqueness, so a race that beat
        # the query above still lands here rather than creating a second host.
        raise DraftError(
            "duplicate_host",
            "A system with this hostname or address already exists.",
            status_code=409,
        ) from exc
    except SSHConnectionError as exc:
        # A stored key that disagrees with the approved one. Not reachable for a
        # host being created for the first time, but it is the one host-key
        # failure with an operator-actionable answer, so it is reported as a
        # code rather than as an unhandled error.
        db.rollback()
        raise DraftError(
            "host_key_conflict",
            "A different host key is already stored for this host. Review it "
            "under SSH Security before adding the host.",
            status_code=409,
        ) from exc
    except Exception:
        # Anything else, including a failure to record the approved host key,
        # takes the whole finalization with it. Reporting success while the
        # trust row is missing would leave a verification-required host active
        # without the key it was approved on, and the draft's replay guard would
        # stop a retry from ever repairing it.
        db.rollback()
        raise

    db.refresh(system)
    return system, True
