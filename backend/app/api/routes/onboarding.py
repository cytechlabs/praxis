"""Guided first-system onboarding.

Seven steps over one draft: connect, authenticate, verify, discover, organize,
confirm, finish. Each step is a separate call so an operator can go back,
change their mind, and re-run a step without losing the work either side of it.

Nothing here creates a managed host except ``finish``. Verification and
discovery run against the draft's parameters, so an operator can find out that
a host is unreachable, or that a password is wrong, without leaving a half-built
system in the inventory or spending a license seat on a host that never
connected.

Authorization is the same gate direct registration uses, and the capability
report on the draft tells the frontend what this operator may do before they
start filling anything in, rather than after a submission is refused.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.schemas import onboarding as schemas
from app.core.auth import get_user_roles, require_role
from app.db.models import Credential, Distro, Group, System, User
from app.db.onboarding_models import (
    HOST_KEY_PENDING,
    HOST_KEY_REJECTED,
    HOST_KEY_TRUSTED,
    STEP_AUTHENTICATE,
    STEP_CONFIRM,
    STEP_DISCOVER,
    STEP_ORGANIZE,
    STEP_VERIFY,
    SystemOnboardingDraft,
)
from app.db.session import get_db
from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import audit_event_service, license_service
from app.services import onboarding_draft_service as drafts
from app.services import onboarding_preflight_service as preflight
from app.services.access_authorization_service import scoped_system_ids
from app.services.notification_service import create_notification

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


def _fail(exc: drafts.DraftError) -> HTTPException:
    """Render a draft error as an HTTP error carrying its structured code."""
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
    )


def _actor_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


# --------------------------------------------------------------------------- #
# Capability reporting                                                         #
# --------------------------------------------------------------------------- #


def _capabilities(db: Session, user: User) -> Dict[str, Any]:
    """What this operator may do, resolved before any form is shown.

    The frontend uses this to shape the wizard rather than guessing from a role
    name. Creating a credential is tenant-wide only, matching the credential
    API, so a scoped maintainer is told up front that they must pick an existing
    credential instead of discovering it at submit time.
    """
    roles = get_user_roles(user)
    tenant_wide = scoped_system_ids(db, user) is None
    return {
        "can_onboard": any(role in ("admin", "maintainer") for role in roles),
        "can_create_credential": tenant_wide
        and any(role in ("admin", "maintainer") for role in roles),
        "scope": "tenant_wide" if tenant_wide else "scoped",
        "roles": roles,
    }


def _license_snapshot(db: Session) -> Dict[str, Any]:
    """Current host-cap position, so Confirm can be honest about capacity."""
    try:
        return license_service.host_cap_status(db)
    except Exception:  # pylint: disable=broad-except
        logger.warning("could not read host cap status for onboarding")
        return {}


# --------------------------------------------------------------------------- #
# Draft rendering                                                              #
# --------------------------------------------------------------------------- #


def _credential_summary(credential: Optional[Credential]) -> Optional[Dict[str, Any]]:
    """Non-secret credential metadata.

    Deliberately excludes the Vault path: which secret backs a credential is not
    something the onboarding surface needs to disclose.
    """
    if credential is None:
        return None
    return {
        "id": credential.id,
        "name": credential.name,
        "username": credential.username,
        "auth_method": credential.auth_method,
        "sudo_method": credential.sudo_method,
        "source": "linked" if credential.vault_path else "managed",
    }


def _render_draft(
    db: Session, draft: SystemOnboardingDraft, *, finalize_token: Optional[str] = None
) -> Dict[str, Any]:
    """The draft as the wizard sees it. No secrets, no transport text."""
    credential = (
        db.query(Credential).filter(Credential.id == draft.credential_id).first()
        if draft.credential_id
        else None
    )
    policy = (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.id == draft.ssh_security_policy_id)
        .first()
        if draft.ssh_security_policy_id
        else None
    )

    payload: Dict[str, Any] = {
        "id": draft.public_id,
        "status": draft.status,
        "current_step": draft.current_step,
        "state_version": draft.state_version,
        "expires_at": draft.expires_at.isoformat() if draft.expires_at else None,
        "connection": draft.connection or {},
        "organization": draft.organization or {},
        "verification": draft.verification,
        "discovery": draft.discovery,
        "verification_skipped": bool(draft.verification_skipped),
        "credential": _credential_summary(credential),
        "ssh_security_policy": (
            {"id": policy.id, "name": policy.name} if policy else None
        ),
        "host_key": {
            "fingerprint": draft.host_key_fingerprint,
            "key_type": draft.host_key_type,
            "decision": draft.host_key_decision,
        },
        "finalized_system_id": draft.finalized_system_id,
    }
    if finalize_token is not None:
        payload["finalize_token"] = finalize_token
    return payload


# --------------------------------------------------------------------------- #
# Draft lifecycle                                                              #
# --------------------------------------------------------------------------- #


@router.get("/capabilities")
async def get_capabilities(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """What the caller may do, plus current host-cap position."""
    return {
        "capabilities": _capabilities(db, current_user),
        "license": _license_snapshot(db),
    }


@router.post("/drafts", status_code=status.HTTP_201_CREATED)
async def create_draft(
    request: Request,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Open a setup. Creates no host and consumes no capacity."""
    draft = drafts.create_draft(db, current_user)
    audit_event_service.safe_emit(
        action="onboarding.draft.create",
        outcome="success",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
    )
    return {
        "draft": _render_draft(db, draft),
        "capabilities": _capabilities(db, current_user),
    }


@router.get("/drafts/{public_id}")
async def get_draft(
    public_id: str,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Resume a setup. Only its creator can."""
    try:
        draft = drafts.load_draft(db, current_user, public_id, require_active=False)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    return {
        "draft": _render_draft(db, draft),
        "capabilities": _capabilities(db, current_user),
    }


@router.delete("/drafts/{public_id}", status_code=status.HTTP_200_OK)
async def cancel_draft(
    public_id: str,
    request: Request,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Abandon a setup. Nothing was created, so nothing is removed."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        draft = drafts.cancel_draft(db, draft)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    audit_event_service.safe_emit(
        action="onboarding.draft.cancel",
        outcome="success",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
    )
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 1: Connect                                                              #
# --------------------------------------------------------------------------- #


@router.put("/drafts/{public_id}/connect")
async def set_connection(
    public_id: str,
    step: schemas.ConnectStep,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Record where the host is. Changing it invalidates prior verification."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)

        previous = draft.connection or {}
        changed = (
            previous.get("address") != step.address
            or previous.get("ssh_port") != step.ssh_port
        )
        changes: Dict[str, Any] = {
            "connection": schemas.serialize_connection(
                step,
                resolved_ip=None if changed else previous.get("resolved_ip"),
            )
        }
        if changed:
            # A different endpoint is a different host until proven otherwise:
            # the approved key, the verification result and the discovered
            # facts all described the old one.
            changes.update(
                {
                    "verification": None,
                    "discovery": None,
                    "host_key_type": None,
                    "host_key_public": None,
                    "host_key_fingerprint": None,
                    "host_key_decision": HOST_KEY_PENDING,
                    "verification_skipped": False,
                    "distro_id": None,
                }
            )
        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes=changes,
            next_step=STEP_AUTHENTICATE,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 2: Authenticate                                                         #
# --------------------------------------------------------------------------- #


@router.get("/credential-options")
async def list_credential_options(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Credentials this operator may use, with non-secret metadata only."""
    credentials = db.query(Credential).order_by(Credential.name).all()
    policies = db.query(SSHSecurityPolicy).order_by(SSHSecurityPolicy.name).all()
    default_policy = drafts.resolve_default_policy(db)
    return {
        "credentials": [_credential_summary(c) for c in credentials],
        "ssh_security_policies": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "requires_host_key_verification": (
                    preflight.policy_requires_host_key_verification(p)
                ),
                "is_default": bool(default_policy and p.id == default_policy.id),
            }
            for p in policies
        ],
        "default_ssh_security_policy_id": (
            default_policy.id if default_policy else None
        ),
        "capabilities": _capabilities(db, current_user),
    }


@router.put("/drafts/{public_id}/authenticate")
async def set_authentication(
    public_id: str,
    step: schemas.AuthenticateStep,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Choose the stored credential and SSH policy for this host."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)

        credential = (
            db.query(Credential).filter(Credential.id == step.credential_id).first()
        )
        if credential is None:
            raise drafts.DraftError(
                "reference_missing", "That credential no longer exists.", 400
            )

        policy = None
        if step.ssh_security_policy_id is not None:
            policy = (
                db.query(SSHSecurityPolicy)
                .filter(SSHSecurityPolicy.id == step.ssh_security_policy_id)
                .first()
            )
            if policy is None:
                raise drafts.DraftError(
                    "reference_missing", "That SSH policy no longer exists.", 400
                )

        changes: Dict[str, Any] = {
            "credential_id": credential.id,
            "ssh_security_policy_id": policy.id if policy else None,
        }
        if draft.credential_id != credential.id:
            # A different credential has not been proven against this host.
            changes.update({"verification": None, "verification_skipped": False})

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes=changes,
            next_step=STEP_VERIFY,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 3: Verify                                                               #
# --------------------------------------------------------------------------- #


def _build_target(
    db: Session, draft: SystemOnboardingDraft
) -> preflight.PreflightTarget:
    """Assemble preflight parameters from the draft."""
    connection = draft.connection or {}
    credential = (
        db.query(Credential).filter(Credential.id == draft.credential_id).first()
        if draft.credential_id
        else None
    )
    if credential is None:
        raise drafts.DraftError(
            "reference_missing",
            "Choose a credential before verifying.",
            status_code=409,
        )
    if not connection.get("address"):
        raise drafts.DraftError(
            "connection_required",
            "Enter the host's address before verifying.",
            status_code=409,
        )

    policy = (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.id == draft.ssh_security_policy_id)
        .first()
        if draft.ssh_security_policy_id
        else drafts.resolve_default_policy(db)
    )

    return preflight.PreflightTarget(
        address=connection["address"],
        ssh_port=connection.get("ssh_port") or schemas.DEFAULT_SSH_PORT,
        credential=credential,
        policy=policy,
        # Only an approved key pins. An offered-but-undecided key must not
        # silently become the trusted one.
        pinned_public_key=(
            draft.host_key_public
            if draft.host_key_decision == HOST_KEY_TRUSTED
            else None
        ),
        require_host_key_verification=preflight.policy_requires_host_key_verification(
            policy
        ),
    )


def _host_key_changes(
    draft: SystemOnboardingDraft,
    target: preflight.PreflightTarget,
    offered: preflight.OfferedHostKey,
) -> Dict[str, Any]:
    """How the key a host just offered changes the draft's pinned key.

    An approval only survives while the host keeps offering the same key, and a
    policy that does not require verification records that plainly rather than
    implying the operator made a decision.
    """
    if (
        draft.host_key_decision == HOST_KEY_TRUSTED
        and draft.host_key_public
        and draft.host_key_public != offered.public_key
    ):
        # Approved key no longer matches. The approval does not carry over.
        return {"host_key_decision": HOST_KEY_REJECTED}
    if draft.host_key_decision == HOST_KEY_TRUSTED:
        return {}

    changes: Dict[str, Any] = {
        "host_key_type": offered.key_type,
        "host_key_public": offered.public_key,
        "host_key_fingerprint": offered.fingerprint,
    }
    if not target.require_host_key_verification:
        # The operator's own policy waives review; record that plainly
        # rather than pretending a decision was made.
        changes["host_key_decision"] = HOST_KEY_TRUSTED
    return changes


def _verification_changes(
    draft: SystemOnboardingDraft,
    target: preflight.PreflightTarget,
    result: preflight.PreflightResult,
) -> Dict[str, Any]:
    """The draft fields one verification run updates."""
    offered = result.offered_host_key
    changes: Dict[str, Any] = {
        "verification": schemas.serialize_verification(
            result.checks,
            verified=result.verified,
            completed_at=preflight.utcnow_iso(),
            host_key_fingerprint=offered.fingerprint if offered else None,
            host_key_type=offered.key_type if offered else None,
        ),
        "verification_skipped": False,
    }

    if offered is not None:
        changes.update(_host_key_changes(draft, target, offered))

    connection = dict(draft.connection or {})
    if result.resolved_ip:
        connection["resolved_ip"] = result.resolved_ip
    changes["connection"] = connection
    return changes


@router.post("/drafts/{public_id}/verify")
async def verify_draft(
    public_id: str,
    request: Request,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Run verification against the draft's parameters. Creates no host."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)
        target = _build_target(db, draft)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    result = preflight.run_preflight(db, target)
    changes = _verification_changes(draft, target, result)

    try:
        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes=changes,
            next_step=STEP_VERIFY if not result.verified else STEP_DISCOVER,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    audit_event_service.safe_emit(
        action="onboarding.verify",
        outcome="success" if result.verified else "failure",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
        context={
            "reason_code": result.reason_code(),
            "checks": [
                {
                    "check": c["check"],
                    "status": c["status"],
                    "reason_code": c["reason_code"],
                }
                for c in result.checks
            ],
        },
    )
    return {"draft": _render_draft(db, draft)}


@router.put("/drafts/{public_id}/host-key")
async def decide_host_key(
    public_id: str,
    step: schemas.HostKeyDecisionStep,
    request: Request,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Approve or reject the key the host offered."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)

        if not draft.host_key_fingerprint:
            raise drafts.DraftError(
                "host_key_absent",
                "Verify the host first so its key can be reviewed.",
                status_code=409,
            )
        if step.fingerprint != draft.host_key_fingerprint:
            # The operator approved something other than what is on record.
            raise drafts.DraftError(
                "host_key_stale",
                "The key changed since it was shown to you. Verify again and "
                "review the new fingerprint.",
                status_code=409,
            )

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes={
                "host_key_decision": (
                    HOST_KEY_TRUSTED if step.accept else HOST_KEY_REJECTED
                )
            },
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    audit_event_service.safe_emit(
        action="onboarding.host_key.decision",
        outcome="success" if step.accept else "denied",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
        context={
            "decision": draft.host_key_decision,
            "fingerprint": draft.host_key_fingerprint,
            "key_type": draft.host_key_type,
        },
    )
    return {"draft": _render_draft(db, draft)}


@router.post("/drafts/{public_id}/skip-verification")
async def skip_verification(
    public_id: str,
    step: schemas.SkipVerificationStep,
    request: Request,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Proceed without verifying. The host will not be reported Active."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)
        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes={"verification_skipped": bool(step.acknowledged)},
            next_step=STEP_DISCOVER,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    audit_event_service.safe_emit(
        action="onboarding.verify.skipped",
        outcome="success",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
    )
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 4: Discover                                                             #
# --------------------------------------------------------------------------- #


def _distro_name_candidates(os_release: Dict[str, str]) -> List[str]:
    """Names a host might be catalogued under, most specific first.

    A host does not describe itself the way an inventory does. Debian reports
    ``NAME="Debian GNU/Linux"`` while the catalogue carries "Debian", and Rocky
    reports ``NAME="Rocky Linux"`` against a catalogue entry of the same name.
    Matching on ``ID`` as well as ``NAME``, and on the leading word of a
    multi-word name, is what makes an ordinary Debian host map to an ordinary
    Debian entry instead of reading as unsupported.
    """
    candidates: List[str] = []
    for value in (os_release.get("NAME"), os_release.get("ID")):
        if not value:
            continue
        cleaned = value.strip()
        if cleaned and cleaned.lower() not in [c.lower() for c in candidates]:
            candidates.append(cleaned)
        first_word = cleaned.split()[0] if cleaned.split() else ""
        if first_word and first_word.lower() not in [c.lower() for c in candidates]:
            candidates.append(first_word)
    return candidates


def _match_distro(db: Session, os_release: Dict[str, str], version: Optional[str]):
    """Map discovered os-release values onto a known distribution.

    Versions are compared exactly first, then on the major component, so a host
    reporting "9.8" still maps to a catalogue entry of "9".
    """
    if not version:
        return None
    names = [n.lower() for n in _distro_name_candidates(os_release)]
    if not names:
        return None

    catalogue = db.query(Distro).all()
    exact = version.strip().lower()
    major = exact.split(".")[0]

    for wanted_version in (exact, major):
        for name in names:
            for distro in catalogue:
                if (
                    distro.name.strip().lower() == name
                    and distro.version.strip().lower() == wanted_version
                ):
                    return distro
    return None


@router.post("/drafts/{public_id}/discover")
async def discover_draft(
    public_id: str,
    request: Request,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Read identity and distribution from the host. Creates no host."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)
        target = _build_target(db, draft)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    result = preflight.run_preflight(db, target, collect_identity=True)
    if not result.verified:
        # Discovery needs a working session. Report why it could not run using
        # the same codes verification uses, rather than a generic failure.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "discovery_unavailable",
                "message": schemas.message_for(result.reason_code()),
                "reason_code": result.reason_code(),
                "checks": result.checks,
            },
        )

    os_release = result.os_release
    distro_name = os_release.get("NAME") or os_release.get("ID")
    distro_version = os_release.get("VERSION_ID") or os_release.get("VERSION")
    package_family = preflight.package_family_for(os_release)
    matched = _match_distro(db, os_release, distro_version)

    discovery = schemas.serialize_discovery(
        effective_hostname=result.identity.get("hostname"),
        fqdn=result.identity.get("fqdn"),
        distro_name=distro_name,
        distro_version=distro_version,
        architecture=result.identity.get("arch"),
        package_family=package_family,
        package_manager=preflight.package_manager_for(package_family),
        support_mapping="matched" if matched else "unknown",
        distro_id=matched.id if matched else None,
        confirmed_unknown=False,
        collected_at=preflight.utcnow_iso(),
    )

    connection = dict(draft.connection or {})
    if result.resolved_ip:
        connection["resolved_ip"] = result.resolved_ip
    changes: Dict[str, Any] = {
        "discovery": discovery,
        "distro_id": matched.id if matched else None,
        "connection": connection,
    }

    try:
        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes=changes,
            next_step=STEP_ORGANIZE if matched else STEP_DISCOVER,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    audit_event_service.safe_emit(
        action="onboarding.discover",
        outcome="success",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_kind="onboarding_draft",
        target_id=draft.public_id,
        context={
            "support_mapping": discovery["support_mapping"],
            "package_family": discovery["package_family"],
        },
    )
    return {"draft": _render_draft(db, draft)}


@router.put("/drafts/{public_id}/discovery-confirmation")
async def confirm_discovery(
    public_id: str,
    step: schemas.DiscoveryConfirmStep,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Resolve an unmapped distribution, explicitly."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)

        discovery = dict(draft.discovery or {})
        if not discovery:
            raise drafts.DraftError(
                "discovery_required",
                "Run discovery before confirming what this host is.",
                status_code=409,
            )

        distro_id = step.distro_id or discovery.get("distro_id")
        if distro_id:
            distro = db.query(Distro).filter(Distro.id == distro_id).first()
            if distro is None:
                raise drafts.DraftError(
                    "reference_missing", "That distribution no longer exists.", 400
                )
        elif not step.confirmed_unknown:
            raise drafts.DraftError(
                "distro_required",
                "Choose a distribution, or confirm this host is unmapped.",
                status_code=400,
            )

        discovery["distro_id"] = distro_id
        discovery["confirmed_unknown"] = bool(step.confirmed_unknown)

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes={"discovery": discovery, "distro_id": distro_id},
            next_step=STEP_ORGANIZE,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 5: Organize                                                             #
# --------------------------------------------------------------------------- #


@router.get("/organization-options")
async def list_organization_options(
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Groups, distributions and defaults the Organize step offers."""
    default_group = drafts.resolve_default_group(db)
    groups = db.query(Group).order_by(Group.name).all()
    distros = db.query(Distro).order_by(Distro.name, Distro.version).all()
    return {
        "groups": [{"id": g.id, "name": g.name} for g in groups],
        "default_group_id": default_group.id if default_group else None,
        "distros": [
            {"id": d.id, "name": d.name, "version": d.version} for d in distros
        ],
        "environments": list(schemas.ENVIRONMENTS),
        "transport_preferences": list(schemas.TRANSPORT_PREFERENCES),
        "capabilities": _capabilities(db, current_user),
    }


@router.put("/drafts/{public_id}/organize")
async def set_organization(
    public_id: str,
    step: schemas.OrganizeStep,
    state_version: Optional[int] = None,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Record placement and labelling. Omitted fields are left alone."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)

        if step.group_id is not None:
            group = db.query(Group).filter(Group.id == step.group_id).first()
            if group is None:
                raise drafts.DraftError(
                    "reference_missing", "That group no longer exists.", 400
                )

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=state_version,
            changes={
                "organization": schemas.serialize_organization(step, draft.organization)
            },
            next_step=STEP_CONFIRM,
        )
    except drafts.DraftError as exc:
        raise _fail(exc) from exc
    return {"draft": _render_draft(db, draft)}


# --------------------------------------------------------------------------- #
# Step 6: Confirm                                                              #
# --------------------------------------------------------------------------- #


@router.post("/drafts/{public_id}/confirm")
async def confirm_draft(
    public_id: str,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Show exactly what Finish would create, and issue its one-time token."""
    try:
        draft = drafts.load_draft(db, current_user, public_id)
        drafts.assert_authority_unchanged(db, draft, current_user)
        preview = drafts.build_finalization_preview(db, draft)
        token = drafts.issue_finalize_token(db, draft)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    return {
        "draft": _render_draft(db, draft, finalize_token=token),
        "preview": preview,
        "license": _license_snapshot(db),
        "follow_ups": [
            {
                "key": "access_broker",
                "label": "Enrol in the Access Broker",
                "description": (
                    "Set up per-user access and session recording. This is a "
                    "separate step and changes the host's SSH configuration, so "
                    "it never happens as part of adding a host."
                ),
            },
            {
                "key": "agent",
                "label": "Install the agent",
                "description": ("Optional. Adds agent transport alongside SSH."),
            },
            {
                "key": "facts",
                "label": "Collect facts",
                "description": "Gather inventory detail for this host.",
            },
            {
                "key": "packages",
                "label": "Scan packages",
                "description": "Build the host's package and update picture.",
            },
        ],
    }


# --------------------------------------------------------------------------- #
# Step 7: Finish                                                               #
# --------------------------------------------------------------------------- #


@router.post("/drafts/{public_id}/finish")
async def finish_draft(
    public_id: str,
    step: schemas.FinishStep,
    request: Request,
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Create the managed host. The only step that creates anything."""
    try:
        draft = drafts.load_draft(db, current_user, public_id, require_active=False)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    # A repeated finish returns the host this draft already created, rather
    # than creating a second one or spending another license seat.
    if draft.finalized_system_id:
        system = db.query(System).filter(System.id == draft.finalized_system_id).first()
        if system is not None:
            return {
                "system_id": system.id,
                "hostname": system.hostname,
                "status": system.status,
                "created": False,
                "verification_skipped": bool(draft.verification_skipped),
            }

    try:
        drafts.load_draft(db, current_user, public_id)
    except drafts.DraftError as exc:
        raise _fail(exc) from exc

    if step.state_version != draft.state_version:
        raise _fail(
            drafts.DraftError(
                "draft_stale",
                "This setup changed after you confirmed it. Review the details "
                "and confirm again.",
                status_code=409,
            )
        )

    if not drafts.claim_for_finalization(db, draft):
        raise _fail(
            drafts.DraftError(
                "finalization_in_progress",
                "This setup is already being finished.",
                status_code=409,
            )
        )

    try:
        system, created = drafts.finalize_draft(
            db, draft, current_user, finalize_token=step.finalize_token
        )
    except drafts.DraftError as exc:
        drafts.release_claim(db, draft)
        audit_event_service.safe_emit(
            action="onboarding.finish",
            outcome="failure",
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            actor_ip=_actor_ip(request),
            target_kind="onboarding_draft",
            target_id=public_id,
            context={"code": exc.code},
        )
        raise _fail(exc) from exc
    except HTTPException:
        # The license gate raises its own HTTP error; the draft must not stay
        # claimed because capacity was refused.
        drafts.release_claim(db, draft)
        audit_event_service.safe_emit(
            action="onboarding.finish",
            outcome="denied",
            actor_user_id=current_user.id,
            actor_username=current_user.username,
            actor_ip=_actor_ip(request),
            target_kind="onboarding_draft",
            target_id=public_id,
            context={"code": "license_capacity"},
        )
        raise
    except Exception:
        drafts.release_claim(db, draft)
        raise

    audit_event_service.safe_emit(
        action="onboarding.finish",
        outcome="success",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        actor_ip=_actor_ip(request),
        target_system_id=system.id,
        target_kind="system",
        target_id=str(system.id),
        context={
            "hostname": system.hostname,
            "status": system.status,
            "verification_skipped": bool(draft.verification_skipped),
            "host_key_decision": draft.host_key_decision,
        },
    )

    try:
        create_notification(
            db,
            type="system_added",
            title=f"System added: {system.hostname}",
            message=(
                f"New system '{system.hostname}' ({system.ip_address}) registered"
            ),
            severity="info",
        )
    except Exception:  # pylint: disable=broad-except
        logger.warning("could not raise the system-added notification")

    return {
        "system_id": system.id,
        "hostname": system.hostname,
        "status": system.status,
        "created": created,
        "verification_skipped": bool(draft.verification_skipped),
    }
