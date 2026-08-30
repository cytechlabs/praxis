"""First-run administrator provisioning, decided once per installation.

Startup used to provision the bootstrap administrator whenever no user carried
the configured username. Absence of a username is not evidence that an
installation was never initialized: an administrator that was deliberately
deleted came back on the next restart, with the admin role and the password
still sitting in the environment, and renaming the account or changing the
configured username produced a second administrator through the same gate.

The decision here rests on a durable record that this installation has been
initialized, held in ``bootstrap_admin_state``. It is a fact about the
installation rather than about an account, so it stays true after the account
is deleted, renamed, disabled, or stripped of its role. Once it exists nothing
is provisioned again, which makes ADMIN_PASSWORD and ADMIN_USERNAME first-run
inputs rather than recurring desired state.

An installation that already carries users but no record is one that predates
the record. It is adopted: marked initialized without creating, modifying,
reactivating, or re-roling anything. An installation with no users at all has
no reachable login, so it is provisioned exactly as before; that is also the
only outcome that keeps an emptied database recoverable.

Concurrency, in three layers. A transaction-scoped advisory lock serializes the
read-decide-write, and being transaction-scoped it is released by the commit or
rollback that ends the decision rather than lingering on a pooled connection.
Under READ COMMITTED each statement takes a fresh snapshot, so a caller that
waited on the lock sees the winner's committed record when it reads. The unique
constraint on the marker is the durable backstop, and the existing uniqueness of
``user.username`` independently prevents a duplicate account.

The record, the account, and the audit event share one transaction: an
administrator whose creation left no audit trail is the failure this module
exists to prevent, so the audit write is part of the change rather than a
best-effort note after it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.auth import get_password_hash
from ..core.startup_validation import validate_production_env
from ..db.models import BootstrapAdminState, Role, User
from . import audit_event_service

logger = logging.getLogger(__name__)

# The single value ``bootstrap_admin_state.marker`` ever holds. Its unique
# constraint is what makes "at most one row" a database fact.
MARKER = "bootstrap_admin"

STATE_PROVISIONED = "provisioned"
STATE_ADOPTED = "adopted"

# Advisory lock coordinates. The namespace follows the ASCII-pair convention the
# scheduler and mirror locks already use; "BA" is bootstrap admin, and collides
# with neither. There is one bootstrap decision per database, so the second
# coordinate is a constant.
BOOTSTRAP_LOCK_NAMESPACE = 0x4241
BOOTSTRAP_LOCK_ID = 0

# Per-user fleet access maps the Praxis username to the managed Linux login, and
# real hosts commonly already carry an ``admin`` user or group, so the default
# bootstrap username is ``praxisadmin``. The application role stays ``admin``.
DEFAULT_USERNAME = "praxisadmin"
DEFAULT_EMAIL = "praxisadmin@praxis.dev"

# Roles the first boot guarantees exist. Seeding runs before this module and
# creates the same three; both are idempotent and neither depends on the other.
SEEDED_ROLES = (
    ("admin", "Administrator role"),
    ("maintainer", "Maintainer role"),
    ("auditor", "Auditor role"),
)

ACTION_PROVISIONED = "bootstrap.admin.provisioned"
ACTION_ADOPTED = "bootstrap.admin.adopted"
ACTION_SUPPRESSED = "bootstrap.admin.suppressed"
ACTION_RESET = "bootstrap.admin.reset"
TARGET_KIND = "bootstrap_admin"

# Outcomes of ``ensure_bootstrap_admin``.
ALREADY_INITIALIZED = "already_initialized"
ADOPTED = "adopted"
PROVISIONED = "provisioned"
SKIPPED_NO_PASSWORD = "skipped_no_password"

# Outcomes of ``reset_bootstrap_state``.
RESET_CLEARED = "cleared"
RESET_NOT_INITIALIZED = "not_initialized"


class BootstrapAdminError(RuntimeError):
    """A bootstrap operation was refused."""


@dataclass(frozen=True)
class BootstrapConfig:
    """The first-run inputs, read fresh so a caller can set them per boot."""

    username: str
    email: str
    password: str


def read_config() -> BootstrapConfig:
    """Read the configured bootstrap identity from the environment.

    The password is carried only as far as the hash function on the one path
    that creates an account. It is never stored, logged, or emitted.
    """
    return BootstrapConfig(
        username=os.getenv("ADMIN_USERNAME", DEFAULT_USERNAME),
        email=os.getenv("ADMIN_EMAIL", DEFAULT_EMAIL),
        password=os.getenv("ADMIN_PASSWORD", ""),
    )


def read_state(db: Session) -> Optional[BootstrapAdminState]:
    """Return the initialization record, or None when there is none."""
    return (
        db.query(BootstrapAdminState)
        .filter(BootstrapAdminState.marker == MARKER)
        .first()
    )


def ensure_bootstrap_admin(db: Session) -> str:
    """Provision the first administrator if, and only if, none ever was.

    Returns one of ``PROVISIONED``, ``ADOPTED``, ``ALREADY_INITIALIZED``, or
    ``SKIPPED_NO_PASSWORD``. The caller owns the session; the transaction this
    opens ends with the commit that records the decision, or with the caller
    closing the session on the paths that write nothing.
    """
    admin_role = ensure_roles(db)
    config = read_config()

    # Every production gate except the ADMIN_PASSWORD one applies on every boot.
    # That gate asks whether a deployment can be signed into at all, so it only
    # belongs on the path that is still deciding whether to create the login.
    validate_production_env()

    _acquire_lock(db)

    state = read_state(db)
    if state is not None:
        _emit_suppressed_if_recreate_would_have_happened(db, config)
        logger.info(
            "bootstrap administrator already recorded as initialized (%s); "
            "no account is provisioned",
            state.state,
        )
        return ALREADY_INITIALIZED

    user_count = db.query(User).count()
    if user_count > 0:
        return _adopt(db, config, user_count)

    validate_production_env(user_count=0)

    if not config.password:
        # No record is written: nothing was provisioned, so a later boot that
        # does supply a password must still be able to initialize. In production
        # this is unreachable, because the gate above has already refused.
        logger.warning(
            "ADMIN_PASSWORD is not set and this installation has no users; "
            "no administrator was created"
        )
        return SKIPPED_NO_PASSWORD

    return _provision(db, config, admin_role)


def reset_bootstrap_state(db: Session) -> str:
    """Clear the initialization record so the next boot can provision again.

    Refused while any user exists. The record is what stops a deleted
    administrator from returning, so clearing it on an installation that still
    has logins would hand back exactly the behavior it removes. It is a recovery
    path for the one state that has no way back in: no users at all.

    Returns ``RESET_CLEARED`` or ``RESET_NOT_INITIALIZED``, and raises
    ``BootstrapAdminError`` when refused. Nothing here reads, writes, or reports
    credential material; the next boot provisions from the environment as a
    first boot would.
    """
    _acquire_lock(db)

    user_count = db.query(User).count()
    if user_count > 0:
        audit_event_service.safe_emit(
            db=db,
            action=ACTION_RESET,
            outcome="denied",
            actor_user_id=None,
            target_kind=TARGET_KIND,
            context={"reason": "users_exist", "user_count": user_count},
        )
        raise BootstrapAdminError(
            f"Refusing to clear the bootstrap record: {user_count} user(s) "
            "still exist. This record is what keeps a deleted administrator "
            "deleted, and an installation with a login does not need it "
            "cleared. Sign in and manage users through the application, or "
            "remove the remaining users first if this installation really is "
            "unreachable."
        )

    state = read_state(db)
    if state is None:
        return RESET_NOT_INITIALIZED

    previous_state = state.state
    previous_username = state.bootstrap_username
    db.delete(state)
    db.flush()

    # The deletion and its record commit together: a cleared marker that left no
    # audit trail would be indistinguishable from one that was never written.
    audit_event_service.emit(
        db,
        action=ACTION_RESET,
        actor_user_id=None,
        target_kind=TARGET_KIND,
        context={
            "previous_state": previous_state,
            "username": previous_username,
        },
    )
    return RESET_CLEARED


def ensure_roles(db: Session) -> Role:
    """Guarantee the application roles exist and return the admin role."""
    admin_role = None
    for name, description in SEEDED_ROLES:
        role = db.query(Role).filter(Role.name == name).first()
        if not role:
            role = Role(name=name, description=description)
            db.add(role)
            db.commit()
            db.refresh(role)
            logger.info("created %s role", name)
        if name == "admin":
            admin_role = role
    return admin_role


def _acquire_lock(db: Session) -> None:
    """Serialize the decision for the rest of this transaction.

    Blocking rather than try-and-skip: the critical section is one read and at
    most one password hash, and a caller that skipped would have to decide
    without knowing the outcome. Transaction-scoped, so it cannot outlive the
    decision on a pooled connection.
    """
    db.execute(
        text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
        {"namespace": BOOTSTRAP_LOCK_NAMESPACE, "lock_id": BOOTSTRAP_LOCK_ID},
    )


def _find_configured_user(db: Session, username: str) -> Optional[User]:
    """The account carrying the configured username, whatever its state.

    An inactive or de-roled account still counts as present: this module reports
    what exists, and never reactivates or re-roles anything.
    """
    return db.query(User).filter(User.username == username).first()


def _emit_suppressed_if_recreate_would_have_happened(
    db: Session, config: BootstrapConfig
) -> None:
    """Record the boots on which the old gate would have created an account.

    Narrow on purpose: a password is still configured and nothing carries the
    configured username, which is exactly the state that used to resurrect a
    deleted administrator. It changes nothing, so a failure to record it must
    not take down an otherwise healthy control plane.
    """
    if not config.password:
        return
    if _find_configured_user(db, config.username) is not None:
        return
    logger.warning(
        "ADMIN_PASSWORD is set and no account carries the configured bootstrap "
        "username; this installation is already initialized, so no account was "
        "created. Clear ADMIN_PASSWORD once the first administrator has signed "
        "in."
    )
    audit_event_service.safe_emit(
        db=db,
        action=ACTION_SUPPRESSED,
        actor_user_id=None,
        target_kind=TARGET_KIND,
        context={"username": config.username},
    )


def _adopt(db: Session, config: BootstrapConfig, user_count: int) -> str:
    """Mark an installation that predates the record as initialized.

    Nothing is created and no existing account is touched. Binding to the
    configured username when one is present is a record of what this
    installation bootstrapped, not a claim over the account.
    """
    existing = _find_configured_user(db, config.username)
    context = {
        "username": config.username,
        "matched_existing": existing is not None,
        "user_id": existing.id if existing is not None else None,
        "user_count": user_count,
        "state": STATE_ADOPTED,
    }
    claimed = _claim_and_record(
        db,
        state=STATE_ADOPTED,
        user=existing,
        username=config.username,
        action=ACTION_ADOPTED,
        context=context,
    )
    if not claimed:
        return ALREADY_INITIALIZED
    logger.info(
        "recorded this installation as already initialized (%d existing user(s)); "
        "no administrator was created",
        user_count,
    )
    return ADOPTED


def _provision(db: Session, config: BootstrapConfig, admin_role: Role) -> str:
    """Create the first administrator and record that it happened."""
    user = User(
        username=config.username,
        email=config.email,
        hashed_password=get_password_hash(config.password),
        is_active=True,
        roles=[admin_role],
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        # An account under this username or email appeared alongside us. The
        # username is unique in the database, so this is the same race the
        # marker guards, caught by the other constraint.
        db.rollback()
        logger.info(
            "a conflicting account already exists; no administrator was created"
        )
        return ALREADY_INITIALIZED

    context = {
        "username": config.username,
        "user_id": user.id,
        "state": STATE_PROVISIONED,
    }
    claimed = _claim_and_record(
        db,
        state=STATE_PROVISIONED,
        user=user,
        username=config.username,
        action=ACTION_PROVISIONED,
        context=context,
    )
    if not claimed:
        return ALREADY_INITIALIZED
    logger.info("created the bootstrap administrator")
    return PROVISIONED


def _claim_and_record(
    db: Session,
    *,
    state: str,
    user: Optional[User],
    username: str,
    action: str,
    context: dict,
) -> bool:
    """Write the record and its audit event as one unit.

    Returns False when the marker was claimed concurrently, in which case
    everything this call would have written is rolled back, including any
    account, and the caller reports the installation as already initialized.

    Only the claim itself is allowed to mean that. The two writes fail for
    different reasons and demand opposite responses: losing the claim is an
    ordinary outcome of two backends starting together, while an audit write
    that will not persist is a fault, and reporting it as a peaceful race would
    hide it behind a success the caller reads as "someone else did this". So
    the claim is flushed on its own, and everything after it propagates.
    """
    db.add(
        BootstrapAdminState(
            marker=MARKER,
            state=state,
            bootstrap_user_id=user.id if user is not None else None,
            bootstrap_username=username,
            initialized_at=datetime.utcnow(),
        )
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.info(
            "another process recorded this installation as initialized first; "
            "nothing was created"
        )
        return False

    # The claim is ours. emit commits, which is what makes the record, the
    # account, and the event one transaction, and it rolls back and re-raises on
    # a database fault so a bootstrap never stands without its audit trail. That
    # failure is deliberately not caught here: the boot fails loudly rather than
    # leaving an administrator whose creation nothing recorded.
    audit_event_service.emit(
        db,
        action=action,
        actor_user_id=None,
        target_kind=TARGET_KIND,
        context=context,
    )
    return True
