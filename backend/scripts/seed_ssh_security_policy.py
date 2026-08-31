"""Seed the default SSH security policy once per installation.

Guided onboarding, and every direct registration that does not name a policy,
resolve their SSH security policy by the name "Default". A fresh installation
therefore needs that policy to exist before the first host is added, and the
policy carries a non-null creator, so it has to be credited to an account that
really exists on this installation.

The creator is resolved from bootstrap and role state rather than from a fixed
username. First-run provisioning names the administrator from ADMIN_USERNAME
and defaults it to ``praxisadmin``, an operator may rename that account, and a
deployment may have been initialized long before this seeder ran, so no literal
username identifies the administrator of an arbitrary installation. The
recorded bootstrap account is preferred while it remains a usable
administrator; otherwise the oldest active administrator stands in. Crediting
seeded system data to an account that is not an administrator, or to no account
at all, is refused: the seeder reports why and creates nothing, and a later
start retries.

Seeding happens once. Absence of a policy named "Default" is not evidence that
one was never seeded: an operator may have deleted it, and recreating it on the
next restart would overturn that decision every time the control plane
restarts. A durable marker in ``app_settings`` records that this installation
has seeded the policy, so the two states are distinguishable. The marker is
written in the same transaction as the policy it describes, which is what makes
"seeded but no marker" and "marker but never seeded" both unreachable.

An installation that already carries a Default policy but no marker predates
the marker. It is adopted: the marker is recorded and the policy is left
exactly as the operator has it, neither replaced nor rewritten. That gives an
installation initialized under the old broken sequence its one corrective
chance, while a policy deleted after the marker exists stays deleted.

The orphan backfill runs on every start, but only when a policy exists to
attach systems to.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy.exc import IntegrityError  # noqa: E402

from app.db.models import AppSettings, Role, System, User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.db.ssh_security_models import SSHSecurityPolicy  # noqa: E402
from app.services import bootstrap_admin_service  # noqa: E402

POLICY_NAME = "Default"
POLICY_DESCRIPTION = (
    "Seeded default policy. Enforces host key verification (TOFU) and "
    "sensible crypto defaults."
)
ADMIN_ROLE = "admin"

# The durable fact that this installation has seeded the Default policy. The
# unique constraint on ``app_settings.setting_key`` is what makes it at most
# one row, and the settings API refuses to write keys outside its own
# allow-list, so this is not reachable as an operator-editable setting.
SEED_MARKER_KEY = "bootstrap.default_ssh_security_policy_seeded"
SEED_MARKER_VALUE = "true"

# Two passes are enough: the only way the first loses is that another start
# committed the policy and its marker, and the second pass reads what it wrote.
_MAX_ATTEMPTS = 2


def _is_eligible_owner(user):
    """Whether ``user`` may be credited as the creator of seeded system data."""
    return user is not None and bool(user.is_active) and user.is_admin


def resolve_policy_owner(db):
    """The administrator the seeded policy is credited to, or None.

    The account first-run initialization recorded is the truest answer, because
    it is the administrator this installation was bootstrapped with whatever it
    was named. It is used only while it remains a usable administrator: an
    account that was deleted, deactivated, or stripped of the admin role no
    longer stands for the installation's administration, and the oldest active
    administrator is then the stable substitute.
    """
    state = bootstrap_admin_service.read_state(db)
    if state is not None and state.bootstrap_user_id is not None:
        bootstrap_user = (
            db.query(User).filter(User.id == state.bootstrap_user_id).first()
        )
        if _is_eligible_owner(bootstrap_user):
            return bootstrap_user

    return (
        db.query(User)
        .join(User.roles)
        .filter(Role.name == ADMIN_ROLE, User.is_active.is_(True))
        .order_by(User.id)
        .first()
    )


def read_seed_marker(db):
    """The record that this installation has seeded the policy, or None."""
    return (
        db.query(AppSettings).filter(AppSettings.setting_key == SEED_MARKER_KEY).first()
    )


def read_default_policy(db):
    """The policy every default resolution looks for, or None."""
    return (
        db.query(SSHSecurityPolicy)
        .filter(SSHSecurityPolicy.name == POLICY_NAME)
        .first()
    )


def _adopt_existing_policy(db):
    """Record an already-seeded installation without touching its policy.

    Returns True when this call wrote the marker. Losing the race to another
    start is an ordinary outcome and not an error: the fact is about the
    installation, and it is true either way.
    """
    db.add(AppSettings(setting_key=SEED_MARKER_KEY, setting_value=SEED_MARKER_VALUE))
    try:
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False


def _create_policy_and_marker(db, owner):
    """Create the policy and the record of it as one transaction.

    Returns the policy, or None when a concurrent start committed first. Both
    unique constraints are load-bearing here: whichever of the two the loser
    trips, it lands in the same rollback and the caller reads what the winner
    wrote instead of creating a second policy or a marker without one.
    """
    policy = SSHSecurityPolicy(
        name=POLICY_NAME,
        description=POLICY_DESCRIPTION,
        require_host_key_verification=True,
        log_commands=True,
        created_by=owner.id,
    )
    db.add(policy)
    db.add(AppSettings(setting_key=SEED_MARKER_KEY, setting_value=SEED_MARKER_VALUE))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    db.refresh(policy)
    return policy


def ensure_default_policy(db):
    """Settle this installation's Default policy, seeding it at most once.

    Returns the policy the backfill should attach orphans to, or None when
    there is none. Creating nothing and recording nothing are the same outcome
    only when no administrator exists yet, which is the one state a later start
    is expected to resolve.
    """
    for _ in range(_MAX_ATTEMPTS):
        marker = read_seed_marker(db)
        policy = read_default_policy(db)

        if marker is not None:
            if policy is None:
                print(
                    "The Default SSHSecurityPolicy was seeded on this "
                    "installation and has since been removed. It is not "
                    "recreated. Create a policy under SSH Security, or set one "
                    "explicitly on each system, if hosts need a default again."
                )
            else:
                print("Default SSHSecurityPolicy already exists.")
            return policy

        if policy is not None:
            if _adopt_existing_policy(db):
                print(
                    "Default SSHSecurityPolicy already exists; recorded as "
                    "seeded for this installation."
                )
            return policy

        owner = resolve_policy_owner(db)
        if owner is None:
            print(
                "No active administrator exists yet, so the Default "
                "SSHSecurityPolicy was not created. It is seeded on the next "
                "start once an administrator account is available."
            )
            return None

        created = _create_policy_and_marker(db, owner)
        if created is not None:
            print(f"Default SSHSecurityPolicy created (id={created.id}).")
            return created

    # Both passes lost, which means another start owns the outcome. Report what
    # is actually there rather than asserting anything about who wrote it.
    return read_default_policy(db)


def backfill_orphan_systems(db, policy):
    """Attach every system with no policy to ``policy``."""
    orphans = db.query(System).filter(System.ssh_security_policy_id.is_(None)).all()
    if not orphans:
        return
    for system in orphans:
        system.ssh_security_policy_id = policy.id
    db.commit()
    print(f"Attached Default policy to {len(orphans)} existing system(s).")


def main():
    db = SessionLocal()
    try:
        policy = ensure_default_policy(db)
        if policy is not None:
            backfill_orphan_systems(db, policy)
    finally:
        db.close()


if __name__ == "__main__":
    main()
