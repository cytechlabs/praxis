"""PRA-414: database-level guarantees behind guided onboarding.

The wizard leans on the database for the things application code cannot make
true on its own: bounded state values, an unforgeable draft handle, and
uniqueness that two concurrent finalizations cannot both slip past.
"""

from datetime import date, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import Credential, Distro, Group, System
from app.db.onboarding_models import SystemOnboardingDraft


@pytest.fixture
def inventory(db):
    group = db.query(Group).filter_by(name="All Systems").first()
    if group is None:
        group = Group(name="All Systems")
        db.add(group)
        db.flush()
    distro = db.query(Distro).filter_by(name="Debian", version="12").first()
    if distro is None:
        distro = Distro(
            name="Debian",
            version="12",
            release_date=date(2023, 6, 10),
            end_of_life_date=date(2028, 6, 10),
        )
        db.add(distro)
        db.flush()
    credential = Credential(name="db-cred", auth_method="password", sudo_method="none")
    db.add(credential)
    db.flush()
    return {"group": group, "distro": distro, "credential": credential}


def _system(inventory, hostname, ip):
    return System(
        hostname=hostname,
        ip_address=ip,
        distro_id=inventory["distro"].id,
        os_version="12",
        status="Active",
        group_id=inventory["group"].id,
        credentials_id=inventory["credential"].id,
    )


def _draft(admin_user, **overrides):
    now = datetime.utcnow()
    values = {
        "public_id": f"draft-{datetime.utcnow().timestamp()}",
        "actor_user_id": admin_user.id,
        "actor_authority_digest": "d" * 64,
        "actor_scope_kind": "tenant_wide",
        "status": "active",
        "current_step": "connect",
        "state_version": 0,
        "expires_at": now + timedelta(hours=1),
        "absolute_expires_at": now + timedelta(hours=8),
        "connection": {},
        "organization": {},
        "host_key_decision": "pending",
        "verification_skipped": False,
    }
    values.update(overrides)
    return SystemOnboardingDraft(**values)


class TestSystemAddressUniqueness:
    def test_two_systems_cannot_share_an_address(self, db, inventory):
        db.add(_system(inventory, "dup-one", "10.80.0.10"))
        db.flush()
        db.add(_system(inventory, "dup-two", "10.80.0.10"))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

    def test_distinct_addresses_are_fine(self, db, inventory):
        db.add(_system(inventory, "uniq-one", "10.80.1.10"))
        db.add(_system(inventory, "uniq-two", "10.80.1.11"))
        db.flush()

    def test_description_is_nullable_and_stored(self, db, inventory):
        system = _system(inventory, "desc-one", "10.80.2.10")
        system.description = "a described host"
        db.add(system)
        db.flush()
        db.expire_all()
        stored = db.query(System).filter_by(hostname="desc-one").first()
        assert stored.description == "a described host"

        bare = _system(inventory, "desc-two", "10.80.2.11")
        db.add(bare)
        db.flush()
        assert bare.description is None


class TestDraftConstraints:
    def test_the_public_handle_is_unique(self, db, admin_user):
        db.add(_draft(admin_user, public_id="fixed-handle"))
        db.flush()
        db.add(_draft(admin_user, public_id="fixed-handle"))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

    @pytest.mark.parametrize(
        "column,value",
        [
            ("status", "half_done"),
            ("current_step", "teleport"),
            ("host_key_decision", "maybe"),
            ("actor_scope_kind", "multi_tenant"),
        ],
    )
    def test_out_of_vocabulary_values_are_refused(self, db, admin_user, column, value):
        db.add(_draft(admin_user, **{column: value}))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

    @pytest.mark.parametrize(
        "column",
        [
            "actor_scope_kind",
            "expires_at",
            "absolute_expires_at",
            "actor_authority_digest",
        ],
    )
    def test_columns_without_a_default_must_be_supplied(self, db, admin_user, column):
        db.add(_draft(admin_user, **{column: None}))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

    @pytest.mark.parametrize(
        "column,expected",
        [
            ("status", "active"),
            ("current_step", "connect"),
            ("host_key_decision", "pending"),
        ],
    )
    def test_lifecycle_columns_fall_back_to_their_safe_default(
        self, db, admin_user, column, expected
    ):
        """These are NOT NULL with a server default, so an unsupplied value
        lands on the safe starting state rather than on NULL. A draft can never
        exist without a status, a step, or a host-key decision."""
        draft = _draft(admin_user, **{column: None})
        db.add(draft)
        db.flush()
        db.expire_all()

        stored = db.query(SystemOnboardingDraft).filter_by(id=draft.id).first()
        assert getattr(stored, column) == expected


class TestDraftReferencesNeverBlockDeletion:
    def test_deleting_a_credential_nulls_the_reference(self, db, admin_user, inventory):
        draft = _draft(admin_user, credential_id=inventory["credential"].id)
        db.add(draft)
        db.flush()

        db.delete(inventory["credential"])
        db.flush()
        db.expire_all()

        stored = db.query(SystemOnboardingDraft).filter_by(id=draft.id).first()
        # The draft survives with a dangling-free null, and the credential was
        # not held hostage by an unfinished setup.
        assert stored is not None
        assert stored.credential_id is None

    def test_deleting_the_actor_removes_their_drafts(self, db, admin_user):
        draft = _draft(admin_user)
        db.add(draft)
        db.flush()
        draft_id = draft.id

        db.delete(admin_user)
        db.flush()
        db.expire_all()

        assert db.query(SystemOnboardingDraft).filter_by(id=draft_id).first() is None
