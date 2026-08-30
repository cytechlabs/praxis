"""PRA-414: guided onboarding draft lifecycle.

Covers the properties the draft table exists to guarantee: a draft is private
to its creator, concurrent writes cannot interleave, exactly one finalization
wins, a finalization token is unrecoverable from storage, and a draft that ends
any way other than finishing leaves no managed host and no consumed capacity.
"""

from datetime import date, datetime, timedelta

import pytest

from app.db.models import (
    Distro,
    Group,
    System,
    SystemAudit,
    SystemMetadata,
    Tag,
    User,
    system_tag,
)
from app.db.onboarding_models import (
    DRAFT_STATUS_ACTIVE,
    DRAFT_STATUS_CANCELED,
    DRAFT_STATUS_COMPLETED,
    DRAFT_STATUS_EXPIRED,
    DRAFT_STATUS_FINALIZING,
    HOST_KEY_TRUSTED,
    SystemOnboardingDraft,
)
from app.db.ssh_security_models import SSHHostKey
from app.services import onboarding_draft_service as drafts
from app.services.ssh_service import SSHConnectionError

# A truncated, deliberately invalid ed25519 public key. Bound here so the
# placeholder is written once and never sits beside an assignment a secret
# scanner reads as credential material.
_ED25519_PUBLIC = "AAAAC3NzaC1lZDI1NTE5AAAAI-test"


@pytest.fixture
def group(db):
    g = db.query(Group).filter_by(name="All Systems").first()
    if g is None:
        g = Group(name="All Systems", description="default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def distro(db):
    d = db.query(Distro).filter_by(name="Debian", version="12").first()
    if d is None:
        d = Distro(
            name="Debian",
            version="12",
            release_date=date(2023, 6, 10),
            end_of_life_date=date(2028, 6, 10),
        )
        db.add(d)
        db.flush()
    return d


@pytest.fixture
def credential(db):
    from app.db.models import Credential

    c = Credential(
        name="draft-cred",
        auth_method="password",
        username="root",
        vault_path="secret/praxis/draft-cred",
        sudo_method="none",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def other_user(db, seed_roles):
    user = User(
        username="otheradmin",
        email="other@example.com",
        hashed_password="x",
        is_active=True,
    )
    user.roles.append(seed_roles["admin"])
    db.add(user)
    db.flush()
    return user


def _ready_draft(db, user, credential, distro, group, **overrides):
    """A draft in the state Finish expects: verified, keyed, and organized."""
    draft = drafts.create_draft(db, user)
    draft.connection = {
        "address": "10.60.0.10",
        "ssh_port": 22,
        "hostname": "ready-01",
        "resolved_ip": "10.60.0.10",
    }
    draft.organization = {
        "group_id": group.id,
        "tags": ["one"],
        "environment": "Production",
    }
    draft.credential_id = credential.id
    draft.distro_id = distro.id
    draft.verification = {"verified": True, "checks": [], "completed_at": "now"}
    draft.host_key_type = "ssh-ed25519"
    draft.host_key_public = _ED25519_PUBLIC
    draft.host_key_fingerprint = "a" * 64
    draft.host_key_decision = HOST_KEY_TRUSTED
    for key, value in overrides.items():
        setattr(draft, key, value)
    db.commit()
    db.refresh(draft)
    return draft


class TestOwnership:
    def test_a_draft_is_invisible_to_another_operator(self, db, admin_user, other_user):
        draft = drafts.create_draft(db, admin_user)
        # Reported as missing rather than forbidden: whether somebody else is
        # setting up a host is not something this discloses.
        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.load_draft(db, other_user, draft.public_id)
        assert excinfo.value.code == "draft_not_found"
        assert excinfo.value.status_code == 404

    def test_public_id_is_opaque_and_not_the_row_id(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        assert draft.public_id != str(draft.id)
        assert len(draft.public_id) >= 40


class TestAuthorityBinding:
    def test_changed_roles_invalidate_the_draft(self, db, admin_user, seed_roles):
        draft = drafts.create_draft(db, admin_user)
        drafts.assert_authority_unchanged(db, draft, admin_user)

        admin_user.roles.append(seed_roles["maintainer"])
        db.flush()

        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.assert_authority_unchanged(db, draft, admin_user)
        assert excinfo.value.code == "authority_changed"

    def test_digest_is_stable_across_role_ordering(self, db, admin_user):
        first = drafts.authority_digest(db, admin_user)
        admin_user.roles.reverse()
        db.flush()
        assert drafts.authority_digest(db, admin_user) == first


class TestVersioning:
    def test_a_stale_version_is_refused(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        drafts.apply_step(
            db, draft, expected_version=0, changes={"current_step": "authenticate"}
        )
        # A second tab still holding version 0 must lose.
        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.apply_step(
                db, draft, expected_version=0, changes={"current_step": "verify"}
            )
        assert excinfo.value.code == "draft_stale"

    def test_version_advances_on_each_write(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        assert draft.state_version == 0
        draft = drafts.apply_step(
            db, draft, expected_version=0, changes={"current_step": "authenticate"}
        )
        assert draft.state_version == 1

    def test_mutating_a_draft_invalidates_an_outstanding_token(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        token = drafts.issue_finalize_token(db, draft)
        assert draft.finalize_token_hash is not None

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=draft.state_version,
            changes={"current_step": "organize"},
        )
        assert draft.finalize_token_hash is None
        assert token  # issued, but no longer accepted

    def test_oversized_payload_is_refused(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.apply_step(
                db,
                draft,
                expected_version=0,
                changes={"organization": {"description": "x" * 40000}},
            )
        assert excinfo.value.code == "payload_too_large"


class TestFinalizeToken:
    def test_only_the_digest_is_stored(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        token = drafts.issue_finalize_token(db, draft)
        assert draft.finalize_token_hash != token
        assert token not in (draft.finalize_token_hash or "")
        assert len(draft.finalize_token_hash) == 64

    def test_a_wrong_token_is_rejected(self, db, admin_user, credential, distro, group):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        drafts.issue_finalize_token(db, draft)
        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.finalize_draft(db, draft, admin_user, finalize_token="not-the-token")
        assert excinfo.value.code == "replay_rejected"


class TestExpiry:
    def test_an_expired_draft_is_refused_and_marked(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        draft.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()

        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.load_draft(db, admin_user, draft.public_id)
        assert excinfo.value.code == "draft_expired"

        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_EXPIRED

    def test_sliding_ttl_never_passes_the_absolute_ceiling(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        ceiling = datetime.utcnow() + timedelta(minutes=5)
        draft.absolute_expires_at = ceiling
        db.commit()

        draft = drafts.apply_step(
            db,
            draft,
            expected_version=draft.state_version,
            changes={"current_step": "authenticate"},
        )
        assert draft.expires_at <= ceiling


class TestFinalizationClaim:
    def test_only_one_claim_succeeds(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        assert drafts.claim_for_finalization(db, draft) is True
        assert draft.status == DRAFT_STATUS_FINALIZING
        # A second worker racing on the same draft loses in the database.
        assert drafts.claim_for_finalization(db, draft) is False

    def test_release_returns_the_draft_to_active(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        drafts.claim_for_finalization(db, draft)
        drafts.release_claim(db, draft)
        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_ACTIVE
        assert draft.finalizing_since is None


class TestSweeper:
    def test_expired_drafts_are_marked(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        draft.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()

        counts = drafts.sweep_drafts(db)
        assert counts["expired"] >= 1
        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_EXPIRED

    def test_a_stale_finalization_lease_is_released(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        drafts.claim_for_finalization(db, draft)
        # Simulate the worker holding the claim dying.
        draft.finalizing_since = datetime.utcnow() - timedelta(
            minutes=drafts.FINALIZE_LEASE_MINUTES + 5
        )
        db.commit()

        counts = drafts.sweep_drafts(db)
        assert counts["released"] >= 1
        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_ACTIVE

    def test_old_terminal_drafts_are_pruned(self, db, admin_user):
        draft = drafts.create_draft(db, admin_user)
        drafts.cancel_draft(db, draft)
        draft.updated_at = datetime.utcnow() - timedelta(
            days=drafts.DRAFT_RETENTION_DAYS + 1
        )
        db.commit()
        public_id = draft.public_id

        counts = drafts.sweep_drafts(db)
        assert counts["pruned"] >= 1
        assert (
            db.query(SystemOnboardingDraft).filter_by(public_id=public_id).first()
            is None
        )


class TestFinalizationLeavesNothingBehindOnFailure:
    def test_cancel_creates_no_system(self, db, admin_user, credential, distro, group):
        before = db.query(System).count()
        draft = _ready_draft(db, admin_user, credential, distro, group)
        drafts.cancel_draft(db, draft)
        assert draft.status == DRAFT_STATUS_CANCELED
        assert db.query(System).count() == before

    def test_expiry_creates_no_system(self, db, admin_user, credential, distro, group):
        before = db.query(System).count()
        draft = _ready_draft(db, admin_user, credential, distro, group)
        draft.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
        drafts.sweep_drafts(db)
        assert db.query(System).count() == before

    def test_a_missing_reference_rolls_back_without_creating_a_host(
        self, db, admin_user, credential, distro, group
    ):
        before = db.query(System).count()
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        # The credential disappears between confirm and finish.
        draft.credential_id = None
        db.commit()

        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.finalize_draft(db, draft, admin_user, finalize_token=token)
        assert excinfo.value.code == "reference_missing"
        assert db.query(System).count() == before

    def test_verification_is_required_unless_explicitly_skipped(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(
            db,
            admin_user,
            credential,
            distro,
            group,
            verification={"verified": False, "checks": []},
        )
        token = drafts.issue_finalize_token(db, draft)
        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.finalize_draft(db, draft, admin_user, finalize_token=token)
        assert excinfo.value.code == "verification_required"


class TestFinalizationSuccess:
    def test_a_verified_draft_creates_an_active_host(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        system, created = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created is True
        assert system.status == "Active"
        assert system.hostname == "ready-01"
        assert str(system.ip_address) == "10.60.0.10"
        assert system.description is None

        metadata = db.query(SystemMetadata).filter_by(system_id=system.id).first()
        assert metadata.connection_status == "connected"

        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_COMPLETED
        assert draft.finalized_system_id == system.id
        # The token is spent, not left recoverable.
        assert draft.finalize_token_hash is None

    def test_skipped_verification_creates_an_honest_inactive_host(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(
            db,
            admin_user,
            credential,
            distro,
            group,
            verification=None,
            verification_skipped=True,
        )
        token = drafts.issue_finalize_token(db, draft)

        system, created = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created is True
        # Not Active: nothing proved this host works.
        assert system.status == "Inactive"
        metadata = db.query(SystemMetadata).filter_by(system_id=system.id).first()
        assert metadata.connection_status == "Pending"
        assert metadata.last_connection is None

    def test_finishing_twice_returns_the_same_host(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        first, created_first = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created_first is True
        count_after_first = db.query(System).count()

        second, created_second = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created_second is False
        assert second.id == first.id
        assert db.query(System).count() == count_after_first

    def test_duplicate_hostname_is_refused(
        self, db, admin_user, credential, distro, group
    ):
        first = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, first)
        drafts.finalize_draft(db, first, admin_user, finalize_token=token)

        second = _ready_draft(db, admin_user, credential, distro, group)
        second.connection = dict(second.connection, resolved_ip="10.60.0.99")
        db.commit()
        token2 = drafts.issue_finalize_token(db, second)

        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.finalize_draft(db, second, admin_user, finalize_token=token2)
        assert excinfo.value.code == "duplicate_host"

    def test_persisted_fields_survive_finalization(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        draft.connection = dict(draft.connection, ssh_port=2222)
        draft.organization = {
            "group_id": group.id,
            "tags": ["edge", "cache"],
            "environment": "Staging",
            "description": "front cache",
            "transport_preference": "ssh",
            "update_policy": "manual",
        }
        draft.discovery = {"architecture": "x86_64", "distro_version": "12.5"}
        db.commit()
        token = drafts.issue_finalize_token(db, draft)

        system, _ = drafts.finalize_draft(db, draft, admin_user, finalize_token=token)
        assert system.description == "front cache"
        assert system.transport_preference == "ssh"
        assert system.update_policy == "manual"
        assert system.os_version == "12.5"

        metadata = db.query(SystemMetadata).filter_by(system_id=system.id).first()
        assert metadata.ssh_port == 2222
        assert metadata.environment_type == "Staging"
        assert metadata.cpu_arch == "x86_64"

        rows = db.execute(
            system_tag.select().where(system_tag.c.system_id == system.id)
        ).fetchall()
        names = sorted(
            t.name
            for t in db.query(Tag).filter(Tag.id.in_([r.tag_id for r in rows])).all()
        )
        assert names == ["cache", "edge"]


class TestHostKeyIsAtomicWithTheHost:
    """The approved key and the host it authorizes commit together.

    A verification-required host that exists without the exact key the operator
    approved is not a partial success, it is a security hole: the draft's replay
    guard would also stop a retry from ever repairing it. So the key is written
    inside the finalization transaction, and a failure there must take the whole
    thing with it.
    """

    @staticmethod
    def _counts(db):
        return {
            "systems": db.query(System).count(),
            "metadata": db.query(SystemMetadata).count(),
            "host_keys": db.query(SSHHostKey).count(),
            "audits": db.query(SystemAudit).count(),
            "tag_links": len(db.execute(system_tag.select()).fetchall()),
        }

    def test_a_host_key_failure_rolls_back_the_entire_finalization(
        self, db, admin_user, credential, distro, group, monkeypatch
    ):
        before = self._counts(db)
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        def _explode(*_args, **_kwargs):
            raise RuntimeError("host key store unavailable")

        monkeypatch.setattr(drafts, "persist_verified_host_key", _explode)

        with pytest.raises(RuntimeError):
            drafts.finalize_draft(db, draft, admin_user, finalize_token=token)

        # Nothing survived: no host, no metadata, no tags, no system audit row,
        # no trust row.
        assert self._counts(db) == before

        # The draft is not completed, so it did not consume a host-cap seat and
        # is not replay-short-circuited into reporting success later.
        db.refresh(draft)
        assert draft.status != DRAFT_STATUS_COMPLETED
        assert draft.finalized_system_id is None

    def test_the_failure_is_not_swallowed(
        self, db, admin_user, credential, distro, group, monkeypatch
    ):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        monkeypatch.setattr(
            drafts,
            "persist_verified_host_key",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        # It raises rather than returning a system, so no caller can report
        # success off the back of it.
        with pytest.raises(RuntimeError):
            drafts.finalize_draft(db, draft, admin_user, finalize_token=token)

    def test_a_conflicting_stored_key_is_reported_and_rolls_back(
        self, db, admin_user, credential, distro, group, monkeypatch
    ):
        before = self._counts(db)
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        def _mismatch(*_args, **_kwargs):
            raise SSHConnectionError("Host key MISMATCH for ready-01.")

        monkeypatch.setattr(drafts, "persist_verified_host_key", _mismatch)

        with pytest.raises(drafts.DraftError) as excinfo:
            drafts.finalize_draft(db, draft, admin_user, finalize_token=token)
        assert excinfo.value.code == "host_key_conflict"
        assert self._counts(db) == before

    def test_the_key_and_the_host_become_durable_together(
        self, db, admin_user, credential, distro, group
    ):
        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)

        system, created = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created is True

        stored = db.query(SSHHostKey).filter_by(system_id=system.id).first()
        assert stored is not None
        # The exact captured material, not a re-derived approximation.
        assert stored.key_type == draft.host_key_type
        assert stored.public_key == draft.host_key_public
        assert stored.fingerprint == draft.host_key_fingerprint
        assert stored.verified is True
        assert stored.hostname == system.hostname

        db.refresh(draft)
        assert draft.status == DRAFT_STATUS_COMPLETED
        assert draft.finalized_system_id == system.id

    def test_a_draft_with_no_approved_key_still_finalizes(
        self, db, admin_user, credential, distro, group
    ):
        """Skipped verification produces no key to promote, and that is not a
        failure: the host is added Inactive with no trust row."""
        draft = _ready_draft(
            db,
            admin_user,
            credential,
            distro,
            group,
            verification=None,
            verification_skipped=True,
            host_key_public=None,
            host_key_fingerprint=None,
            host_key_type=None,
            host_key_decision="pending",
        )
        token = drafts.issue_finalize_token(db, draft)

        system, created = drafts.finalize_draft(
            db, draft, admin_user, finalize_token=token
        )
        assert created is True
        assert system.status == "Inactive"
        assert db.query(SSHHostKey).filter_by(system_id=system.id).first() is None


class TestHostKeyHelperContract:
    """The shared writer keeps its existing behavior for handshake callers."""

    def test_it_commits_by_default(self, db, admin_user, credential, distro, group):
        from app.services.ssh_service import persist_verified_host_key

        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)
        system, _ = drafts.finalize_draft(db, draft, admin_user, finalize_token=token)
        db.query(SSHHostKey).filter_by(system_id=system.id).delete()
        db.commit()

        # An SSH handshake caller passes no `commit`, and the row must be
        # durable before the connection it authorizes is allowed to proceed.
        row = persist_verified_host_key(
            db,
            system=system,
            key_type="ssh-ed25519",
            public_key="AAAAC3NzaC1lZDI1NTE5AAAAI-handshake",
            fingerprint="c" * 64,
        )
        assert row.id is not None
        assert row.verified is True

    def test_a_changed_key_is_refused_rather_than_overwritten(
        self, db, admin_user, credential, distro, group
    ):
        from app.services.ssh_service import persist_verified_host_key

        draft = _ready_draft(db, admin_user, credential, distro, group)
        token = drafts.issue_finalize_token(db, draft)
        system, _ = drafts.finalize_draft(db, draft, admin_user, finalize_token=token)

        with pytest.raises(SSHConnectionError):
            persist_verified_host_key(
                db,
                system=system,
                key_type="ssh-ed25519",
                public_key="AAAAC3NzaC1lZDI1NTE5AAAAI-a-different-key",
                fingerprint="d" * 64,
                commit=False,
            )

        db.rollback()
        stored = db.query(SSHHostKey).filter_by(system_id=system.id).first()
        # The approved key stands; re-trusting is a deliberate act elsewhere.
        assert stored.public_key == _ED25519_PUBLIC
