"""PRA-159 #2: MirrorServeCredentialService unit tests.

Covers:
  * issue returns plaintext + row, hash-only storage
  * issue revokes prior active credential
  * verify accepts valid bearer, rejects revoked / expired / unknown
  * stamp_used best-effort
  * revoke idempotency + list_for_host filtering
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Credential,
    Group,
    HostMirrorServeCredential,
    MirrorRepo,
    System,
)
from app.services.mirror_serve_credential_service import (
    MirrorServeCredentialError,
    MirrorServeCredentialService,
)


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="serve-cred-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    return m


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="serve-cred-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="serve-cred-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="serve-cred.example.com",
        ip_address="10.40.40.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def test_issue_returns_plaintext_and_stores_hash_only(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id)
    assert result.plaintext  # non-empty
    assert result.host_id == host.id
    assert result.mirror_id == mirror.id

    row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == result.credential_id)
        .one()
    )
    # Hash is stored, plaintext is not.
    assert row.token_hash != result.plaintext
    assert result.plaintext not in row.token_hash
    assert row.revoked_at is None


def test_issue_does_not_revoke_prior(db, host, mirror):
    """``issue`` is non-destructive: the apply
    orchestrator only revokes the prior bearer AFTER the host
    auth.conf / .repo file has been updated to use the new one.
    Multiple active credentials for the same (host, mirror) coexist.
    """
    svc = MirrorServeCredentialService(db)
    first = svc.issue(host_id=host.id, mirror_id=mirror.id)
    second = svc.issue(host_id=host.id, mirror_id=mirror.id)

    first_row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == first.credential_id)
        .one()
    )
    second_row = (
        db.query(HostMirrorServeCredential)
        .filter(HostMirrorServeCredential.id == second.credential_id)
        .one()
    )
    assert first_row.revoked_at is None
    assert second_row.revoked_at is None
    assert first.plaintext != second.plaintext

    # Both bearers verify until something explicitly revokes one.
    assert svc.verify(first.plaintext) is not None
    assert svc.verify(second.plaintext) is not None


def test_revoke_other_active_for_pair_revokes_only_others(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    first = svc.issue(host_id=host.id, mirror_id=mirror.id)
    second = svc.issue(host_id=host.id, mirror_id=mirror.id)
    third = svc.issue(host_id=host.id, mirror_id=mirror.id)

    revoked_ids = svc.revoke_other_active_for_pair(
        host_id=host.id, mirror_id=mirror.id, except_id=second.credential_id
    )
    assert sorted(revoked_ids) == sorted([first.credential_id, third.credential_id])

    # The kept credential still verifies; the others don't.
    assert svc.verify(second.plaintext) is not None
    assert svc.verify(first.plaintext) is None
    assert svc.verify(third.plaintext) is None


def test_revoke_other_active_for_pair_noop_on_fresh_host(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    only = svc.issue(host_id=host.id, mirror_id=mirror.id)
    # Nothing else to revoke.
    revoked = svc.revoke_other_active_for_pair(
        host_id=host.id, mirror_id=mirror.id, except_id=only.credential_id
    )
    assert revoked == []
    assert svc.verify(only.plaintext) is not None


def test_issue_rejects_unknown_host(db, mirror):
    svc = MirrorServeCredentialService(db)
    with pytest.raises(MirrorServeCredentialError, match="host"):
        svc.issue(host_id=99999, mirror_id=mirror.id)


def test_issue_rejects_unknown_mirror(db, host):
    svc = MirrorServeCredentialService(db)
    with pytest.raises(MirrorServeCredentialError, match="mirror"):
        svc.issue(host_id=host.id, mirror_id=99999)


def test_issue_rejects_zero_or_negative_ttl(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    with pytest.raises(MirrorServeCredentialError, match="ttl"):
        svc.issue(host_id=host.id, mirror_id=mirror.id, ttl_days=0)


def test_verify_accepts_valid(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id)
    cred = svc.verify(result.plaintext)
    assert cred is not None
    assert cred.id == result.credential_id


def test_verify_rejects_unknown_token(db):
    assert MirrorServeCredentialService(db).verify("not-a-real-token") is None


def test_verify_rejects_empty_or_none(db):
    svc = MirrorServeCredentialService(db)
    assert svc.verify("") is None
    assert svc.verify(None) is None  # type: ignore[arg-type]


def test_verify_rejects_revoked(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id)
    assert svc.revoke(result.credential_id) is True
    assert svc.verify(result.plaintext) is None


def test_verify_rejects_expired(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id, ttl_days=1)
    # Force the row's expires_at into the past.
    db.query(HostMirrorServeCredential).filter(
        HostMirrorServeCredential.id == result.credential_id
    ).update({"expires_at": datetime.utcnow() - timedelta(seconds=1)})
    db.commit()
    assert svc.verify(result.plaintext) is None


def test_revoke_idempotent_returns_false_second_time(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id)
    assert svc.revoke(result.credential_id) is True
    assert svc.revoke(result.credential_id) is False


def test_list_for_host_default_excludes_revoked(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    first = svc.issue(host_id=host.id, mirror_id=mirror.id)
    second = svc.issue(host_id=host.id, mirror_id=mirror.id)
    # issue() no longer auto-revokes (PRA-159 #3-a) — both are active
    # until the orchestrator explicitly revokes the other.
    assert len(svc.list_for_host(host.id)) == 2

    svc.revoke(first.credential_id)
    active = svc.list_for_host(host.id)
    assert len(active) == 1
    assert active[0].id == second.credential_id

    full = svc.list_for_host(host.id, include_revoked=True)
    assert len(full) == 2


def test_stamp_used_updates_last_used_at(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    result = svc.issue(host_id=host.id, mirror_id=mirror.id)
    cred = svc.verify(result.plaintext)
    assert cred.last_used_at is None
    svc.stamp_used(cred)
    db.refresh(cred)
    assert cred.last_used_at is not None
