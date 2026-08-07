"""PRA-158 #3b: trust-bundle endpoint tests.

Surface under test:
  * ``GET /mirrors/{id}/trust-bundle``     — JSON
  * ``GET /mirrors/{id}/trust-bundle.asc`` — concatenated armored

Locks asserted:
  * Bundle includes active + pending_cutover + rotating_out, NEVER
    retired.
  * Bundle ordering is locked: active first, then pending_cutover,
    then rotating_out.
  * Authenticated only — no anonymous access.
"""

from __future__ import annotations

import pytest

from app.db.models import MirrorRepo, MirrorSigningKey
from app.services.mirror_signing_key_service import vault_path_for

_ACTIVE_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
_PENDING_FPR = "B" * 40
_ROTATING_FPR = "C" * 40
_RETIRED_FPR = "D" * 40


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="bundle-mirror",
        display_name="Bundle Mirror",
        package_family="deb",
        upstream_url="http://example.com/ubuntu",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


def _add_key(db, mirror, *, status, fpr, armored=None):
    """Insert a hand-rolled signing-key row for bundle testing."""
    if armored is None:
        armored = (
            f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUBLIC-{fpr}\n-----END-----\n"
        )
    row = MirrorSigningKey(
        mirror_repo_id=mirror.id,
        status=status,
        gpg_fingerprint=fpr,
        key_uid=f"Praxis Mirror Signing {mirror.slug} {fpr}",
        vault_path=vault_path_for(mirror.slug, fpr),
        armored_public_key=armored,
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# JSON bundle
# ---------------------------------------------------------------------------


def test_trust_bundle_json_empty_when_no_keys(authed_client, mirror):
    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle")
    assert res.status_code == 200
    body = res.json()
    assert body["mirror_id"] == mirror.id
    assert body["mirror_slug"] == mirror.slug
    assert body["active_fingerprint"] is None
    assert body["keys"] == []


def test_trust_bundle_json_includes_active_pending_rotating(authed_client, db, mirror):
    _add_key(db, mirror, status="active", fpr=_ACTIVE_FPR)
    _add_key(db, mirror, status="pending_cutover", fpr=_PENDING_FPR)
    _add_key(db, mirror, status="rotating_out", fpr=_ROTATING_FPR)
    _add_key(db, mirror, status="retired", fpr=_RETIRED_FPR)

    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle")
    assert res.status_code == 200
    body = res.json()

    fingerprints = [k["fingerprint"] for k in body["keys"]]
    statuses = [k["status"] for k in body["keys"]]

    # Locked invariant: NEVER includes retired.
    assert _RETIRED_FPR not in fingerprints
    assert "retired" not in statuses

    # Locked ordering: active → pending_cutover → rotating_out.
    assert statuses == ["active", "pending_cutover", "rotating_out"]
    assert fingerprints == [_ACTIVE_FPR, _PENDING_FPR, _ROTATING_FPR]
    assert body["active_fingerprint"] == _ACTIVE_FPR

    # Each entry includes the armored public block.
    for entry in body["keys"]:
        assert "BEGIN PGP PUBLIC KEY BLOCK" in entry["armored"]
        assert entry["uid"].startswith("Praxis Mirror Signing")


def test_trust_bundle_json_no_active_when_only_rotating(authed_client, db, mirror):
    """Edge case: a mirror mid-rotation could theoretically have only
    rotating_out keys. ``active_fingerprint`` should be None — no
    fabricated value.
    """
    _add_key(db, mirror, status="rotating_out", fpr=_ROTATING_FPR)

    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle")
    assert res.status_code == 200
    body = res.json()
    assert body["active_fingerprint"] is None
    assert len(body["keys"]) == 1
    assert body["keys"][0]["status"] == "rotating_out"


def test_trust_bundle_json_404_on_missing_mirror(authed_client):
    res = authed_client.get("/mirrors/99999/trust-bundle")
    assert res.status_code == 404


def test_trust_bundle_json_404_on_soft_deleted(authed_client, db, mirror):
    from datetime import datetime

    mirror.deleted_at = datetime.utcnow()
    db.commit()
    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle")
    assert res.status_code == 404


def test_trust_bundle_json_requires_auth(client, db, mirror):
    """No anonymous access — locked in project_pra158_design_locks."""
    res = client.get(f"/mirrors/{mirror.id}/trust-bundle")
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# .asc concatenated bundle
# ---------------------------------------------------------------------------


def test_trust_bundle_asc_empty_body_when_no_keys(authed_client, mirror):
    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle.asc")
    assert res.status_code == 200
    assert res.text == ""
    assert res.headers["content-type"].startswith("application/pgp-keys")
    assert "praxis-mirror-bundle-mirror.asc" in res.headers["content-disposition"]


def test_trust_bundle_asc_concatenates_in_locked_order(authed_client, db, mirror):
    _add_key(db, mirror, status="active", fpr=_ACTIVE_FPR)
    _add_key(db, mirror, status="pending_cutover", fpr=_PENDING_FPR)
    _add_key(db, mirror, status="rotating_out", fpr=_ROTATING_FPR)
    _add_key(db, mirror, status="retired", fpr=_RETIRED_FPR)

    res = authed_client.get(f"/mirrors/{mirror.id}/trust-bundle.asc")
    assert res.status_code == 200
    body = res.text

    # All non-retired fingerprints appear; retired does NOT.
    assert _ACTIVE_FPR in body
    assert _PENDING_FPR in body
    assert _ROTATING_FPR in body
    assert _RETIRED_FPR not in body

    # Order is preserved: active before pending before rotating.
    assert body.index(_ACTIVE_FPR) < body.index(_PENDING_FPR)
    assert body.index(_PENDING_FPR) < body.index(_ROTATING_FPR)

    # Three PGP PUBLIC KEY BLOCKs.
    assert body.count("BEGIN PGP PUBLIC KEY BLOCK") == 3


def test_trust_bundle_asc_404_on_missing_mirror(authed_client):
    res = authed_client.get("/mirrors/99999/trust-bundle.asc")
    assert res.status_code == 404


def test_trust_bundle_asc_requires_auth(client, mirror):
    res = client.get(f"/mirrors/{mirror.id}/trust-bundle.asc")
    assert res.status_code == 401
