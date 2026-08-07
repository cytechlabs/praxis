"""Tests for PRA-149: access reviews.

Covers create-with-snapshots, attest/revoke/extend item lifecycle,
revoke-disables-binding, extend-bumps-expires_at, complete gating,
overdue sweep, REST 403, CSV export shape, and cadence skip logic.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.db.access_models import AccessBinding, AccessReview, AccessReviewItem
from app.db.models import AppSettings, Group
from app.services import access_review_service


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def fleet_role_id(db):
    """Reuse any existing FleetRole; M11 seeded built-ins so the table is non-empty."""
    from app.db.access_models import FleetRole

    fr = db.query(FleetRole).first()
    if fr is None:
        fr = FleetRole(
            name="r-pra149-base",
            login_mode="per_user",
            allowed_actions_json="[]",
            os_groups_json="[]",
        )
        db.add(fr)
        db.flush()
    return fr.id


def _mk_binding(db, *, user_id, group_id, fleet_role_id, enabled=True, expires_at=None):
    b = AccessBinding(
        subject_user_id=user_id,
        scope_group_id=group_id,
        fleet_role_id=fleet_role_id,
        enabled=enabled,
        expires_at=expires_at,
    )
    db.add(b)
    db.flush()
    return b


def _login(client, user):
    res = client.post(
        "/auth/login",
        data={"username": user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


# --------------------------------------------------- create


def test_create_review_snapshots_only_enabled_bindings(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    enabled_b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
        enabled=True,
    )
    _disabled_b = _mk_binding(
        db,
        user_id=admin_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
        enabled=False,
    )
    db.commit()

    review = access_review_service.create_review(
        db, creator=admin_user, scope="all", due_in_days=14
    )
    snapshot_ids = [
        json.loads(i.binding_snapshot_json)["binding_id"]
        for i in db.query(AccessReviewItem)
        .filter(AccessReviewItem.review_id == review.id)
        .all()
    ]
    assert enabled_b.id in snapshot_ids
    # Disabled bindings are excluded — only enabled are reviewed.
    assert all(sid != _disabled_b.id for sid in snapshot_ids)


def test_create_review_user_scope_filters(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    target_b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    _other_b = _mk_binding(
        db,
        user_id=admin_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()

    review = access_review_service.create_review(
        db, creator=admin_user, scope="user", scope_ref_id=maintainer_user.id
    )
    items = (
        db.query(AccessReviewItem).filter(AccessReviewItem.review_id == review.id).all()
    )
    assert len(items) == 1
    assert items[0].binding_id == target_b.id


# --------------------------------------------------- attest


def test_attest_item_marks_decided(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()
    review = access_review_service.create_review(db, creator=admin_user, scope="all")
    item = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.review_id == review.id,
            AccessReviewItem.binding_id == b.id,
        )
        .first()
    )
    out = access_review_service.attest_item(
        db, item_id=item.id, reviewer=admin_user, notes="ok"
    )
    assert out.action == "attest"
    assert out.decided_at is not None
    assert out.notes == "ok"


def test_attest_twice_rejects(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()
    review = access_review_service.create_review(db, creator=admin_user, scope="all")
    item = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.review_id == review.id,
            AccessReviewItem.binding_id == b.id,
        )
        .first()
    )
    access_review_service.attest_item(db, item_id=item.id, reviewer=admin_user)
    with pytest.raises(access_review_service.ReviewError) as exc:
        access_review_service.attest_item(db, item_id=item.id, reviewer=admin_user)
    assert exc.value.code == "invalid_state"


# --------------------------------------------------- revoke disables binding


def test_revoke_item_disables_binding(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()
    review = access_review_service.create_review(db, creator=admin_user, scope="all")
    item = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.review_id == review.id,
            AccessReviewItem.binding_id == b.id,
        )
        .first()
    )
    access_review_service.revoke_item(
        db, item_id=item.id, reviewer=admin_user, notes="left team"
    )
    db.expire_all()
    refreshed = db.query(AccessBinding).filter_by(id=b.id).first()
    assert refreshed.enabled is False


# --------------------------------------------------- extend bumps expires_at


def test_extend_item_bumps_expires_at(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    initial = datetime.utcnow() + timedelta(days=30)
    b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
        expires_at=initial,
    )
    db.commit()
    review = access_review_service.create_review(db, creator=admin_user, scope="all")
    item = (
        db.query(AccessReviewItem)
        .filter(
            AccessReviewItem.review_id == review.id,
            AccessReviewItem.binding_id == b.id,
        )
        .first()
    )
    access_review_service.extend_item(db, item_id=item.id, reviewer=admin_user, days=60)
    db.expire_all()
    refreshed = db.query(AccessBinding).filter_by(id=b.id).first()
    assert refreshed.expires_at == initial + timedelta(days=60)


# --------------------------------------------------- complete gating


def test_complete_blocked_until_all_decided(
    db, admin_user, maintainer_user, seed_default_group, fleet_role_id
):
    b1 = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    b2 = _mk_binding(
        db,
        user_id=admin_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()
    review = access_review_service.create_review(db, creator=admin_user, scope="all")
    items = (
        db.query(AccessReviewItem).filter(AccessReviewItem.review_id == review.id).all()
    )
    # Decide only one
    access_review_service.attest_item(db, item_id=items[0].id, reviewer=admin_user)
    with pytest.raises(access_review_service.ReviewError) as exc:
        access_review_service.complete_review(
            db, review_id=review.id, reviewer=admin_user
        )
    assert exc.value.code == "undecided"

    access_review_service.attest_item(db, item_id=items[1].id, reviewer=admin_user)
    completed = access_review_service.complete_review(
        db, review_id=review.id, reviewer=admin_user, summary="ok"
    )
    assert completed.state == "completed"
    assert completed.completed_at is not None
    _ = b1, b2  # quiet linter


# --------------------------------------------------- sweep_overdue


def test_sweep_overdue_marks_expired(db, admin_user):
    review = AccessReview(
        scope="all",
        state="pending",
        due_at=datetime.utcnow() - timedelta(days=1),
        created_by=admin_user.id,
    )
    db.add(review)
    db.commit()
    n = access_review_service.sweep_overdue(db)
    assert n >= 1
    db.expire_all()
    refreshed = db.query(AccessReview).filter_by(id=review.id).first()
    assert refreshed.state == "expired"


# --------------------------------------------------- cadence


def test_cadence_skips_when_pending_exists(db, admin_user):
    pending = AccessReview(
        scope="all",
        state="pending",
        due_at=datetime.utcnow() + timedelta(days=14),
        created_by=admin_user.id,
    )
    db.add(pending)
    db.commit()
    new_id = access_review_service.maybe_create_scheduled_review(db)
    assert new_id is None


def test_cadence_uses_app_setting(db):
    db.add(
        AppSettings(
            setting_key=access_review_service.CADENCE_SETTING_KEY,
            setting_value="42",
        )
    )
    db.commit()
    assert access_review_service.get_cadence_days(db) == 42


# --------------------------------------------------- REST


def test_rest_list_forbidden_for_auditor(client, auditor_user):
    _login(client, auditor_user)
    res = client.get("/access-reviews")
    assert res.status_code == 403


def test_rest_create_admin_only(client, maintainer_user):
    _login(client, maintainer_user)
    res = client.post("/access-reviews", json={"scope": "all"})
    assert res.status_code == 403


def test_rest_lifecycle_and_csv(
    client, admin_user, maintainer_user, seed_default_group, fleet_role_id, db
):
    b = _mk_binding(
        db,
        user_id=maintainer_user.id,
        group_id=seed_default_group.id,
        fleet_role_id=fleet_role_id,
    )
    db.commit()
    _login(client, admin_user)
    create_res = client.post("/access-reviews", json={"scope": "all"})
    assert create_res.status_code == 200, create_res.text
    review_id = create_res.json()["review"]["id"]

    detail = client.get(f"/access-reviews/{review_id}")
    assert detail.status_code == 200
    items = detail.json()["items"]
    target_item = next(i for i in items if i["binding_id"] == b.id)

    # Attest the one item we care about
    attest_res = client.post(
        f"/access-reviews/{review_id}/items/{target_item['id']}/attest",
        json={"notes": "ok"},
    )
    assert attest_res.status_code == 200

    # Decide remaining items so we can complete
    for i in items:
        if i["id"] == target_item["id"]:
            continue
        client.post(f"/access-reviews/{review_id}/items/{i['id']}/attest", json={})

    complete_res = client.post(
        f"/access-reviews/{review_id}/complete", json={"summary": "all good"}
    )
    assert complete_res.status_code == 200, complete_res.text

    csv_res = client.get(f"/access-reviews/{review_id}/export.csv")
    assert csv_res.status_code == 200
    body = csv_res.text
    assert "review_id,review_state,review_scope" in body
    assert "attest" in body
