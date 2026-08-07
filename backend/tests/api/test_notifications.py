"""Integration tests for the notifications routes."""

from app.db.models import Notification


def _seed_notification(
    db, user_id=None, is_read=False, type="job_completed", title="t"
):
    n = Notification(
        type=type,
        title=title,
        message="msg",
        severity="info",
        is_read=is_read,
        user_id=user_id,
    )
    db.add(n)
    db.flush()
    return n


def test_list_notifications_shape(authed_client):
    res = authed_client.get("/notifications")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "total" in body
    assert "limit" in body
    assert "offset" in body
    assert isinstance(body["notifications"], list)


def test_list_notifications_includes_seeded(authed_client, admin_user, db):
    _seed_notification(db, user_id=admin_user.id, title="hello", is_read=False)
    res = authed_client.get("/notifications")
    assert res.status_code == 200
    titles = [n["title"] for n in res.json()["notifications"]]
    assert "hello" in titles


def test_unread_count_shape(authed_client):
    res = authed_client.get("/notifications/unread-count")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "unread_count" in body
    assert isinstance(body["unread_count"], int)


def test_unread_count_reflects_seeded(authed_client, admin_user, db):
    before = authed_client.get("/notifications/unread-count").json()["unread_count"]
    _seed_notification(db, user_id=admin_user.id, is_read=False, title="u1")
    _seed_notification(db, user_id=admin_user.id, is_read=False, title="u2")
    _seed_notification(db, user_id=admin_user.id, is_read=True, title="r1")

    after = authed_client.get("/notifications/unread-count").json()["unread_count"]
    assert after == before + 2


def test_filter_is_read_false(authed_client, admin_user, db):
    _seed_notification(db, user_id=admin_user.id, is_read=False, title="unread-one")
    _seed_notification(db, user_id=admin_user.id, is_read=True, title="read-one")

    res = authed_client.get("/notifications", params={"is_read": "false"})
    assert res.status_code == 200
    titles = [n["title"] for n in res.json()["notifications"]]
    assert "unread-one" in titles
    assert "read-one" not in titles
    # All returned notifications must be unread
    for n in res.json()["notifications"]:
        assert n["is_read"] is False
