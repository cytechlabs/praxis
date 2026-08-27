"""PRA-154 slice #1b + #1d-α: admin CRUD endpoints for activation tokens."""

from __future__ import annotations

import pytest

from app.db.models import ActivationToken, Credential, Group, System, Tag
from tests.conftest import unique_test_ip


@pytest.fixture
def group(db):
    g = Group(name="m14-routes-test", description="PRA-154 routes")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def tag(db, admin_user):
    t = Tag(name="m14-tag", color="#123456", created_by=admin_user.id)
    db.add(t)
    db.flush()
    return t


def _make_system(db, group, seed_distro, hostname: str) -> System:
    cred = Credential(name=f"cred-{hostname}", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname=hostname,
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def target_system(db, group, seed_distro):
    return _make_system(db, group, seed_distro, "routes-target.example.com")


@pytest.fixture
def other_group_system(db, seed_distro):
    g = Group(name="m14-routes-other", description="other group")
    db.add(g)
    db.flush()
    return _make_system(db, g, seed_distro, "routes-other.example.com")


def _create_body(target_system, **overrides):
    body = {
        "name": "test enrollment",
        "default_group_id": target_system.group_id,
        "target_system_id": target_system.id,
        "ttl_seconds": 600,
        "max_uses": 1,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------- create


def test_create_returns_plaintext_once(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens", json=_create_body(target_system)
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["plaintext"].startswith("praxis_")
    assert data["status"] == "active"
    assert data["uses_count"] == 0
    assert data["max_uses"] == 1
    assert data["default_group_id"] == target_system.group_id
    assert data["target_system_id"] == target_system.id
    assert data["target_system_hostname"] == target_system.hostname
    listing = authed_client.get("/agent/activation-tokens").json()
    assert all("plaintext" not in t for t in listing)


def test_create_with_tags(authed_client, target_system, tag):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="tagged", default_tag_ids=[tag.id]),
    )
    assert res.status_code == 201, res.text
    assert res.json()["default_tag_ids"] == [tag.id]


def test_create_returns_bootstrap_command_when_public_url_set(
    authed_client, target_system, monkeypatch
):
    monkeypatch.setenv("PRAXIS_PUBLIC_URL", "https://praxis.example.com")
    res = authed_client.post(
        "/agent/activation-tokens", json=_create_body(target_system)
    )
    assert res.status_code == 201
    data = res.json()
    assert data["bootstrap_command"] is not None
    assert "https://praxis.example.com/agent/bootstrap.sh" in data["bootstrap_command"]
    assert data["plaintext"] in data["bootstrap_command"]
    assert f"PRAXIS_SYSTEM_ID='{target_system.id}'" in data["bootstrap_command"]
    assert data["bootstrap_command_unavailable_reason"] is None


def test_create_returns_null_command_with_reason_when_public_url_unset(
    authed_client, target_system, monkeypatch
):
    monkeypatch.delenv("PRAXIS_PUBLIC_URL", raising=False)
    res = authed_client.post(
        "/agent/activation-tokens", json=_create_body(target_system)
    )
    assert res.status_code == 201
    data = res.json()
    assert data["bootstrap_command"] is None
    assert data["bootstrap_command_unavailable_reason"] == "PRAXIS_PUBLIC_URL unset"


def test_create_rejects_unknown_group(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, default_group_id=999_999),
    )
    assert res.status_code == 400


def test_create_rejects_unknown_tag(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, default_tag_ids=[999_999]),
    )
    assert res.status_code == 400


def test_create_rejects_unknown_target_system(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, target_system_id=999_999),
    )
    assert res.status_code == 400


def test_create_rejects_target_system_in_different_group(
    authed_client, target_system, other_group_system
):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(
            target_system,
            default_group_id=target_system.group_id,
            target_system_id=other_group_system.id,
        ),
    )
    assert res.status_code == 400


def test_create_rejects_zero_max_uses(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, max_uses=0),
    )
    assert res.status_code == 422


def test_create_rejects_max_uses_above_one(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, max_uses=2),
    )
    # Pydantic le=1 rejects before service is invoked.
    assert res.status_code == 422


def test_create_rejects_too_short_ttl(authed_client, target_system):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, ttl_seconds=30),
    )
    assert res.status_code == 422


def test_create_rejects_duplicate_tags(authed_client, target_system, tag):
    res = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, default_tag_ids=[tag.id, tag.id]),
    )
    assert res.status_code == 422


# ---------------------------------------------------------------- list / get


def test_list_orders_newest_first(authed_client, db, target_system, seed_distro):
    second_target = _make_system(
        db, target_system.group, seed_distro, "second-target.example.com"
    )
    db.commit()
    a = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="a"),
    ).json()
    b = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(second_target, name="b"),
    ).json()
    listing = authed_client.get("/agent/activation-tokens").json()
    assert [t["id"] for t in listing[:2]] == [b["id"], a["id"]]


def test_get_returns_token_view(authed_client, target_system):
    created = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="lookup"),
    ).json()
    res = authed_client.get(f"/agent/activation-tokens/{created['id']}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == created["id"]
    assert data["target_system_id"] == target_system.id
    assert "plaintext" not in data


def test_get_404_for_unknown(authed_client):
    res = authed_client.get("/agent/activation-tokens/999999")
    assert res.status_code == 404


# ---------------------------------------------------------------- revoke


def test_revoke_marks_token_revoked(authed_client, db, target_system):
    created = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="to-revoke"),
    ).json()
    res = authed_client.post(f"/agent/activation-tokens/{created['id']}/revoke")
    assert res.status_code == 200
    assert res.json()["status"] == "revoked"
    assert res.json()["revoked_at"] is not None
    persisted = db.query(ActivationToken).filter_by(id=created["id"]).one()
    assert persisted.revoked_at is not None


def test_revoke_is_idempotent_via_route(authed_client, target_system):
    created = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="idem-revoke"),
    ).json()
    first = authed_client.post(
        f"/agent/activation-tokens/{created['id']}/revoke"
    ).json()
    second = authed_client.post(
        f"/agent/activation-tokens/{created['id']}/revoke"
    ).json()
    assert first["revoked_at"] == second["revoked_at"]


# ---------------------------------------------------------------- auth


def test_routes_require_admin(client, target_system):
    assert client.get("/agent/activation-tokens").status_code in (401, 403)
    assert client.post(
        "/agent/activation-tokens", json=_create_body(target_system)
    ).status_code in (401, 403)
    assert client.get("/agent/activation-tokens/1").status_code in (401, 403)
    assert client.post("/agent/activation-tokens/1/revoke").status_code in (401, 403)


# ---------------------------------------------------------------- audit


def test_create_emits_audit_event(authed_client, db, target_system):
    from app.db.access_models import AuditEvent

    authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="audited"),
    )
    after = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "activation_token.create")
        .count()
    )
    assert after == 1


def test_revoke_emits_audit_event(authed_client, db, target_system):
    from app.db.access_models import AuditEvent

    created = authed_client.post(
        "/agent/activation-tokens",
        json=_create_body(target_system, name="audited-revoke"),
    ).json()
    authed_client.post(f"/agent/activation-tokens/{created['id']}/revoke")
    revoke_rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "activation_token.revoke",
            AuditEvent.target_id == str(created["id"]),
        )
        .all()
    )
    assert len(revoke_rows) == 1
