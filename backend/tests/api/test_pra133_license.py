"""PRA-133: offline license spine, host-cap enforcement, and activation.

Tokens are minted with an ephemeral Ed25519 keypair generated per test; the
matching public key is injected via the PRAXIS_LICENSE_PUBLIC_KEY env var. No
production key material is involved.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.entitlements import (
    ACCESS_SESSION_LOCKS,
    COMMANDS_METRICS,
    FREE_HOST_CAP,
    LICENSE_STATE_ACTIVE,
    LICENSE_STATE_EXPIRED,
    LICENSE_STATE_INVALID,
    LICENSE_STATE_MALFORMED,
    LICENSE_STATE_NONE,
    LICENSE_STATE_WRONG_INSTANCE,
    TIER_BUSINESS,
    TIER_ENTERPRISE,
    TIER_PRO,
    registry,
)
from app.services import license_service
from app.services.license_service import LicenseError

PAID_SAMPLE = [ACCESS_SESSION_LOCKS, COMMANDS_METRICS]


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv_pem, pub_pem


def _mint(
    priv_pem,
    *,
    instance_id,
    tier=TIER_PRO,
    host_cap=50,
    entitlements=None,
    exp_days=365,
    issued_to="ACME Corp",
    extra=None,
):
    now = datetime.now(timezone.utc)
    payload = {
        "tier": tier,
        "host_cap": host_cap,
        "issued_to": issued_to,
        "instance_id": instance_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=exp_days)).timestamp()),
        "entitlements": PAID_SAMPLE if entitlements is None else entitlements,
        "license_id": "lic-test-1",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, priv_pem, algorithm="EdDSA")


@pytest.fixture
def license_keys(monkeypatch):
    priv, pub = _keypair()
    monkeypatch.setenv(license_service.LICENSE_PUBLIC_KEY_ENV, pub)
    return priv, pub


def _seed_systems(db, seed_distro, count, *, status="Active", start=0):
    from app.db.models import Credential, Group, System

    group = db.query(Group).filter(Group.name == "pra133-cap").first()
    if group is None:
        group = Group(name="pra133-cap", description="x")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter(Credential.name == "pra133-cred").first()
    if cred is None:
        cred = Credential(name="pra133-cred", auth_method="ssh_key", username="root")
        db.add(cred)
        db.flush()
    for i in range(start, start + count):
        db.add(
            System(
                hostname=f"pra133-host-{i}.example.com",
                # Keep every octet valid even for large ``start`` values.
                ip_address=f"198.51.{100 + (i // 254)}.{(i % 254) + 1}",
                distro_id=seed_distro.id,
                os_version="22.04",
                status=status,
                group_id=group.id,
                credentials_id=cred.id,
            )
        )
    db.flush()


def _cap_group_cred(db):
    from app.db.models import Credential, Group

    return (
        db.query(Group).filter(Group.name == "pra133-cap").first(),
        db.query(Credential).filter(Credential.name == "pra133-cred").first(),
    )


# --------------------------------------------------------------------------- #
# instance_id
# --------------------------------------------------------------------------- #


def test_instance_id_is_stable(db):
    first = license_service.get_or_create_instance_id(db)
    second = license_service.get_or_create_instance_id(db)
    assert first and first == second
    assert license_service.get_instance_id(db) == first


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #


def test_verify_valid_token(db, license_keys):
    priv, pub = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_PRO, host_cap=50)
    claims = license_service.verify_token(
        token, public_key_pem=pub, expected_instance_id=iid
    )
    assert claims.tier == TIER_PRO
    assert claims.host_cap == 50
    assert claims.issued_to == "ACME Corp"
    assert set(claims.entitlements) == set(PAID_SAMPLE)


def test_verify_expired_token(db, license_keys):
    priv, pub = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, exp_days=-1)
    with pytest.raises(LicenseError) as ei:
        license_service.verify_token(
            token, public_key_pem=pub, expected_instance_id=iid
        )
    assert ei.value.state == LICENSE_STATE_EXPIRED


def test_verify_wrong_instance(db, license_keys):
    priv, pub = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id="some-other-install")
    with pytest.raises(LicenseError) as ei:
        license_service.verify_token(
            token, public_key_pem=pub, expected_instance_id=iid
        )
    assert ei.value.state == LICENSE_STATE_WRONG_INSTANCE


def test_verify_bad_signature(db, license_keys):
    priv, pub = license_keys
    other_priv, _ = _keypair()  # signed by a different key than pub verifies
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(other_priv, instance_id=iid)
    with pytest.raises(LicenseError) as ei:
        license_service.verify_token(
            token, public_key_pem=pub, expected_instance_id=iid
        )
    assert ei.value.state == LICENSE_STATE_INVALID


def test_verify_unsupported_tier(db, license_keys):
    priv, pub = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier="platinum")
    with pytest.raises(LicenseError) as ei:
        license_service.verify_token(
            token, public_key_pem=pub, expected_instance_id=iid
        )
    assert ei.value.state == LICENSE_STATE_INVALID


# --------------------------------------------------------------------------- #
# apply / evaluate / hydrate
# --------------------------------------------------------------------------- #


def test_apply_valid_license_hydrates_registry(db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(
        priv, instance_id=iid, tier=TIER_PRO, host_cap=50, entitlements=PAID_SAMPLE
    )
    status = license_service.apply_license(db, token)
    assert registry.tier == TIER_PRO
    assert registry.host_cap == 50
    assert registry.license_state == LICENSE_STATE_ACTIVE
    assert registry.is_active(ACCESS_SESSION_LOCKS) is True
    assert status["edition"] == TIER_PRO
    assert status["host_cap"] == 50
    assert status["license_state"] == LICENSE_STATE_ACTIVE
    # stored token round-trips through evaluate()
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE


def test_apply_business_license_uses_500_host_cap(db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_BUSINESS, host_cap=500)
    license_service.apply_license(db, token)
    assert registry.tier == TIER_BUSINESS
    assert registry.host_cap == 500


def test_apply_enterprise_license_requires_numeric_custom_cap(db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_ENTERPRISE, host_cap=750)
    license_service.apply_license(db, token)
    assert registry.tier == TIER_ENTERPRISE
    assert registry.host_cap == 750


def test_license_rejects_unlimited_host_cap(db, license_keys):
    priv, pub = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_BUSINESS, host_cap=None)
    with pytest.raises(LicenseError) as ei:
        license_service.verify_token(
            token, public_key_pem=pub, expected_instance_id=iid
        )
    assert ei.value.state == LICENSE_STATE_MALFORMED


def test_apply_invalid_license_stays_free(db, license_keys):
    priv, pub = license_keys
    other_priv, _ = _keypair()
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    bad = _mint(other_priv, instance_id=iid)  # wrong signature
    with pytest.raises(LicenseError):
        license_service.apply_license(db, bad)
    # registry not left in a paid state, and nothing stored
    assert registry.license_state == LICENSE_STATE_NONE
    assert registry.host_cap == FREE_HOST_CAP
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_NONE


def test_hydrate_noop_without_token(db):
    """No stored token -> hydrate leaves the registry untouched (preserves the
    enterprise default the test harness set)."""
    registry.enable_enterprise()
    license_service.hydrate_registry(db)
    assert registry.tier == TIER_ENTERPRISE
    assert registry.host_cap is None


def test_remove_license_returns_to_free(db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_PRO, host_cap=50)
    license_service.apply_license(db, token)
    assert registry.tier == TIER_PRO
    license_service.remove_license(db)
    assert registry.tier == "free"
    assert registry.host_cap == FREE_HOST_CAP
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_NONE


# --------------------------------------------------------------------------- #
# Host cap enforcement
# --------------------------------------------------------------------------- #


def test_assert_can_add_host_blocks_at_cap(db, seed_distro):
    from fastapi import HTTPException

    registry.reset()
    registry.set_host_cap(2)
    _seed_systems(db, seed_distro, 2)
    with pytest.raises(HTTPException) as ei:
        license_service.assert_can_add_host(db)
    assert ei.value.status_code == 403


def test_assert_can_add_host_allows_under_cap(db, seed_distro):
    registry.reset()
    registry.set_host_cap(5)
    _seed_systems(db, seed_distro, 2)
    license_service.assert_can_add_host(db)  # 2 < 5, no raise


def test_unlimited_cap_never_blocks(db, seed_distro):
    registry.enable_enterprise()  # host_cap None
    _seed_systems(db, seed_distro, 3)
    license_service.assert_can_add_host(db)  # unlimited


def test_decommissioned_hosts_do_not_count(db, seed_distro):
    from fastapi import HTTPException

    registry.reset()
    registry.set_host_cap(2)
    _seed_systems(db, seed_distro, 2, status="Active")
    _seed_systems(db, seed_distro, 1, status="Decommissioned", start=100)
    # active count is 2 (decommissioned excluded) -> at cap
    assert license_service.active_host_count(db) == 2
    with pytest.raises(HTTPException):
        license_service.assert_can_add_host(db)
    # lift cap to 3 -> the 2 active fit
    registry.set_host_cap(3)
    license_service.assert_can_add_host(db)


# --------------------------------------------------------------------------- #
# Route surface
# --------------------------------------------------------------------------- #


def test_edition_route_exposes_license_fields(authed_client):
    registry.reset()
    res = authed_client.get("/edition")
    assert res.status_code == 200
    data = res.json()
    for key in (
        "edition",
        "entitlements",
        "host_cap",
        "host_count",
        "instance_id",
        "tier",
        "license_state",
        "over_cap",
        "in_grace",
    ):
        assert key in data, f"missing {key}"
    assert data["tier"] == "free"
    assert data["license_state"] == LICENSE_STATE_NONE
    assert data["host_cap"] == FREE_HOST_CAP


def test_apply_license_route_admin(authed_client, db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_PRO, host_cap=50)
    res = authed_client.post("/edition/license", json={"token": token})
    assert res.status_code == 200
    data = res.json()
    assert data["tier"] == TIER_PRO
    assert data["license_state"] == LICENSE_STATE_ACTIVE
    assert data["host_cap"] == 50


def test_apply_license_route_rejects_bad_token(authed_client, db, license_keys):
    priv, _ = license_keys
    other_priv, _ = _keypair()
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    bad = _mint(other_priv, instance_id=iid)
    res = authed_client.post("/edition/license", json={"token": bad})
    assert res.status_code == 422
    assert res.json()["detail"]["state"] == LICENSE_STATE_INVALID


def test_remove_license_route(authed_client, db, license_keys):
    priv, _ = license_keys
    registry.reset()
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, tier=TIER_PRO, host_cap=50)
    authed_client.post("/edition/license", json={"token": token})
    res = authed_client.delete("/edition/license")
    assert res.status_code == 200
    assert res.json()["tier"] == "free"


# --------------------------------------------------------------------------- #
# Runtime expiry (P1: a hydrated license must deactivate when it lapses, without
# a restart or re-hydrate)
# --------------------------------------------------------------------------- #


def test_expired_license_deactivates_at_runtime():
    registry.reset()
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    registry.apply_license(
        tier=TIER_PRO,
        host_cap=50,
        entitlements=[ACCESS_SESSION_LOCKS],
        issued_to="ACME Corp",
        expires_at=past,
        license_id="lic-x",
    )
    # Every gating read reflects the lapse.
    assert registry.license_state == LICENSE_STATE_EXPIRED
    assert registry.is_active(ACCESS_SESSION_LOCKS) is False
    assert registry.host_cap == FREE_HOST_CAP
    assert registry.edition == "free"
    assert registry.tier == "free"
    assert all(v is False for v in registry.entitlement_map().values())


def test_expired_license_gates_paid_route(authed_client):
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    registry.apply_license(
        tier=TIER_PRO,
        host_cap=50,
        entitlements=[ACCESS_SESSION_LOCKS],
        issued_to="x",
        expires_at=past,
    )
    assert authed_client.get("/session-locks").status_code == 402


def test_unexpired_license_stays_active():
    registry.reset()
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    registry.apply_license(
        tier=TIER_PRO,
        host_cap=50,
        entitlements=[ACCESS_SESSION_LOCKS],
        issued_to="x",
        expires_at=future,
    )
    assert registry.license_state == LICENSE_STATE_ACTIVE
    assert registry.is_active(ACCESS_SESSION_LOCKS) is True
    assert registry.host_cap == 50


def test_runtime_expiry_records_grace_over_free_cap(authed_client, db, seed_distro):
    """A license that lapses at runtime while the install is over the free cap
    must record + surface the 14-day grace deadline via /edition (not only on
    apply/remove)."""
    registry.reset()
    _seed_systems(db, seed_distro, 16, status="Active")  # over the free cap of 15
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    registry.apply_license(
        tier=TIER_PRO,
        host_cap=50,
        entitlements=[ACCESS_SESSION_LOCKS],
        issued_to="ACME Corp",
        expires_at=past,
        license_id="lic-x",
    )
    data = authed_client.get("/edition").json()
    assert data["license_state"] == LICENSE_STATE_EXPIRED
    assert data["host_count"] == 16
    assert data["over_cap"] is True
    assert data["grace_until"] is not None
    assert data["in_grace"] is True


# --------------------------------------------------------------------------- #
# Decommissioned re-registration is gated by the cap (P1)
# --------------------------------------------------------------------------- #


def test_reregister_decommissioned_blocked_at_cap(authed_client, db, seed_distro):
    registry.reset()
    registry.set_host_cap(2)
    _seed_systems(db, seed_distro, 2, status="Active")  # at cap
    _seed_systems(db, seed_distro, 1, status="Decommissioned", start=500)
    group, cred = _cap_group_cred(db)
    body = {
        "hostname": "pra133-host-500.example.com",  # matches the decommissioned row
        "ip_address": "203.0.113.5",  # fresh IP so only the hostname matches
        "distro_id": seed_distro.id,
        "status": "Active",
        "group_id": group.id,
        "credentials_id": cred.id,
        "environment": "Production",
    }
    res = authed_client.post("/systems/add-system", json=body)
    assert res.status_code == 403, res.text


def test_reregister_decommissioned_allowed_under_cap(authed_client, db, seed_distro):
    registry.reset()
    registry.set_host_cap(5)
    _seed_systems(db, seed_distro, 1, status="Active")
    _seed_systems(db, seed_distro, 1, status="Decommissioned", start=600)
    group, cred = _cap_group_cred(db)
    body = {
        "hostname": "pra133-host-600.example.com",
        "ip_address": "203.0.113.6",
        "distro_id": seed_distro.id,
        "status": "Active",
        "group_id": group.id,
        "credentials_id": cred.id,
        "environment": "Production",
    }
    res = authed_client.post("/systems/add-system", json=body)
    assert res.status_code in (200, 201), res.text
