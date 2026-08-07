"""Online license refresh (connected installs renew after Paddle renewals).

Covers the app-side contract:

- applying a valid license + refresh_token stores the token server-side;
- applying an invalid license stores nothing;
- manual refresh calls the EE bridge and applies the returned renewed license;
- EE unavailable / 404 leaves the current license active (never invalidated);
- a returned license that fails local validation is rejected, license kept;
- missing token -> refresh-not-configured;
- status surfaces configured/not-configured + last-attempt but NEVER the token,
  and the token never leaks through /edition or /app-settings.

Tokens are minted with an ephemeral Ed25519 keypair; the matching public key is
injected via PRAXIS_LICENSE_PUBLIC_KEY. No production key material is involved.
The EE bridge is stubbed by monkeypatching ``_call_ee_refresh`` — no network.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.entitlements import LICENSE_STATE_ACTIVE, TIER_PRO, registry
from app.services import license_service
from app.services.license_service import LicenseError

REFRESH_TOKEN = "rt-super-secret-value-do-not-leak"


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
        "entitlements": ["access.session_locks"],
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


# --------------------------------------------------- storage on apply


def test_apply_with_refresh_token_stores_it(db, license_keys):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid)

    license_service.apply_license(db, token, refresh_token=REFRESH_TOKEN)

    assert license_service.refresh_configured(db) is True
    assert license_service._stored_refresh_token(db) == REFRESH_TOKEN


def test_apply_without_refresh_token_leaves_it_unset(db, license_keys):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(db, _mint(priv, instance_id=iid))

    assert license_service.refresh_configured(db) is False


def test_apply_invalid_license_does_not_store_refresh_token(db, license_keys):
    # A token signed by a different key -> invalid signature -> nothing stored.
    other_priv, _ = _keypair()
    iid = license_service.get_or_create_instance_id(db)
    bad = _mint(other_priv, instance_id=iid)

    with pytest.raises(LicenseError):
        license_service.apply_license(db, bad, refresh_token=REFRESH_TOKEN)

    assert license_service.refresh_configured(db) is False
    assert license_service._stored_refresh_token(db) is None


def test_refresh_token_bound_to_instance_id(db, license_keys):
    """A stored token whose bound instance_id no longer matches is ignored."""
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(
        db, _mint(priv, instance_id=iid), refresh_token=REFRESH_TOKEN
    )
    assert license_service.refresh_configured(db) is True

    # Simulate a restored/cloned DB: rebind the stored blob to a different install.
    import json

    license_service._set_setting(
        db,
        license_service.REFRESH_KEY,
        json.dumps({"instance_id": "some-other-install", "token": REFRESH_TOKEN}),
    )
    assert license_service.refresh_configured(db) is False
    assert license_service._stored_refresh_token(db) is None


# --------------------------------------------------- manual refresh


def test_refresh_not_configured(db, license_keys):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(db, _mint(priv, instance_id=iid))  # no refresh token

    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_NOT_CONFIGURED
    # Current license untouched.
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE


def test_manual_refresh_applies_returned_license(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    # Start with a 50-cap license + a refresh token.
    license_service.apply_license(
        db, _mint(priv, instance_id=iid, host_cap=50), refresh_token=REFRESH_TOKEN
    )

    # EE returns a renewed license with a bigger cap + later expiry.
    renewed = _mint(priv, instance_id=iid, host_cap=200, exp_days=400)

    def fake_ee(instance_id, refresh_token):
        assert instance_id == iid
        assert refresh_token == REFRESH_TOKEN
        return 200, {
            "status": "ready",
            "license": renewed,
            "tier": "pro",
            "host_cap": 200,
        }

    monkeypatch.setattr(license_service, "_call_ee_refresh", fake_ee)

    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_OK
    # The renewed license is now the applied one.
    assert registry.host_cap == 200
    assert (
        license_service._get_setting(db, license_service.LICENSE_TOKEN_KEY) == renewed
    )
    # Refresh token is preserved (EE does not return a new one).
    assert license_service.refresh_configured(db) is True


def test_refresh_unavailable_keeps_license(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    original = _mint(priv, instance_id=iid, host_cap=50)
    license_service.apply_license(db, original, refresh_token=REFRESH_TOKEN)

    def boom(instance_id, refresh_token):
        raise RuntimeError("connection refused")  # transport failure

    monkeypatch.setattr(license_service, "_call_ee_refresh", boom)

    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_UNAVAILABLE
    # License untouched.
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE
    assert (
        license_service._get_setting(db, license_service.LICENSE_TOKEN_KEY) == original
    )


def test_refresh_503_keeps_license(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    original = _mint(priv, instance_id=iid)
    license_service.apply_license(db, original, refresh_token=REFRESH_TOKEN)

    monkeypatch.setattr(license_service, "_call_ee_refresh", lambda i, t: (503, None))
    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_UNAVAILABLE
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE


def test_refresh_404_keeps_license(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    original = _mint(priv, instance_id=iid)
    license_service.apply_license(db, original, refresh_token=REFRESH_TOKEN)

    monkeypatch.setattr(license_service, "_call_ee_refresh", lambda i, t: (404, None))
    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_REJECTED
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE
    assert (
        license_service._get_setting(db, license_service.LICENSE_TOKEN_KEY) == original
    )


def test_refresh_rejects_unverifiable_returned_license(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    original = _mint(priv, instance_id=iid)
    license_service.apply_license(db, original, refresh_token=REFRESH_TOKEN)

    # EE returns a license signed by the WRONG key -> local validation fails.
    other_priv, _ = _keypair()
    bad = _mint(other_priv, instance_id=iid)
    monkeypatch.setattr(
        license_service, "_call_ee_refresh", lambda i, t: (200, {"license": bad})
    )

    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_REJECTED
    # Original license still active.
    assert license_service.evaluate(db)["state"] == LICENSE_STATE_ACTIVE
    assert (
        license_service._get_setting(db, license_service.LICENSE_TOKEN_KEY) == original
    )


# --------------------------------------------------- auto-refresh


def test_auto_refresh_fires_near_expiry(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    # License expiring in 3 days (inside the 7-day window) + refresh token.
    license_service.apply_license(
        db, _mint(priv, instance_id=iid, exp_days=3), refresh_token=REFRESH_TOKEN
    )
    renewed = _mint(priv, instance_id=iid, host_cap=50, exp_days=365)
    monkeypatch.setattr(
        license_service, "_call_ee_refresh", lambda i, t: (200, {"license": renewed})
    )

    out = license_service.maybe_auto_refresh(db)

    assert out is not None and out["result"] == license_service.REFRESH_RESULT_OK
    assert (
        license_service._get_setting(db, license_service.LICENSE_TOKEN_KEY) == renewed
    )


def test_auto_refresh_skips_when_not_near_expiry(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(
        db, _mint(priv, instance_id=iid, exp_days=100), refresh_token=REFRESH_TOKEN
    )

    def fail(i, t):  # must not be called
        raise AssertionError("EE should not be contacted when not near expiry")

    monkeypatch.setattr(license_service, "_call_ee_refresh", fail)

    assert license_service.maybe_auto_refresh(db) is None


def test_auto_refresh_noop_without_token(db, license_keys, monkeypatch):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(db, _mint(priv, instance_id=iid, exp_days=3))

    def fail(i, t):
        raise AssertionError("EE should not be contacted without a refresh token")

    monkeypatch.setattr(license_service, "_call_ee_refresh", fail)

    assert license_service.maybe_auto_refresh(db) is None


# --------------------------------------------------- API surface + no-leak


def test_status_shows_configured_but_never_returns_token(
    authed_client, db, license_keys
):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid)

    # Apply via the API with a refresh token.
    res = authed_client.post(
        "/edition/license", json={"token": token, "refresh_token": REFRESH_TOKEN}
    )
    assert res.status_code == 200, res.text
    assert REFRESH_TOKEN not in res.text  # apply response must not echo the token

    # /edition status shows configured, never the token.
    edition = authed_client.get("/edition")
    assert edition.status_code == 200
    body = edition.json()
    assert body["online_refresh"]["configured"] is True
    assert REFRESH_TOKEN not in edition.text

    # /app-settings dump must never contain the secret refresh key/value.
    settings = authed_client.get("/app-settings")
    assert settings.status_code == 200
    assert REFRESH_TOKEN not in settings.text
    keys = {row["setting_key"] for row in settings.json()}
    assert license_service.REFRESH_KEY not in keys
    # The single-key fetch treats the secret as non-existent.
    assert (
        authed_client.get(f"/app-settings/{license_service.REFRESH_KEY}").status_code
        == 404
    )


def test_bulk_settings_put_never_leaks_refresh_token(authed_client, db, license_keys):
    # Regression: PUT /app-settings returns the full settings list; it must apply
    # the same secret filtering as GET so the refresh token can't leak there.
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    res = authed_client.post(
        "/edition/license",
        json={"token": _mint(priv, instance_id=iid), "refresh_token": REFRESH_TOKEN},
    )
    assert res.status_code == 200, res.text

    put = authed_client.put("/app-settings", json={"settings": {"timezone": "UTC"}})
    assert put.status_code == 200, put.text
    assert REFRESH_TOKEN not in put.text
    keys = {row["setting_key"] for row in put.json()}
    assert license_service.REFRESH_KEY not in keys
    assert "timezone" in keys  # the write still went through


# --------------------------------------------------- issued_to (PRA-279)


def test_apply_exposes_issued_to_via_edition(authed_client, db, license_keys):
    # The organization/licensee name comes only from the signed license claim and
    # must surface on /edition after applying.
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(priv, instance_id=iid, issued_to="Globex Corporation")

    res = authed_client.post("/edition/license", json={"token": token})
    assert res.status_code == 200, res.text
    assert res.json()["issued_to"] == "Globex Corporation"

    edition = authed_client.get("/edition")
    assert edition.status_code == 200
    assert edition.json()["issued_to"] == "Globex Corporation"


def test_refresh_updates_issued_to_from_renewed_license(db, license_keys, monkeypatch):
    # Authority is the signed license: a renewed license's issued_to wins.
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    license_service.apply_license(
        db,
        _mint(priv, instance_id=iid, issued_to="ACME Corp"),
        refresh_token=REFRESH_TOKEN,
    )
    assert license_service.license_status(db)["issued_to"] == "ACME Corp"

    renewed = _mint(priv, instance_id=iid, issued_to="ACME Corp International")
    monkeypatch.setattr(
        license_service, "_call_ee_refresh", lambda i, t: (200, {"license": renewed})
    )

    out = license_service.refresh_license(db)

    assert out["result"] == license_service.REFRESH_RESULT_OK
    assert out["status"]["issued_to"] == "ACME Corp International"
    assert license_service.license_status(db)["issued_to"] == "ACME Corp International"


def test_issued_to_non_string_is_dropped(db, license_keys):
    # A malformed (nested) issued_to must never surface as the licensee name.
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(
        priv, instance_id=iid, extra={"issued_to": {"email": "buyer@example.com"}}
    )

    license_service.apply_license(db, token)

    status = license_service.license_status(db)
    assert status["issued_to"] is None
    # And the nested email certainly must not leak.
    assert "buyer@example.com" not in str(status)


def test_edition_never_exposes_email_or_paddle_metadata(
    authed_client, db, license_keys
):
    # Even if the issuer put rogue claims in the token, only the explicit fields
    # are lifted — email / Paddle IDs / checkout metadata never reach the client.
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    token = _mint(
        priv,
        instance_id=iid,
        issued_to="Initech",
        extra={
            "customer_email": "cfo@initech.example",
            "paddle_price_id": "pri_01hxyzsecret",
            "checkout_id": "chk_should_not_appear",
        },
    )

    res = authed_client.post("/edition/license", json={"token": token})
    assert res.status_code == 200, res.text
    edition = authed_client.get("/edition")
    assert edition.status_code == 200
    assert edition.json()["issued_to"] == "Initech"
    for leak in ("cfo@initech.example", "pri_01hxyzsecret", "chk_should_not_appear"):
        assert leak not in edition.text


def test_refresh_endpoint_not_configured(authed_client, db, license_keys):
    priv, _ = license_keys
    iid = license_service.get_or_create_instance_id(db)
    authed_client.post("/edition/license", json={"token": _mint(priv, instance_id=iid)})

    res = authed_client.post("/edition/license/refresh")

    assert res.status_code == 200
    body = res.json()
    assert body["result"] == license_service.REFRESH_RESULT_NOT_CONFIGURED
    assert REFRESH_TOKEN not in res.text
