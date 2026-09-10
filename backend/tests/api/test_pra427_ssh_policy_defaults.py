"""PRA-427: the SSH policy API creates policies with a negotiable key exchange.

A create that omits the algorithm fields stores the same defaults the model
and the seeded Default carry: modern cipher and MAC subsets, and an empty
key-exchange list that leaves every supported key exchange negotiable. What
a caller does send is stored as sent, and an update never touches a field it
does not name, which is also the supported recovery path for a policy that
was created under the old pinned key exchange.
"""

from __future__ import annotations

import uuid

from app.db.ssh_security_models import SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight
from app.services import ssh_service as sshs

POLICIES = "/ssh-security/policies"
LEGACY_KEX = "diffie-hellman-group-exchange-sha256"

# Pinned as literals: a regression must read as the wrong stored value.
EXPECTED_KEX = ""
EXPECTED_CIPHERS = "aes256-ctr,aes192-ctr,aes128-ctr"
EXPECTED_MACS = "hmac-sha2-512,hmac-sha2-256"


def _name() -> str:
    return f"pra427-api-{uuid.uuid4().hex[:8]}"


def _stored(db, policy_id: int) -> SSHSecurityPolicy:
    db.expire_all()
    return db.query(SSHSecurityPolicy).filter(SSHSecurityPolicy.id == policy_id).one()


def test_create_with_omitted_fields_stores_the_new_default(authed_client, db):
    name = _name()

    res = authed_client.post(POLICIES, json={"name": name})

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["allowed_kex"] == EXPECTED_KEX
    assert body["allowed_ciphers"] == EXPECTED_CIPHERS
    assert body["allowed_macs"] == EXPECTED_MACS
    assert body["require_host_key_verification"] is True

    row = _stored(db, body["id"])
    assert row.allowed_kex == EXPECTED_KEX
    assert row.allowed_ciphers == EXPECTED_CIPHERS
    assert row.allowed_macs == EXPECTED_MACS


def test_an_api_created_policy_negotiates_modern_key_exchange(authed_client, db):
    """What the route stores is what a handshake under it will offer."""
    res = authed_client.post(POLICIES, json={"name": _name()})
    assert res.status_code == 200, res.text
    row = _stored(db, res.json()["id"])

    disabled = preflight.build_disabled_algorithms(row)

    for name in ("curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"):
        assert name in sshs.supported_algorithms()["kex"]
        assert name not in disabled.get("kex", [])
    for name in sshs._RETIRED_ALGORITHMS["kex"]:  # pylint: disable=protected-access
        assert name in disabled["kex"]
    assert "aes128-cbc" in disabled["ciphers"]


def test_create_stores_an_explicit_restriction_as_sent(authed_client, db):
    """The default fills a gap; it never overrides what the caller chose."""
    res = authed_client.post(
        POLICIES, json={"name": _name(), "allowed_kex": LEGACY_KEX}
    )

    assert res.status_code == 200, res.text
    assert res.json()["allowed_kex"] == LEGACY_KEX
    row = _stored(db, res.json()["id"])
    assert row.allowed_kex == LEGACY_KEX
    disabled = preflight.build_disabled_algorithms(row)
    assert LEGACY_KEX not in disabled["kex"]
    assert "curve25519-sha256@libssh.org" in disabled["kex"]


def test_update_omitting_the_field_leaves_a_legacy_value_alone(authed_client, db):
    created = authed_client.post(
        POLICIES, json={"name": _name(), "allowed_kex": LEGACY_KEX}
    )
    policy_id = created.json()["id"]

    res = authed_client.put(f"{POLICIES}/{policy_id}", json={"description": "touched"})

    assert res.status_code == 200, res.text
    assert res.json()["allowed_kex"] == LEGACY_KEX
    assert _stored(db, policy_id).allowed_kex == LEGACY_KEX


def test_update_recovers_a_legacy_policy_without_touching_other_fields(
    authed_client, db
):
    created = authed_client.post(
        POLICIES,
        json={
            "name": _name(),
            "allowed_kex": LEGACY_KEX,
            "allowed_ciphers": "aes256-ctr",
            "max_auth_tries": 5,
        },
    )
    policy_id = created.json()["id"]

    res = authed_client.put(
        f"{POLICIES}/{policy_id}", json={"allowed_kex": EXPECTED_KEX}
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["allowed_kex"] == EXPECTED_KEX
    assert body["allowed_ciphers"] == "aes256-ctr"
    assert body["max_auth_tries"] == 5
    row = _stored(db, policy_id)
    assert row.allowed_kex == EXPECTED_KEX
    assert row.allowed_ciphers == "aes256-ctr"
    disabled = preflight.build_disabled_algorithms(row)
    assert "curve25519-sha256@libssh.org" not in disabled.get("kex", [])
    assert "aes128-ctr" in disabled["ciphers"]


def test_a_policy_named_only_with_retired_algorithms_cannot_negotiate(
    authed_client, db
):
    """The API stores what it is given; the floor refuses it at connect time."""
    res = authed_client.post(
        POLICIES, json={"name": _name(), "allowed_kex": "diffie-hellman-group14-sha1"}
    )
    assert res.status_code == 200, res.text
    row = _stored(db, res.json()["id"])

    try:
        preflight.build_disabled_algorithms(row)
    except sshs.SSHConnectionError as exc:
        assert "allows no supported key exchange algorithms" in str(exc)
    else:
        raise AssertionError("a retired-only allow-list was accepted")


def test_the_response_schema_reports_an_empty_list_as_empty(authed_client):
    """Clients see the stored value, not a null that reads as unset."""
    res = authed_client.post(POLICIES, json={"name": _name()})
    policy_id = res.json()["id"]

    fetched = authed_client.get(f"{POLICIES}/{policy_id}")

    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["allowed_kex"] == ""
