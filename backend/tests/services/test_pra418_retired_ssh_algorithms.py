"""PRA-418: DSA, RSA/SHA-1, SHA-1 key exchange and GSSAPI are refused.

Two layers have to hold, and these tests separate them:

- the transport library itself no longer implements any of them, which is what
  removes the vulnerable RSA/SHA-1 signature path; and
- Praxis names them in an explicit floor that every connection carries, so the
  refusal does not silently depend on which release happens to be installed.

The distinction the suite keeps returning to is that ``ssh-rsa`` names two
different things. As RSA *key material* it is supported: pinned host keys,
stored credential keys and minted certificates all serialize under it. As a
*signature or host-key algorithm* it is the SHA-1 one, and it is refused.
"""

from __future__ import annotations

import importlib.util
import uuid

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.db.models import Credential, Group, System
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy
from app.services import onboarding_preflight_service as preflight
from app.services.ssh_service import (
    _PINNABLE_HOST_KEY_TYPES,
    SSHConnectionError,
    SSHKeyError,
    SSHService,
    configure_host_key_policy,
    disabled_from_allowlists,
    harden_disabled_algorithms,
    load_credential_private_key,
    load_pinned_host_key,
    supported_algorithms,
)

# The ECDSA curves OpenSSH offers as a host key, with the wire name each one
# is recorded under.
ECDSA_CURVES = (
    ("ecdsa-sha2-nistp256", ec.SECP256R1),
    ("ecdsa-sha2-nistp384", ec.SECP384R1),
    ("ecdsa-sha2-nistp521", ec.SECP521R1),
)

RETIRED_KEX = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    "gss-group14-sha1-toWM5Slw5Ew8Mqkay+al2g==",
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
)

# An OpenSSH DSA private key, generated once for this test. It carries no
# access to anything: it exists to be rejected.
DSA_PRIVATE_KEY = """-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD3yWfHM9U0RQmQ2gN6TF1YMc0Z1nq8bDCFBBVzTQvnLWCLXwUq
-----END DSA PRIVATE KEY-----
"""


# ------------------------------------------------ the library itself


def test_the_vulnerable_rsa_sha1_signature_path_is_gone():
    """The upstream removal, asserted rather than assumed from a pin."""
    assert tuple(int(p) for p in paramiko.__version__.split(".")[:2]) >= (5, 0)
    # RSA signatures are SHA-2 only. ``ssh-rsa`` is the SHA-1 identifier.
    assert "ssh-rsa" not in paramiko.RSAKey.HASHES
    assert "ssh-rsa-cert-v01@openssh.com" not in paramiko.RSAKey.HASHES
    assert set(paramiko.RSAKey.HASHES) == {
        "rsa-sha2-256",
        "rsa-sha2-256-cert-v01@openssh.com",
        "rsa-sha2-512",
        "rsa-sha2-512-cert-v01@openssh.com",
    }


def test_dsa_and_gssapi_are_not_implemented_at_all():
    assert not hasattr(paramiko, "DSSKey")
    assert [cls.__name__ for cls in paramiko.key_classes] == [
        "RSAKey",
        "Ed25519Key",
        "ECDSAKey",
    ]
    for module in ("paramiko.ssh_gss", "paramiko.kex_gss", "paramiko.kex_group1"):
        assert importlib.util.find_spec(module) is None, module


def test_no_retired_algorithm_is_offered_by_default():
    supported = supported_algorithms()
    for name in RETIRED_KEX:
        assert name not in supported["kex"]


# ------------------------------------------------ the Praxis floor


def test_the_floor_applies_with_no_caller_policy():
    disabled = harden_disabled_algorithms()
    assert "ssh-rsa" in disabled["keys"]
    assert "ssh-rsa-cert-v01@openssh.com" in disabled["keys"]
    assert "ssh-dss" in disabled["keys"]
    assert "ssh-rsa" in disabled["pubkeys"]
    assert "ssh-dss" in disabled["pubkeys"]
    for name in RETIRED_KEX:
        assert name in disabled["kex"]


def test_the_floor_extends_a_caller_policy_without_mutating_it():
    caller = {"kex": ["diffie-hellman-group16-sha512"], "ciphers": ["3des-cbc"]}
    disabled = harden_disabled_algorithms(caller)

    assert caller == {
        "kex": ["diffie-hellman-group16-sha512"],
        "ciphers": ["3des-cbc"],
    }
    assert disabled["ciphers"] == ["3des-cbc"]
    assert "diffie-hellman-group16-sha512" in disabled["kex"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]


def test_the_floor_does_not_repeat_a_name_the_caller_already_gave():
    disabled = harden_disabled_algorithms({"kex": ["diffie-hellman-group14-sha1"]})
    assert disabled["kex"].count("diffie-hellman-group14-sha1") == 1


def test_an_allow_list_naming_a_retired_algorithm_cannot_re_enable_it():
    """Allow-lists are subtractive, so a legacy entry buys nothing."""
    disabled = disabled_from_allowlists(
        allowed_ciphers="aes256-ctr",
        allowed_macs="hmac-sha2-512",
        allowed_kex="diffie-hellman-group14-sha1,diffie-hellman-group14-sha256",
    )
    for name in RETIRED_KEX:
        assert name in disabled["kex"]
    assert "ssh-rsa" in disabled["pubkeys"]
    # The one entry that is still supported is what the host negotiates.
    assert "diffie-hellman-group14-sha256" not in disabled["kex"]


def test_an_allow_list_with_nothing_negotiable_says_so(monkeypatch):
    """An all-legacy allow-list is reported, not left to fail as a bad host.

    Before the retired algorithms were removed this list negotiated; after,
    it selects nothing, and an empty proposal reaching the wire is
    indistinguishable from an unreachable host.
    """
    with pytest.raises(SSHConnectionError) as excinfo:
        disabled_from_allowlists(
            allowed_ciphers=None,
            allowed_macs=None,
            allowed_kex="diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
        )

    message = str(excinfo.value)
    assert "allows no supported key exchange algorithms" in message
    assert "diffie-hellman-group14-sha1" in message
    # The operator is told what they can use instead.
    assert "diffie-hellman-group14-sha256" in message


def test_a_partly_legacy_allow_list_still_connects():
    """One usable entry is enough; only an empty selection is an error."""
    disabled = disabled_from_allowlists(
        allowed_ciphers=None,
        allowed_macs=None,
        allowed_kex="diffie-hellman-group14-sha1,diffie-hellman-group14-sha256",
    )
    assert "diffie-hellman-group14-sha256" not in disabled["kex"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]


def test_preflight_reports_an_unnegotiable_policy_as_a_policy_rejection(db):
    """The same condition, surfaced through guided onboarding's check list."""
    policy = SSHSecurityPolicy(
        name=f"pra418-legacy-{uuid.uuid4().hex[:8]}",
        allowed_kex="diffie-hellman-group1-sha1",
    )
    result = preflight.PreflightResult()
    transport, started = preflight._start_transport(
        result,
        preflight.PreflightTarget(
            address="10.18.4.250",
            ssh_port=22,
            credential=None,
            policy=policy,
        ),
        sock=None,
    )

    assert started is False
    assert transport is None
    assert result.checks[-1]["reason_code"] == "ssh_policy_rejected"


def test_an_allow_list_still_narrows_what_it_does_name():
    supported = supported_algorithms()
    disabled = disabled_from_allowlists(
        allowed_ciphers="aes256-ctr",
        allowed_macs=None,
        allowed_kex=None,
    )
    assert "aes256-ctr" not in disabled["ciphers"]
    assert "aes128-ctr" in disabled["ciphers"]
    # A dimension the policy does not name keeps everything supported that the
    # floor does not retire; only the floor narrows it.
    retired = set(RETIRED_KEX)
    assert [name for name in supported["kex"] if name in disabled["kex"]] == [
        name for name in supported["kex"] if name in retired
    ]
    assert "macs" not in disabled


def test_the_floor_leaves_the_modern_algorithms_negotiable():
    """Fail-closed must not mean fail-shut: RSA-SHA2 still has to work."""
    transport = paramiko.Transport(
        __import__("socket").socket(),
        disabled_algorithms=harden_disabled_algorithms(),
    )
    try:
        assert "rsa-sha2-512" in transport.preferred_pubkeys
        assert "rsa-sha2-512-cert-v01@openssh.com" in transport.preferred_keys
        assert "ssh-ed25519" in transport.preferred_pubkeys
        assert transport.preferred_kex
        for offered in (
            transport.preferred_keys,
            transport.preferred_pubkeys,
            transport.preferred_kex,
        ):
            assert not [name for name in offered if name.startswith("ssh-rsa")]
            assert not [name for name in offered if name.startswith("ssh-dss")]
            assert not [name for name in offered if name.endswith("-sha1")]
            assert not [name for name in offered if name.startswith("gss-")]
    finally:
        transport.close()


# ------------------------------------------------ the service paths


def _system(db, seed_distro, admin_user, *, policy: SSHSecurityPolicy | None) -> System:
    tag = uuid.uuid4().hex[:8]
    grp = Group(name=f"pra418-{tag}")
    cred = Credential(
        name=f"pra418-cred-{tag}", auth_method="password", username="root"
    )
    db.add_all([grp, cred])
    db.flush()
    policy_id = None
    if policy is not None:
        policy.created_by = admin_user.id
        db.add(policy)
        db.flush()
        policy_id = policy.id
    system = System(
        hostname=f"pra418-{tag}.example.com",
        ip_address=f"10.18.4.{uuid.uuid4().int % 200 + 1}",
        distro_id=seed_distro.id,
        os_version="24.04",
        status="Active",
        group_id=grp.id,
        credentials_id=cred.id,
        ssh_security_policy_id=policy_id,
    )
    db.add(system)
    db.flush()
    return system


def test_a_system_with_no_policy_still_carries_the_floor(db, seed_distro, admin_user):
    system = _system(db, seed_distro, admin_user, policy=None)
    assert system.ssh_security_policy is None

    disabled = SSHService(db)._build_disabled_algorithms(system)

    assert "ssh-rsa" in disabled["pubkeys"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]


def test_a_configured_policy_is_applied_on_top_of_the_floor(
    db, seed_distro, admin_user
):
    system = _system(
        db,
        seed_distro,
        admin_user,
        policy=SSHSecurityPolicy(
            name=f"pra418-pol-{uuid.uuid4().hex[:8]}",
            allowed_ciphers="aes256-ctr",
            allowed_macs="hmac-sha2-512",
            allowed_kex="diffie-hellman-group-exchange-sha256",
        ),
    )

    disabled = SSHService(db)._build_disabled_algorithms(system)

    assert "aes256-ctr" not in disabled["ciphers"]
    assert "aes128-ctr" in disabled["ciphers"]
    assert "diffie-hellman-group-exchange-sha256" not in disabled["kex"]
    assert "diffie-hellman-group14-sha1" in disabled["kex"]
    assert "ssh-rsa" in disabled["pubkeys"]


def test_the_preflight_and_managed_translations_agree(db, seed_distro, admin_user):
    """Preflight must negotiate what the host will negotiate once managed."""
    policy = SSHSecurityPolicy(
        name=f"pra418-shared-{uuid.uuid4().hex[:8]}",
        allowed_ciphers="aes256-ctr,aes128-ctr",
        allowed_macs="hmac-sha2-512",
        allowed_kex="diffie-hellman-group14-sha256",
    )
    system = _system(db, seed_distro, admin_user, policy=policy)

    assert preflight.build_disabled_algorithms(policy) == SSHService(
        db
    )._build_disabled_algorithms(system)


# ------------------------------------------------ host keys and credentials


def _pin(db, system, *, key_type: str) -> SSHHostKey:
    hk = SSHHostKey(
        system_id=system.id,
        hostname=system.hostname,
        key_type=key_type,
        public_key=paramiko.RSAKey.generate(2048).get_base64(),
        fingerprint=f"fp-{uuid.uuid4().hex}",
        verified=True,
    )
    db.add(hk)
    db.flush()
    return hk


def test_a_pinned_dsa_host_key_fails_closed_with_a_sanitized_message(
    db, seed_distro, admin_user
):
    """DSA is refused by name, not by an internal parser error."""
    system = _system(db, seed_distro, admin_user, policy=None)
    _pin(db, system, key_type="ssh-dss")
    client = paramiko.SSHClient()

    with pytest.raises(SSHConnectionError) as excinfo:
        configure_host_key_policy(client, db, system)

    message = str(excinfo.value)
    assert "Unsupported host key type" in message
    assert "ssh-dss" in message
    assert system.hostname in message
    assert "SSH Security > Host Keys" in message
    # The refusal names the type, not an internal parser failure.
    assert "Traceback" not in message
    assert "paramiko" not in message
    assert "AttributeError" not in message
    # The refusing policy is installed before the key is read, so the client is
    # never left permissive by the failure.
    assert isinstance(client._policy, paramiko.RejectPolicy)


def test_a_pinned_rsa_host_key_is_still_accepted(db, seed_distro, admin_user):
    """``ssh-rsa`` as key material stays supported.

    Refusing this would unpin every RSA host key in a fleet, which is a
    different outcome from refusing the SHA-1 signature algorithm.
    """
    system = _system(db, seed_distro, admin_user, policy=None)
    pin = _pin(db, system, key_type="ssh-rsa")
    client = paramiko.SSHClient()

    configure_host_key_policy(client, db, system)

    assert isinstance(client._policy, paramiko.RejectPolicy)
    loaded = client.get_host_keys().lookup(system.hostname)
    assert loaded is not None
    assert loaded["ssh-rsa"].get_base64() == pin.public_key
    # Loaded as RSA material, which signs under RSA-SHA2 and never SHA-1.
    assert isinstance(loaded["ssh-rsa"], paramiko.RSAKey)


# ------------------------------------------------ pinned ECDSA host keys
#
# Paramiko negotiates ECDSA host keys by default, so a host that presents one
# has it captured on first use. Every curve it can capture has to be readable
# again on the next connection, or trust-on-first-use would pin a key that can
# never be verified.


def _ecdsa_host_key(curve_class):
    return paramiko.ECDSAKey.generate(curve=curve_class())


@pytest.mark.parametrize("key_type,curve_class", ECDSA_CURVES)
def test_a_pinned_ecdsa_host_key_loads_on_every_curve(key_type, curve_class):
    """The material comes back byte for byte, on the curve it was stored on."""
    key = _ecdsa_host_key(curve_class)
    assert key.get_name() == key_type

    loaded = load_pinned_host_key(key_type, key.get_base64(), hostname="h.example.com")

    assert isinstance(loaded, paramiko.ECDSAKey)
    assert loaded.get_name() == key_type
    assert loaded.asbytes() == key.asbytes()
    assert loaded == key


@pytest.mark.parametrize("key_type,curve_class", ECDSA_CURVES)
def test_a_pinned_ecdsa_host_key_is_preloaded_for_hostname_and_ip(
    db, seed_distro, admin_user, key_type, curve_class
):
    """The whole point of reading it: it is preloaded and RejectPolicy is on."""
    system = _system(db, seed_distro, admin_user, policy=None)
    key = _ecdsa_host_key(curve_class)
    db.add(
        SSHHostKey(
            system_id=system.id,
            hostname=system.hostname,
            key_type=key_type,
            public_key=key.get_base64(),
            fingerprint=f"fp-{uuid.uuid4().hex}",
            verified=True,
        )
    )
    db.flush()
    client = paramiko.SSHClient()

    configure_host_key_policy(client, db, system)

    assert isinstance(client._policy, paramiko.RejectPolicy)
    for name in (system.hostname, system.ip_address):
        entry = client.get_host_keys().lookup(name)
        assert entry is not None, name
        assert entry[key_type].asbytes() == key.asbytes()


def test_a_changed_ecdsa_host_key_is_refused(db, seed_distro, admin_user):
    """Changed-key review is unaffected: the pin is on the material.

    The stored key is preloaded and ``RejectPolicy`` installed, so a host
    offering different material of the same type is rejected by paramiko
    rather than silently re-trusted.
    """
    system = _system(db, seed_distro, admin_user, policy=None)
    pinned = _ecdsa_host_key(ec.SECP256R1)
    impostor = _ecdsa_host_key(ec.SECP256R1)
    assert pinned.asbytes() != impostor.asbytes()
    db.add(
        SSHHostKey(
            system_id=system.id,
            hostname=system.hostname,
            key_type="ecdsa-sha2-nistp256",
            public_key=pinned.get_base64(),
            fingerprint=f"fp-{uuid.uuid4().hex}",
            verified=True,
        )
    )
    db.flush()
    client = paramiko.SSHClient()

    configure_host_key_policy(client, db, system)

    stored = client.get_host_keys().lookup(system.hostname)["ecdsa-sha2-nistp256"]
    assert stored == pinned
    assert stored != impostor


@pytest.mark.parametrize(
    "body",
    ["", "not-base64!!", "AAAA", "c3NoLWVkMjU1MTk="],
    ids=["empty", "not-base64", "truncated", "wrong-algorithm"],
)
def test_a_malformed_ecdsa_host_key_fails_closed(body):
    """Unreadable material is refused, and the parser is not quoted back."""
    with pytest.raises(SSHConnectionError) as excinfo:
        load_pinned_host_key("ecdsa-sha2-nistp256", body, hostname="broken.example.com")

    message = str(excinfo.value)
    assert "could not be read" in message
    assert "broken.example.com" in message
    assert "SSH Security > Host Keys" in message
    assert "Traceback" not in message
    assert "paramiko" not in message
    assert "SSHException" not in message


def test_a_row_whose_curve_disagrees_with_its_material_fails_closed():
    """A row cannot claim one curve and pin another.

    Paramiko picks the reader from the requested type but takes the curve from
    the body, so without this check a row recorded as nistp256 would quietly
    pin a nistp384 key.
    """
    key = _ecdsa_host_key(ec.SECP384R1)

    with pytest.raises(SSHConnectionError) as excinfo:
        load_pinned_host_key(
            "ecdsa-sha2-nistp256", key.get_base64(), hostname="drift.example.com"
        )

    message = str(excinfo.value)
    assert "recorded as ecdsa-sha2-nistp256" in message
    assert "ecdsa-sha2-nistp384" in message
    assert "drift.example.com" in message


@pytest.mark.parametrize("key_type", ["ssh-dss", "ssh-dss-cert-v01@openssh.com"])
def test_a_pinned_dsa_host_key_type_is_refused_by_name(key_type):
    """DSA stays refused now that the pinnable set has grown."""
    with pytest.raises(SSHConnectionError) as excinfo:
        load_pinned_host_key(key_type, "AAAA", hostname="legacy.example.com")

    message = str(excinfo.value)
    assert "Unsupported host key type" in message
    assert key_type in message
    assert "Ed25519, ECDSA (nistp256/384/521) and RSA" in message
    # Refused on the type alone, before the body is ever parsed.
    assert "could not be read" not in message


def test_capture_and_re_read_agree_for_every_host_key_algorithm():
    """First use can never pin a key the next connection cannot read.

    Trust-on-first-use records ``key.get_name()``, which names the key
    *material* and so differs from the negotiated host key algorithm: an RSA
    host key agreed as ``rsa-sha2-512`` is still recorded as ``ssh-rsa``. Every
    name a captured host key can report has to round-trip back through the
    reader, or a host would be pinned and then permanently unverifiable.
    """
    # Guard the enumeration below: if paramiko gains a reader, this test has
    # stopped covering everything and should be extended rather than trusted.
    assert {cls.__name__ for cls in paramiko.Transport._key_info.values()} == {
        "RSAKey",
        "Ed25519Key",
        "ECDSAKey",
    }

    captured = [paramiko.RSAKey.generate(2048)] + [
        paramiko.ECDSAKey.generate(curve=curve_class())
        for _, curve_class in ECDSA_CURVES
    ]
    for key in captured:
        assert key.get_name() in _PINNABLE_HOST_KEY_TYPES, key.get_name()
        reloaded = load_pinned_host_key(
            key.get_name(), key.get_base64(), hostname="h.example.com"
        )
        assert reloaded.asbytes() == key.asbytes()

    # Ed25519 has no generator on PKey, so its name is asserted from the class
    # the readers table maps ``ssh-ed25519`` to.
    assert paramiko.Transport._key_info["ssh-ed25519"] is paramiko.Ed25519Key
    assert "ssh-ed25519" in _PINNABLE_HOST_KEY_TYPES


def test_a_stored_dsa_credential_key_is_refused_by_format(db):
    with pytest.raises(SSHKeyError) as excinfo:
        load_credential_private_key(DSA_PRIVATE_KEY)

    message = str(excinfo.value)
    assert "DSA format" in message
    assert "Ed25519, ECDSA" in message
    # No part of the key body reaches the operator-facing error.
    assert "MIIBuwIBAAKBgQD" not in message


def test_a_minted_certificate_key_serializes_as_ssh_rsa():
    """What the secrets service is asked to sign is still an ``ssh-rsa`` line.

    The three certificate paths all build this string, so a change here would
    break certificate auth on every governed host.
    """
    pkey = paramiko.RSAKey.generate(2048)
    assert f"{pkey.get_name()} {pkey.get_base64()}".startswith("ssh-rsa AAAA")
    assert paramiko.PKey.from_type_string("ssh-rsa", pkey.asbytes()).get_bits() == 2048
