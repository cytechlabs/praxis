"""PRA-247: the bundled broker TLS cert is renewed before expiry, validated, and
replaced atomically.

Exercises the shell helpers in ``vault/scripts/broker-tls.sh`` with real
OpenSSL-validated fixtures (minted here via ``cryptography``) and a fake ``vault``
issue command. Proves the renewal decision (keep vs (re)issue) across
valid/near-expiry/expired/mismatched/untrusted/SAN-drift, and that issuance is
atomic (a bad issue leaves prior working files intact) with perms normalized.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_LIB = Path(
    os.environ.get("PRAXIS_BROKER_TLS_LIB")
    or Path(__file__).resolve().parents[3] / "vault" / "scripts" / "broker-tls.sh"
)

if not _LIB.exists():  # pragma: no cover - only when repo root isn't mounted
    pytest.skip("vault/scripts/broker-tls.sh not found", allow_module_level=True)

HOSTNAMES = "localhost,backend,127.0.0.1,agent-broker"
DEFAULT_SANS = ["localhost", "backend", "127.0.0.1", "agent-broker"]
_NOW = datetime.datetime.now(datetime.timezone.utc)


def _san_list(names):
    out = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def _pem_cert(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem_key(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _mint_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Praxis Broker CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mint_leaf(ca_key, ca_cert, sans, *, not_after, leaf_key=None):
    key = leaf_key or ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(_san_list(sans)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_material(dirp: Path, *, sans=None, not_after=None, ca=None, leaf_key=None):
    """Write server.crt/server.key/ca.crt into dirp and return the CA (key, cert)."""
    sans = sans or DEFAULT_SANS
    not_after = not_after or (_NOW + datetime.timedelta(days=300))
    ca_key, ca_cert = ca or _mint_ca()
    key, cert = _mint_leaf(
        ca_key, ca_cert, sans, not_after=not_after, leaf_key=leaf_key
    )
    (dirp / "server.crt").write_text(_pem_cert(cert))
    (dirp / "server.key").write_text(_pem_key(key))
    (dirp / "ca.crt").write_text(_pem_cert(ca_cert))
    return ca_key, ca_cert


def _run(snippet: str, *, env_extra=None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PRAXIS_BROKER_HOSTNAMES"] = HOSTNAMES
    if env_extra:
        env.update(env_extra)
    script = f'. "{_LIB}"\n{snippet}\n'
    return subprocess.run(
        ["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30
    )


def _needs_issue(dirp: Path, **env_extra) -> subprocess.CompletedProcess:
    d = str(dirp)
    return _run(
        f'broker_needs_issue "{d}/server.crt" "{d}/server.key" "{d}/ca.crt"',
        env_extra=env_extra,
    )


# --------------------------------------------------- renewal decision


def test_valid_cert_not_near_expiry_is_kept(tmp_path):
    _write_material(tmp_path)  # 300-day cert, matching key/CA/SANs
    r = _needs_issue(tmp_path)
    assert r.returncode == 1, f"expected keep, got reissue: {r.stdout}{r.stderr}"


def test_expiring_cert_is_renewed(tmp_path):
    _write_material(tmp_path, not_after=_NOW + datetime.timedelta(days=10))
    r = _needs_issue(tmp_path)  # default 30-day threshold
    assert r.returncode == 0
    assert "threshold" in r.stdout


def test_expired_cert_is_renewed(tmp_path):
    _write_material(tmp_path, not_after=_NOW - datetime.timedelta(days=1))
    r = _needs_issue(tmp_path)
    assert r.returncode == 0


def test_mismatched_cert_key_is_renewed(tmp_path):
    ca_key, ca_cert = _write_material(tmp_path)
    # Overwrite the key with a DIFFERENT keypair -> cert/key no longer match.
    other = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "server.key").write_text(_pem_key(other))
    r = _needs_issue(tmp_path)
    assert r.returncode == 0


def test_invalid_chain_is_renewed(tmp_path):
    # Cert signed by CA-A, but ca.crt is an unrelated CA-B -> chain invalid.
    _write_material(tmp_path)
    _other_ca_key, other_ca_cert = _mint_ca()
    (tmp_path / "ca.crt").write_text(_pem_cert(other_ca_cert))
    r = _needs_issue(tmp_path)
    assert r.returncode == 0


def test_unparseable_cert_is_renewed(tmp_path):
    _write_material(tmp_path)
    (tmp_path / "server.crt").write_text(
        "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"
    )
    r = _needs_issue(tmp_path)
    assert r.returncode == 0


def test_san_drift_is_renewed(tmp_path):
    # Valid, trusted, not-near-expiry — but SANs no longer cover the hostnames.
    _write_material(tmp_path, sans=["localhost"])
    r = _needs_issue(tmp_path)
    assert r.returncode == 0
    assert "SAN drift" in r.stdout


# --------------------------------------------------- issuance atomicity


def _mk_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _fake_vault(tmp_path: Path, issue_payload: dict):
    binp = tmp_path / "bin"
    binp.mkdir(exist_ok=True)
    jsonf = tmp_path / "issue.json"
    jsonf.write_text(json.dumps(issue_payload))
    # PRA-311: broker-tls.sh issues via `bao write` against bundled OpenBao.
    _mk_exec(
        binp / "bao",
        "#!/bin/sh\n"
        'if [ "$1" = "write" ]; then\n'
        '  for a in "$@"; do case "$a" in *issue/server*) cat "$FAKE_VAULT_ISSUE_JSON"; exit 0;; esac; done\n'
        "fi\n"
        "exit 0\n",
    )
    # Hermetic `jq -r <path>` shim (the vault container ships jq; some test envs
    # don't). Extracts a dotted path like `.data.certificate` from stdin JSON.
    _mk_exec(
        binp / "jq",
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        "flt = sys.argv[-1].strip('.')\n"
        "d = json.load(sys.stdin)\n"
        "for p in flt.split('.'):\n"
        "    d = d[p]\n"
        "sys.stdout.write(str(d) + '\\n')\n",
    )
    return binp, jsonf


def test_issue_success_replaces_atomically(tmp_path):
    broker = tmp_path / "broker"
    broker.mkdir()
    _write_material(broker, not_after=_NOW - datetime.timedelta(days=1))  # expired
    old_crt = (broker / "server.crt").read_text()

    # Vault returns a fresh, valid, matching trio.
    ca_key, ca_cert = _mint_ca()
    key, cert = _mint_leaf(
        ca_key, ca_cert, DEFAULT_SANS, not_after=_NOW + datetime.timedelta(days=365)
    )
    payload = {
        "data": {
            "certificate": _pem_cert(cert),
            "private_key": _pem_key(key),
            "issuing_ca": _pem_cert(ca_cert),
        }
    }
    binp, jsonf = _fake_vault(tmp_path, payload)
    r = _run(
        f'broker_issue_cert "{broker}"',
        env_extra={
            "PATH": f"{binp}{os.pathsep}{os.environ['PATH']}",
            "FAKE_VAULT_ISSUE_JSON": str(jsonf),
        },
    )
    assert r.returncode == 0, r.stderr
    assert (broker / "server.crt").read_text() != old_crt  # replaced
    # jq -r appends a trailing newline; compare on content.
    assert (broker / "server.crt").read_text().strip() == _pem_cert(cert).strip()
    assert (broker / "server.key").read_text().strip() == _pem_key(key).strip()
    # No temp files left behind.
    assert not list(broker.glob("*.new"))


def test_issue_validation_failure_keeps_prior_files(tmp_path):
    broker = tmp_path / "broker"
    broker.mkdir()
    # Existing WORKING material (expired, so a renew would be attempted).
    _write_material(broker, not_after=_NOW - datetime.timedelta(days=1))
    old_crt = (broker / "server.crt").read_text()
    old_key = (broker / "server.key").read_text()
    old_ca = (broker / "ca.crt").read_text()

    # Vault returns a MISMATCHED trio (cert and key from different keypairs) ->
    # validation of the freshly issued temp files must fail, and the prior files
    # must be left untouched.
    ca_key, ca_cert = _mint_ca()
    _leaf_key, cert = _mint_leaf(
        ca_key, ca_cert, DEFAULT_SANS, not_after=_NOW + datetime.timedelta(days=365)
    )
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    payload = {
        "data": {
            "certificate": _pem_cert(cert),
            "private_key": _pem_key(wrong_key),  # does not match the cert
            "issuing_ca": _pem_cert(ca_cert),
        }
    }
    binp, jsonf = _fake_vault(tmp_path, payload)
    r = _run(
        f'broker_issue_cert "{broker}"',
        env_extra={
            "PATH": f"{binp}{os.pathsep}{os.environ['PATH']}",
            "FAKE_VAULT_ISSUE_JSON": str(jsonf),
        },
    )
    assert r.returncode != 0
    # Prior working files intact (not partially overwritten).
    assert (broker / "server.crt").read_text() == old_crt
    assert (broker / "server.key").read_text() == old_key
    assert (broker / "ca.crt").read_text() == old_ca
    assert not list(broker.glob("*.new"))  # temp files cleaned up


def test_issue_vault_failure_keeps_prior_files(tmp_path):
    broker = tmp_path / "broker"
    broker.mkdir()
    _write_material(broker, not_after=_NOW - datetime.timedelta(days=1))
    old_crt = (broker / "server.crt").read_text()
    # Fake vault that returns EMPTY output for the issue call -> issue fails.
    binp = tmp_path / "bin"
    binp.mkdir()
    vault = binp / "vault"
    vault.write_text("#!/bin/sh\nexit 0\n")  # prints nothing
    vault.chmod(vault.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    r = _run(
        f'broker_issue_cert "{broker}"',
        env_extra={"PATH": f"{binp}{os.pathsep}{os.environ['PATH']}"},
    )
    assert r.returncode != 0
    assert (broker / "server.crt").read_text() == old_crt
    assert not list(broker.glob("*.new"))


# --------------------------------------------------- perms normalization


def test_normalize_perms_runs(tmp_path):
    broker = tmp_path / "broker"
    broker.mkdir()
    _write_material(broker)
    # Start from wrong modes.
    for f in ("server.key", "server.crt", "ca.crt"):
        (broker / f).chmod(0o666)
    r = _run(f'broker_normalize_perms "{broker}"')
    assert r.returncode == 0
    assert stat.S_IMODE((broker / "server.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((broker / "server.crt").stat().st_mode) == 0o644
    assert stat.S_IMODE((broker / "ca.crt").stat().st_mode) == 0o644


# ------------------------------------- provision_broker_tls wrapper fail-closed


def _failing_vault(tmp_path: Path) -> Path:
    """Install a fake `vault` on PATH whose issue call produces no output."""
    binp = tmp_path / "bin"
    binp.mkdir(exist_ok=True)
    vault = binp / "vault"
    vault.write_text("#!/bin/sh\nexit 0\n")  # prints nothing -> issue fails
    vault.chmod(vault.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return binp


def test_provision_fails_closed_on_first_time_issue_failure(tmp_path):
    # Empty broker dir (first-time provision) + a Vault that can't issue. The
    # wrapper must return NONZERO (so init-vault.sh halts under set -e) and must
    # not leave any broker files behind.
    broker = tmp_path / "broker"
    broker.mkdir()
    binp = _failing_vault(tmp_path)
    r = _run(
        f'provision_broker_tls "{broker}"',
        env_extra={"PATH": f"{binp}{os.pathsep}{os.environ['PATH']}"},
    )
    assert r.returncode != 0, f"expected fail-closed, got rc=0: {r.stdout}{r.stderr}"
    assert not (broker / "server.crt").exists()
    assert not (broker / "server.key").exists()
    assert not list(broker.glob("*.new"))


def test_provision_fails_closed_on_expired_when_issue_fails(tmp_path):
    # Existing but EXPIRED material is not usable now; a failed reissue must fail
    # closed (nonzero) rather than silently keep the dead cert.
    broker = tmp_path / "broker"
    broker.mkdir()
    _write_material(broker, not_after=_NOW - datetime.timedelta(days=1))
    binp = _failing_vault(tmp_path)
    r = _run(
        f'provision_broker_tls "{broker}"',
        env_extra={"PATH": f"{binp}{os.pathsep}{os.environ['PATH']}"},
    )
    assert r.returncode != 0, f"expected fail-closed, got rc=0: {r.stdout}{r.stderr}"


def test_provision_keeps_valid_cert_when_renewal_fails(tmp_path):
    # Near-expiry (still valid today) cert triggers a proactive reissue. When that
    # reissue fails, the still-usable cert must be KEPT and the wrapper must return
    # 0 — a transient Vault outage must not crash-loop the stack with weeks of
    # validity left.
    broker = tmp_path / "broker"
    broker.mkdir()
    _write_material(broker, not_after=_NOW + datetime.timedelta(days=10))
    old_crt = (broker / "server.crt").read_text()
    old_key = (broker / "server.key").read_text()
    binp = _failing_vault(tmp_path)
    r = _run(
        f'provision_broker_tls "{broker}"',
        env_extra={"PATH": f"{binp}{os.pathsep}{os.environ['PATH']}"},
    )
    assert r.returncode == 0, f"expected keep-and-continue: {r.stdout}{r.stderr}"
    assert (broker / "server.crt").read_text() == old_crt  # untouched
    assert (broker / "server.key").read_text() == old_key
    assert not list(broker.glob("*.new"))


def test_provision_succeeds_and_issues_when_missing(tmp_path):
    # First-time provision with a WORKING Vault: wrapper issues, validates, and
    # returns 0 with a usable trio on disk.
    broker = tmp_path / "broker"
    broker.mkdir()
    ca_key, ca_cert = _mint_ca()
    key, cert = _mint_leaf(
        ca_key, ca_cert, DEFAULT_SANS, not_after=_NOW + datetime.timedelta(days=365)
    )
    payload = {
        "data": {
            "certificate": _pem_cert(cert),
            "private_key": _pem_key(key),
            "issuing_ca": _pem_cert(ca_cert),
        }
    }
    binp, jsonf = _fake_vault(tmp_path, payload)
    r = _run(
        f'provision_broker_tls "{broker}"',
        env_extra={
            "PATH": f"{binp}{os.pathsep}{os.environ['PATH']}",
            "FAKE_VAULT_ISSUE_JSON": str(jsonf),
        },
    )
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    assert (broker / "server.crt").read_text().strip() == _pem_cert(cert).strip()
    assert (broker / "server.key").read_text().strip() == _pem_key(key).strip()
    assert not list(broker.glob("*.new"))
