"""PRA-151 task #13: broker mTLS handshake + peer cert validation.

Narrow scope: prove the broker process requires mTLS, accepts WSS,
extracts the peer cert via the websockets-lib transport (NOT Uvicorn,
which does not surface peer certs in ASGI scope), validates it against
the System identity, and rejects invalid cases. No registry,
heartbeat, nonce, or op flow yet.

These tests run a real broker on a high port for each test, drive it
with a real ``websockets`` client presenting various certs (good /
fingerprint-mismatched / serial-mismatched / no-SAN). Identity
validation is stubbed (``identity_validator`` callable) so we don't
touch the real DB or Vault here — the full end-to-end with Vault-issued
certs is exercised in the integration harness (task #18).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import ssl
import tempfile
from contextlib import asynccontextmanager

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.broker.handlers import REJECT_FINGERPRINT_MISMATCH, BrokerRejection
from app.broker.main import serve
from app.broker.tls import PeerIdentity

# ---------------------------------------------------------------------------
# helpers — mint a tiny self-signed CA and per-test client/server certs
# ---------------------------------------------------------------------------


def _mk_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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


def _mk_client_cert(ca_key, ca_cert, *, san_uri="praxis://system/42", cn="placeholder"):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(hours=1))
    )
    if san_uri is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _mk_server_cert(ca_key, ca_cert, hostname="localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(hostname), x509.DNSName("127.0.0.1")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_pair(key, cert) -> tuple[str, str]:
    kf = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    cf = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    kf.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cf.write(cert.public_bytes(serialization.Encoding.PEM))
    kf.close()
    cf.close()
    return kf.name, cf.name


def _write_ca(cert) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".ca.crt")
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def trust_setup(monkeypatch, tmp_path):
    """Generate a CA, a server cert/key, and the CA file path. Set
    PRAXIS_BROKER_TLS_* env vars so app.broker.main.serve uses them."""
    ca_key, ca_cert = _mk_ca()
    server_key, server_cert = _mk_server_cert(ca_key, ca_cert)
    server_key_path, server_cert_path = _write_pair(server_key, server_cert)
    ca_path = _write_ca(ca_cert)

    monkeypatch.setenv("PRAXIS_BROKER_TLS_KEY", server_key_path)
    monkeypatch.setenv("PRAXIS_BROKER_TLS_CERT", server_cert_path)
    monkeypatch.setenv("PRAXIS_BROKER_TLS_CA_CLIENT", ca_path)
    return {"ca_key": ca_key, "ca_cert": ca_cert, "ca_path": ca_path}


@asynccontextmanager
async def _running_broker(validator, port):
    # PRA-153: pass internal_port=0 so we don't compete for the
    # default 8444 between back-to-back tests in this suite.
    task = asyncio.create_task(
        serve(host="127.0.0.1", port=port, internal_port=0, validator=validator)
    )
    # wait briefly for socket bind
    for _ in range(20):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            break
        except OSError:
            await asyncio.sleep(0.05)
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, SystemExit):
            pass


def _client_ssl_ctx(client_key_path, client_cert_path, ca_path):
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False  # server cert is self-signed for tests
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return ctx


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def _hello(client_cert, *, version=1, agent_version="0.1.0", capabilities=None):
    """Build a valid hello payload for tests, with the client cert
    fingerprint already inlined in wire format (sha256:<hex>) to match
    the TLS-layer cert."""
    fp = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return {
        "type": "hello",
        "protocol_version": version,
        "agent_version": agent_version,
        "capabilities": capabilities
        if capabilities is not None
        else ["exec", "pty", "facts", "heartbeat"],
        "cert_fingerprint": "sha256:" + fp,
    }


@pytest.mark.asyncio
async def test_accept_valid_client_cert_with_full_handshake(
    trust_setup, unused_tcp_port
):
    """Identity validation passes AND the agent sends a valid hello —
    expect a fully populated welcome."""
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], san_uri="praxis://system/42"
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    received = {}

    def validator(identity: PeerIdentity):
        received["identity"] = identity
        return {"system_id": identity.system_id, "hostname": "h"}

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            msg = json.loads(await ws.recv())

    assert msg["type"] == "welcome"
    assert msg["system_id"] == 42
    # Welcome carries the wire format (sha256:<hex>); internal PeerIdentity
    # carries bare hex.
    assert (
        msg["cert_fingerprint"] == "sha256:" + received["identity"].fingerprint_sha256
    )
    assert msg["tunnel_session_id"]
    assert "server_time" in msg
    assert msg["heartbeat_interval_seconds"] == 30
    assert msg["heartbeat_dead_seconds"] == 90
    assert sorted(msg["accepted_capabilities"]) == sorted(
        ["exec", "pty", "facts", "heartbeat"]
    )


@pytest.mark.asyncio
async def test_capability_intersection_drops_unknown_agent_caps(
    trust_setup, unused_tcp_port
):
    """Agent advertises a capability the broker doesn't support — it gets
    dropped from accepted_capabilities silently (forward-compat)."""
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(
                json.dumps(
                    _hello(
                        client_cert,
                        capabilities=["exec", "made_up_capability_v99", "facts"],
                    )
                )
            )
            msg = json.loads(await ws.recv())

    assert "made_up_capability_v99" not in msg["accepted_capabilities"]
    assert sorted(msg["accepted_capabilities"]) == sorted(["exec", "facts"])


async def _expect_close_with_reason(ctx, port, payload, reason_substr):
    async with websockets.connect(
        f"wss://127.0.0.1:{port}/agent/tunnel", ssl=ctx
    ) as ws:
        await ws.send(payload)
        with pytest.raises(websockets.exceptions.ConnectionClosed) as ei:
            await ws.recv()
        assert ei.value.code == 4001, f"unexpected close code {ei.value.code}"
        assert reason_substr in (
            ei.value.reason or ""
        ), f"reason {ei.value.reason!r} does not contain {reason_substr!r}"


@pytest.mark.asyncio
async def test_reject_unsupported_protocol_version(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx,
            unused_tcp_port,
            json.dumps(_hello(client_cert, version=99)),
            "version",
        )


@pytest.mark.asyncio
async def test_reject_hello_fingerprint_mismatch(trust_setup, unused_tcp_port):
    """Agent lies about its cert fingerprint in the hello payload — even
    though the TLS-layer cert is valid, this is an integrity violation."""
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    bad_hello = _hello(client_cert)
    bad_hello["cert_fingerprint"] = "sha256:" + ("0" * 64)

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx, unused_tcp_port, json.dumps(bad_hello), "fingerprint"
        )


@pytest.mark.asyncio
async def test_reject_malformed_hello_not_json(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx, unused_tcp_port, "not json at all {{{", "json"
        )


@pytest.mark.asyncio
async def test_reject_hello_missing_field(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    incomplete = _hello(client_cert)
    del incomplete["agent_version"]

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx, unused_tcp_port, json.dumps(incomplete), "missing"
        )


@pytest.mark.asyncio
async def test_reject_hello_fingerprint_missing_prefix(trust_setup, unused_tcp_port):
    """Agent sends bare hex (no sha256: prefix) — wire format violation.
    Should be rejected as fingerprint_mismatch (not silently accepted)."""
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    bad = _hello(client_cert)
    fp = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    bad["cert_fingerprint"] = fp  # bare hex — missing the wire prefix

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx, unused_tcp_port, json.dumps(bad), "fingerprint"
        )


def test_normalize_serial_canonicalises_leading_zeros():
    """Regression: format(int_value, 'x') strips leading zero nibbles
    on the cert side, but naive colon-stripping on the DB side would
    keep them. Both must canonicalise to the same form."""
    from app.broker.tls import normalize_serial

    assert normalize_serial("0a:bc") == "abc"
    assert normalize_serial("0abc") == "abc"
    assert normalize_serial("abc") == "abc"
    assert normalize_serial("AB:CD") == "abcd"
    # Single-byte serial expressed two ways
    assert normalize_serial("0f") == normalize_serial("f") == "f"
    # All-zero serial collapses to "0"
    assert normalize_serial("00:00") == "0"
    # Non-hex returns the stripped lower form so the eventual compare
    # fails loudly instead of silently matching.
    assert normalize_serial("nothex") == "nothex"
    assert normalize_serial("") is None
    assert normalize_serial(None) is None


@pytest.mark.asyncio
async def test_db_validator_accepts_vault_style_colon_serial(
    trust_setup, unused_tcp_port
):
    """Regression: PRA-150 stores serials in Vault's aa:bb:cc form. The
    cert presents the same serial as bare hex (cryptography lib output).
    Validator must normalise both sides before comparing or every real
    Vault-issued cert is rejected as serial_mismatch."""
    from app.broker.handlers import make_db_validator

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], san_uri="praxis://system/77"
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    # Build a PeerIdentity exactly the way the handler will, so we test
    # the validator with the same shape it sees in production.
    cert_der = client_cert.public_bytes(serialization.Encoding.DER)
    bare_serial = format(client_cert.serial_number, "x")
    bare_fp = hashlib.sha256(cert_der).hexdigest()

    # The DB stores Vault-style colon-separated serial.
    colon_serial = ":".join(
        bare_serial[i : i + 2] for i in range(0, len(bare_serial), 2)
    )

    # Stand up a stub System object that mirrors a real DB row.
    class FakeSystem:
        id = 77
        hostname = "fake-host"
        agent_status = "active"
        agent_cert_serial = colon_serial
        agent_cert_fingerprint = bare_fp

    class FakeQuery:
        def __init__(self, system):
            self._system = system

        def filter(self, *_args, **_kw):
            return self

        def first(self):
            return self._system

    class FakeDB:
        def query(self, _model):
            return FakeQuery(FakeSystem())

        def close(self):
            pass

    def fake_session_factory():
        return FakeDB()

    validator = make_db_validator(fake_session_factory)

    # Build a real PeerIdentity by running the live extractor against an
    # SSL session — easier to do via the running broker than to fabricate
    # an SSLObject by hand.
    accepted_calls = {}

    def wrapping_validator(identity):
        accepted_calls["identity"] = identity
        return validator(identity)

    async with _running_broker(wrapping_validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            msg = json.loads(await ws.recv())

    assert msg["type"] == "welcome"
    assert msg["system_id"] == 77
    assert accepted_calls["identity"].serial_hex == bare_serial


@pytest.mark.asyncio
async def test_reject_wrong_message_type(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        return {"system_id": identity.system_id, "hostname": "h"}

    bad = _hello(client_cert)
    bad["type"] = "heartbeat"

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        await _expect_close_with_reason(
            ctx, unused_tcp_port, json.dumps(bad), "bad_type"
        )


@pytest.mark.asyncio
async def test_reject_when_validator_says_not_active(trust_setup, unused_tcp_port):
    """websockets 12 raises ConnectionClosedError on early server close.
    Verify the close reason carries our code."""
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"]
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):
        raise BrokerRejection(REJECT_FINGERPRINT_MISMATCH, "stub")

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        try:
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
            ) as ws:
                # If we got in, the server should close immediately.
                await ws.recv()
        except websockets.exceptions.ConnectionClosed as e:
            assert e.code == 4001
            assert REJECT_FINGERPRINT_MISMATCH in (e.reason or "")
        except websockets.exceptions.InvalidStatusCode as e:
            # Older client behavior — also acceptable
            assert e.status_code in (401, 403, 1006)


@pytest.mark.asyncio
async def test_reject_cert_with_no_san_uri(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], san_uri=None
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):  # pragma: no cover
        raise AssertionError("validator should not run when cert lacks SAN URI")

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        try:
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
            ) as ws:
                await ws.recv()
        except websockets.exceptions.ConnectionClosed as e:
            assert e.code == 4001
        except websockets.exceptions.InvalidStatusCode:
            pass  # also acceptable


@pytest.mark.asyncio
async def test_reject_cert_with_wrong_san_uri_format(trust_setup, unused_tcp_port):
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"],
        trust_setup["ca_cert"],
        san_uri="praxis://something-else/42",
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)

    def validator(identity):  # pragma: no cover
        raise AssertionError("validator should not run when SAN URI is wrong shape")

    async with _running_broker(validator, unused_tcp_port):
        ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])
        try:
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
            ) as ws:
                await ws.recv()
        except websockets.exceptions.ConnectionClosed as e:
            assert e.code == 4001
        except websockets.exceptions.InvalidStatusCode:
            pass


@pytest.mark.asyncio
async def test_reject_when_no_client_cert_presented(trust_setup, unused_tcp_port):
    """TLS handshake itself should fail before any handler runs."""

    def validator(identity):  # pragma: no cover
        raise AssertionError("validator should not run; TLS should reject first")

    async with _running_broker(validator, unused_tcp_port):
        ctx = ssl.create_default_context(cafile=trust_setup["ca_path"])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # No load_cert_chain — client presents nothing. Server-side TLS
        # rejection surfaces to the client as either an SSL/OSError, an
        # EOF before the WS upgrade, or websockets' wrapper exceptions.
        with pytest.raises(
            (
                ssl.SSLError,
                OSError,
                websockets.exceptions.InvalidMessage,
                ConnectionResetError,
                EOFError,
            )
        ):
            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
            ):
                pass  # pragma: no cover
