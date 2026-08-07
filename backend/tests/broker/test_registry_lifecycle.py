"""PRA-151 task #15: AgentRegistry + heartbeat lifecycle.

Covers registration on accept, duplicate-tunnel replacement, heartbeat
send/recv liveness using ``time.monotonic()``, dead-after-silence
teardown, cert-expiry timer, throttled last_seen_at writes, and clean
unregister on disconnect.

Tests run with sub-second cadences to keep the suite fast — production
defaults (30s/90s) are exercised by the integration harness in task #18.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import ssl
import tempfile
from contextlib import asynccontextmanager
from functools import partial

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.broker.handlers import tunnel_handler
from app.broker.registry import AgentRegistry
from app.broker.tls import build_server_ssl_context

# ---------------------------------------------------------------------------
# minimal cert + ssl helpers (a slimmer copy of test_tls_handshake.py)
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mk_client_cert(ca_key, ca_cert, *, system_id=42, not_after_seconds=3600):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "placeholder")])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(seconds=not_after_seconds))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"praxis://system/{system_id}")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _mk_server_cert(ca_key, ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.DNSName("127.0.0.1")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_pair(key, cert):
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


def _write_ca(cert):
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".ca.crt")
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# server harness
# ---------------------------------------------------------------------------


@pytest.fixture
def trust_setup():
    ca_key, ca_cert = _mk_ca()
    server_key, server_cert = _mk_server_cert(ca_key, ca_cert)
    server_key_path, server_cert_path = _write_pair(server_key, server_cert)
    ca_path = _write_ca(ca_cert)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "ca_path": ca_path,
        "server_cert_path": server_cert_path,
        "server_key_path": server_key_path,
    }


@asynccontextmanager
async def _broker_with_handler(trust_setup, port, handler):
    """Run a websockets server with the supplied handler. Caller controls
    the registry / timing via ``functools.partial`` on ``tunnel_handler``."""
    ssl_ctx = build_server_ssl_context(
        server_certfile=trust_setup["server_cert_path"],
        server_keyfile=trust_setup["server_key_path"],
        client_ca_certfile=trust_setup["ca_path"],
    )
    server = await websockets.serve(
        handler,
        host="127.0.0.1",
        port=port,
        ssl=ssl_ctx,
        ping_interval=None,
        max_size=64 * 1024,
    )
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


def _client_ssl_ctx(client_key_path, client_cert_path, ca_path):
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return ctx


def _hello(client_cert, capabilities=None):
    fp = hashlib.sha256(
        client_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return {
        "type": "hello",
        "protocol_version": 1,
        "agent_version": "0.1.0",
        "capabilities": capabilities or ["exec", "facts", "heartbeat"],
        "cert_fingerprint": "sha256:" + fp,
    }


def _accept_validator(identity):
    return {"system_id": identity.system_id, "hostname": "h"}


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_on_welcome_and_unregister_on_close(
    trust_setup, unused_tcp_port
):
    """Successful handshake puts the entry in the registry; clean
    disconnect removes it."""
    registry = AgentRegistry()
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=30.0,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=42
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            welcome = json.loads(await ws.recv())
            assert welcome["type"] == "welcome"
            # Now registered
            await asyncio.sleep(0.05)
            assert len(registry) == 1
            entry = registry.get(42)
            assert entry is not None
            assert entry.tunnel_session_id == welcome["tunnel_session_id"]
            assert entry.agent_version == "0.1.0"

        # client closed → handler unregisters
        for _ in range(20):
            await asyncio.sleep(0.05)
            if registry.get(42) is None:
                break
        assert registry.get(42) is None


@pytest.mark.asyncio
async def test_duplicate_system_id_newest_wins(trust_setup, unused_tcp_port):
    """Second tunnel for the same system_id replaces the first; the
    first receives ``bye:replaced`` and is closed."""
    registry = AgentRegistry()
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=30.0,
    )

    client_key1, client_cert1 = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=99
    )
    client_key2, client_cert2 = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=99
    )
    p1 = _write_pair(client_key1, client_cert1)
    p2 = _write_pair(client_key2, client_cert2)
    ctx1 = _client_ssl_ctx(*p1, trust_setup["ca_path"])
    ctx2 = _client_ssl_ctx(*p2, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx1
        ) as ws1:
            await ws1.send(json.dumps(_hello(client_cert1)))
            await ws1.recv()  # welcome
            first_session = registry.get(99).tunnel_session_id

            async with websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx2
            ) as ws2:
                await ws2.send(json.dumps(_hello(client_cert2)))
                await ws2.recv()  # welcome

                # First tunnel must receive bye:replaced and close.
                bye = json.loads(await ws1.recv())
                assert bye == {"type": "bye", "reason": "replaced"}
                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await ws1.recv()

                # Registry now points at the second session.
                second_session = registry.get(99).tunnel_session_id
                assert second_session != first_session


@pytest.mark.asyncio
async def test_heartbeat_dead_silence_closes_tunnel(trust_setup, unused_tcp_port):
    """No traffic from the agent for ``heartbeat_dead_seconds`` -> broker
    sends bye:heartbeat_dead and closes."""
    registry = AgentRegistry()
    # Sub-second cadence: dead in 0.4s, watchdog polls every 0.08s.
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=10.0,  # don't let our own heartbeats matter
        heartbeat_dead_seconds=0.4,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=7
    )
    client_key_path, client_cert_path = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(client_key_path, client_cert_path, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome

            # Don't send anything else. Within ~1s we should get bye + close.
            bye = json.loads(await asyncio.wait_for(ws.recv(), timeout=2.0))
            assert bye == {"type": "bye", "reason": "heartbeat_dead"}
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()

    assert registry.get(7) is None


@pytest.mark.asyncio
async def test_inbound_messages_keep_tunnel_alive(trust_setup, unused_tcp_port):
    """Any inbound frame (heartbeat or otherwise) bumps last_recv and
    prevents the watchdog from declaring the tunnel dead."""
    registry = AgentRegistry()
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=0.4,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=8
    )
    p = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(*p, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome

            # Send heartbeats faster than the dead window for ~1s.
            for _ in range(10):
                await ws.send(
                    json.dumps(
                        {
                            "type": "heartbeat",
                            "ts": dt.datetime.utcnow().isoformat() + "Z",
                        }
                    )
                )
                await asyncio.sleep(0.1)

            # Tunnel should still be open.
            assert registry.get(8) is not None
            entry = registry.get(8)
            assert entry.last_recv_monotonic > entry.connected_at_monotonic


@pytest.mark.asyncio
async def test_broker_sends_periodic_heartbeats(trust_setup, unused_tcp_port):
    """Broker emits its own heartbeat at the configured cadence."""
    registry = AgentRegistry()
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=0.15,
        heartbeat_dead_seconds=10.0,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=11
    )
    p = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(*p, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome

            # Collect heartbeats received within ~0.5s.
            received = []
            try:
                while len(received) < 2:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1.0))
                    if msg.get("type") == "heartbeat":
                        received.append(msg)
            except asyncio.TimeoutError:
                pass
            assert len(received) >= 2, f"expected ≥2 heartbeats, got {received}"
            for hb in received:
                assert "ts" in hb


@pytest.mark.asyncio
async def test_cert_expiry_closes_tunnel(trust_setup, unused_tcp_port):
    """A cert with NotAfter ~1s in the future causes the broker to send
    bye:cert_expired and close at that time."""
    registry = AgentRegistry()
    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=10.0,
    )

    # 3s, not 1s: 1s lost intermittent races with the TLS handshake on
    # slower CI runners (the cert can expire mid-handshake, killing the
    # connection before _close_at_expiry has anything to close).
    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"],
        trust_setup["ca_cert"],
        system_id=14,
        not_after_seconds=3,
    )
    p = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(*p, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome

            bye = json.loads(await asyncio.wait_for(ws.recv(), timeout=3.0))
            assert bye == {"type": "bye", "reason": "cert_expired"}
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.recv()


@pytest.mark.asyncio
async def test_last_seen_writer_is_throttled(trust_setup, unused_tcp_port):
    """Many heartbeats from the agent should result in only the first
    DB write within the throttle window."""
    registry = AgentRegistry()
    write_calls = []

    def writer(system_id, agent_version=None):
        write_calls.append((system_id, agent_version, dt.datetime.utcnow()))

    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        last_seen_writer=writer,
        last_seen_throttle_seconds=10.0,  # generously larger than test
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=10.0,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=21
    )
    p = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(*p, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome
            # Hammer 20 heartbeats; only the first should write.
            for _ in range(20):
                await ws.send(
                    json.dumps(
                        {
                            "type": "heartbeat",
                            "ts": dt.datetime.utcnow().isoformat() + "Z",
                        }
                    )
                )
            await asyncio.sleep(0.2)

    assert len(write_calls) == 1
    assert write_calls[0][0] == 21


@pytest.mark.asyncio
async def test_last_seen_writer_receives_agent_version_on_connect(
    trust_setup, unused_tcp_port
):
    """PRA-324: the writer must fire once at connect (not only on the first
    heartbeat) and carry the hello's agent_version so the production writer
    can persist System.agent_version, which was previously never written."""
    registry = AgentRegistry()
    write_calls = []

    def writer(system_id, agent_version=None):
        write_calls.append((system_id, agent_version))

    handler = partial(
        tunnel_handler,
        identity_validator=_accept_validator,
        registry=registry,
        last_seen_writer=writer,
        last_seen_throttle_seconds=10.0,
        heartbeat_interval_seconds=10.0,
        heartbeat_dead_seconds=10.0,
    )

    client_key, client_cert = _mk_client_cert(
        trust_setup["ca_key"], trust_setup["ca_cert"], system_id=22
    )
    p = _write_pair(client_key, client_cert)
    ctx = _client_ssl_ctx(*p, trust_setup["ca_path"])

    async with _broker_with_handler(trust_setup, unused_tcp_port, handler):
        async with websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        ) as ws:
            await ws.send(json.dumps(_hello(client_cert)))
            await ws.recv()  # welcome
            # Give the connect-time write a beat to land; send NO heartbeat
            # so the only write is the one on connect.
            await asyncio.sleep(0.2)

    assert write_calls, "writer was never called on connect"
    assert write_calls[0] == (22, "0.1.0")


# ---------------------------------------------------------------------------
# pure registry unit tests
# ---------------------------------------------------------------------------


def test_registry_returns_none_for_unknown_system_id():
    reg = AgentRegistry()
    assert reg.get(999) is None
    assert len(reg) == 0


@pytest.mark.asyncio
async def test_unregister_only_evicts_matching_session():
    """The race we're guarding: an old coroutine's late unregister must
    NOT remove a newer entry that already replaced it."""
    from unittest.mock import MagicMock

    from app.broker.registry import TunnelEntry

    reg = AgentRegistry()
    fake_ws = MagicMock()

    old = TunnelEntry(
        system_id=1,
        tunnel_session_id="OLD",
        ws=fake_ws,
        identity=None,  # type: ignore[arg-type]
        capabilities=[],
        agent_version="x",
    )
    new = TunnelEntry(
        system_id=1,
        tunnel_session_id="NEW",
        ws=fake_ws,
        identity=None,  # type: ignore[arg-type]
        capabilities=[],
        agent_version="x",
    )
    await reg.register(old)
    displaced = await reg.register(new)
    assert displaced is old

    # Old coroutine tries to clean up after the fact — must be a no-op.
    removed = await reg.unregister(1, "OLD")
    assert removed is False
    assert reg.get(1) is new

    # New coroutine cleans up properly.
    removed = await reg.unregister(1, "NEW")
    assert removed is True
    assert reg.get(1) is None
