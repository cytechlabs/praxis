"""PRA-151 task #18: end-to-end fake-agent integration harness.

Goes wider than the unit tests: this drives the real PRA-150 Vault
signing path, a real System row in the test DB, the live broker
identity validator (DB lookup with normalised serials), and the full
tunnel + per-op WSS dance.

Skipped when /vault/data/backend-token isn't present (e.g. CI without
the bundled Vault profile). When run inside the dev compose stack the
token is mounted via the ``vault_data`` volume.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import json
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import date

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.broker.handlers import (
    REJECT_FINGERPRINT_MISMATCH,
    REJECT_NOT_ACTIVE,
    REJECT_SERIAL_MISMATCH,
    BrokerRejection,
    op_handler,
    tunnel_handler,
)
from app.broker.ops import OperationManager, OperationState
from app.broker.protocol import Channel, Frame, FrameOp, decode_frame, encode_frame
from app.broker.registry import AgentRegistry
from app.broker.tls import PeerIdentity, build_server_ssl_context, normalize_serial

from . import _certfx as cfx

# ---------------------------------------------------------------------------
# Vault availability gate
# ---------------------------------------------------------------------------

_BACKEND_TOKEN_PATH = "/vault/data/backend-token"


def _ensure_vault_token() -> bool:
    """Make sure VAULT_TOKEN is set so VaultService can authenticate.
    Returns False (skip) if no token is available."""
    if os.environ.get("VAULT_TOKEN"):
        return True
    if not os.path.exists(_BACKEND_TOKEN_PATH):
        return False
    try:
        with open(_BACKEND_TOKEN_PATH, encoding="utf-8") as f:
            os.environ["VAULT_TOKEN"] = f.read().strip()
    except OSError:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _ensure_vault_token(),
    reason="bundled Vault not available (no /vault/data/backend-token)",
)


# ---------------------------------------------------------------------------
# Fixtures: real Vault-signed cert + matching DB row
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_signed_agent(db):
    """Mint an agent cert through the real PRA-150 Vault path and seed
    a System row whose ``agent_*`` columns line up with the cert.

    Returns ``{system_id, client_key_path, client_cert_path,
    agent_ca_path, serial_normalized, fingerprint}``.
    """
    # Local imports keep test collection cheap when this fixture isn't used.
    from app.db.models import Credential, Distro, Group, System, VaultConfig
    from app.services.vault_service import VaultService

    # A running stack ships with an active internal VaultConfig (seeded by the
    # entrypoint's setup_vault.py), but the per-test SAVEPOINT'd test DB starts
    # empty — seed one so VaultService.initialize_client picks up http://vault:8200.
    if db.query(VaultConfig).filter_by(is_active=True).first() is None:
        db.add(VaultConfig(is_internal=True, server_url=None, is_active=True))
        db.flush()

    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if distro is None:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    # Reuse any existing group rather than INSERT a "Default" — the
    # migrated test DB already has seeded groups (e.g. "All Systems")
    # and the sequence state can collide with our manual insert.
    group = db.query(Group).order_by(Group.id).first()
    if group is None:
        group = Group(name="harness-default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter_by(name="harness-cred").first()
    if cred is None:
        cred = Credential(
            name="harness-cred",
            auth_method="password",
            username="root",
            vault_path="v/harness",
        )
        db.add(cred)
        db.flush()
    system = System(
        hostname="harness-host-1",
        ip_address="10.42.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.flush()

    # Generate the agent's own keypair + CSR. CN/SAN don't matter — the
    # Vault role discards them and substitutes backend-controlled values.
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "placeholder")])
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    vault = VaultService(db)
    signed = vault.sign_agent_csr(
        csr_pem=csr_pem,
        common_name=f"system-{system.id}.agent.praxis.internal",
        uri_san=f"praxis://system/{system.id}",
    )
    cert_pem = signed["certificate"]
    serial_from_vault = signed["serial_number"]  # may be aa:bb:cc form
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
    fingerprint = hashlib.sha256(
        cert_obj.public_bytes(serialization.Encoding.DER)
    ).hexdigest()

    # Update the System row to match the cert. Store the raw Vault
    # serial form to exercise the normalisation path.
    system.agent_status = "active"
    system.agent_cert_serial = serial_from_vault
    system.agent_cert_fingerprint = fingerprint
    system.agent_cert_expires_at = dt.datetime.utcnow() + dt.timedelta(hours=1)
    db.commit()

    # Materialise paths the websockets client will load.
    key_path = tempfile.NamedTemporaryFile(delete=False, suffix=".key").name
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    cert_path = tempfile.NamedTemporaryFile(delete=False, suffix=".crt").name
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(cert_pem)
        for chain_pem in signed.get("ca_chain") or []:
            f.write("\n")
            f.write(chain_pem)

    ca_pem = vault.get_agent_ca_bundle()
    ca_path = tempfile.NamedTemporaryFile(delete=False, suffix=".ca.crt").name
    with open(ca_path, "w", encoding="utf-8") as f:
        f.write(ca_pem)

    return {
        "system_id": system.id,
        "client_key_path": key_path,
        "client_cert_path": cert_path,
        "agent_ca_path": ca_path,
        "serial_normalized": normalize_serial(serial_from_vault),
        "fingerprint": fingerprint,
    }


@pytest.fixture
def broker_server_cert(vault_signed_agent):
    """Self-signed broker server cert (broker-CA mount lands in #19)."""
    ca_key, ca_cert = cfx.mk_ca()
    server_key, server_cert = cfx.mk_server_cert(ca_key, ca_cert)
    server_key_path, server_cert_path = cfx.write_pair(server_key, server_cert)
    return {
        "server_cert_path": server_cert_path,
        "server_key_path": server_key_path,
        # Client CA for mTLS validation is the REAL agent CA from Vault.
        "client_ca_path": vault_signed_agent["agent_ca_path"],
    }


# ---------------------------------------------------------------------------
# Live identity validator (uses the test's db session so committed data
# is visible to the broker handler in the same connection)
# ---------------------------------------------------------------------------


def _live_identity_validator(db):
    """Build a validator that mirrors handlers.make_db_validator but
    reads from the test's session instead of opening its own (the test
    db fixture wraps everything in a SAVEPOINT a fresh session would
    not see)."""
    from app.db.models import System

    def _validator(identity: PeerIdentity):
        system = db.query(System).filter(System.id == identity.system_id).first()
        if system is None:
            raise BrokerRejection(
                REJECT_NOT_ACTIVE, f"system {identity.system_id} not found"
            )
        if system.agent_status != "active":
            raise BrokerRejection(
                REJECT_NOT_ACTIVE, f"agent_status={system.agent_status}"
            )
        if normalize_serial(system.agent_cert_serial) != identity.serial_hex:
            raise BrokerRejection(REJECT_SERIAL_MISMATCH, "")
        if system.agent_cert_fingerprint != identity.fingerprint_sha256:
            raise BrokerRejection(REJECT_FINGERPRINT_MISMATCH, "")
        return {"system_id": system.id, "hostname": system.hostname}

    return _validator


@asynccontextmanager
async def _broker(broker_server_cert, port, *, registry, manager, validator):
    async def dispatch(ws):
        if ws.path == "/agent/tunnel":
            await tunnel_handler(
                ws,
                identity_validator=validator,
                registry=registry,
                manager=manager,
                heartbeat_interval_seconds=0.2,
                heartbeat_dead_seconds=10.0,
            )
        elif ws.path == "/agent/op":
            await op_handler(
                ws,
                identity_validator=validator,
                registry=registry,
                manager=manager,
            )
        else:
            await ws.close(code=4404, reason="unknown_path")

    ssl_ctx = build_server_ssl_context(
        server_certfile=broker_server_cert["server_cert_path"],
        server_keyfile=broker_server_cert["server_key_path"],
        client_ca_certfile=broker_server_cert["client_ca_path"],
    )
    server = await websockets.serve(
        dispatch,
        host="127.0.0.1",
        port=port,
        ssl=ssl_ctx,
        ping_interval=None,
        max_size=2 << 20,
    )
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


def _hello_payload(client_cert_path):
    with open(client_cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(
            f.read().split(b"-----END CERTIFICATE-----")[0]
            + b"-----END CERTIFICATE-----"
        )
    fp = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest()
    return {
        "type": "hello",
        "protocol_version": 1,
        "agent_version": "harness-0.1",
        "capabilities": ["exec", "facts", "heartbeat"],
        "cert_fingerprint": "sha256:" + fp,
    }


# ---------------------------------------------------------------------------
# THE TEST
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_end_to_end_with_real_vault_and_db(
    db, vault_signed_agent, broker_server_cert, unused_tcp_port
):
    """Full pipeline:

    1.  Real Vault signs an agent CSR (PRA-150 path).
    2.  System row in the live test DB carries the matching serial +
        fingerprint + status='active'.
    3.  Broker validates the cert chain against the real Vault agent CA
        and the live DB validator confirms identity.
    4.  Fake agent connects /agent/tunnel, sends hello, gets welcome,
        exchanges a heartbeat.
    5.  Backend creates an op via OperationManager; agent receives
        op_request + op_nonce on the tunnel.
    6.  Agent dials /agent/op with the nonce header, sends op_attach,
        round-trips one frame in each direction.
    7.  Agent sends op_complete on the tunnel; op terminalises COMPLETED.
    8.  Agent disconnects; registry cleans up.
    """
    registry = AgentRegistry()
    manager = OperationManager(registry, nonce_ttl_seconds=15.0)
    validator = _live_identity_validator(db)

    sys_id = vault_signed_agent["system_id"]
    client_key = vault_signed_agent["client_key_path"]
    client_cert = vault_signed_agent["client_cert_path"]
    agent_ca = vault_signed_agent["agent_ca_path"]

    async with _broker(
        broker_server_cert,
        unused_tcp_port,
        registry=registry,
        manager=manager,
        validator=validator,
    ):
        # ---------- step 4: tunnel up ----------
        ctx = cfx.client_ssl_ctx(client_key, client_cert, agent_ca)
        tunnel_ws = await websockets.connect(
            f"wss://127.0.0.1:{unused_tcp_port}/agent/tunnel", ssl=ctx
        )
        try:
            hello = _hello_payload(client_cert)
            await tunnel_ws.send(json.dumps(hello))
            welcome = json.loads(await tunnel_ws.recv())
            assert welcome["type"] == "welcome"
            assert welcome["system_id"] == sys_id
            assert welcome["cert_fingerprint"] == (
                "sha256:" + vault_signed_agent["fingerprint"]
            )
            assert welcome["accepted_capabilities"] == [
                "exec",
                "facts",
                "heartbeat",
            ]

            # Wait for the broker's first heartbeat to confirm the
            # liveness loop is actually running.
            for _ in range(50):
                msg = json.loads(await tunnel_ws.recv())
                if msg.get("type") == "heartbeat":
                    break
            else:
                pytest.fail("did not receive a broker heartbeat")

            # Agent sends its own heartbeat back.
            await tunnel_ws.send(
                json.dumps(
                    {
                        "type": "heartbeat",
                        "ts": dt.datetime.utcnow().isoformat() + "Z",
                    }
                )
            )

            assert registry.get(sys_id) is not None

            # ---------- step 5: backend creates an op ----------
            op, _ = await manager.create_and_dispatch(
                sys_id, "exec", {"cmd": "uname -a"}
            )
            # Drain any leading heartbeats the broker may have emitted
            # while we were setting up; we want the next op_request +
            # op_nonce.
            messages = []
            while len(messages) < 2:
                msg = json.loads(await asyncio.wait_for(tunnel_ws.recv(), timeout=2.0))
                if msg.get("type") in ("op_request", "op_nonce"):
                    messages.append(msg)
            req = next(m for m in messages if m["type"] == "op_request")
            nonce_msg = next(m for m in messages if m["type"] == "op_nonce")
            assert req["operation_id"] == op.operation_id
            assert nonce_msg["operation_id"] == op.operation_id
            nonce = nonce_msg["nonce"]

            # ---------- step 6: per-op WSS round trip ----------
            op_ws = await websockets.connect(
                f"wss://127.0.0.1:{unused_tcp_port}/agent/op",
                ssl=ctx,
                extra_headers=[("X-Praxis-Op-Nonce", nonce)],
            )
            try:
                await op_ws.send(
                    json.dumps({"type": "op_attach", "operation_id": op.operation_id})
                )
                # Backend writes a stdin frame.
                await op.outbound.put(
                    Frame(
                        op=FrameOp.DATA,
                        channel=Channel.STDIN,
                        payload=b"hello-from-backend",
                    )
                )
                wire = await asyncio.wait_for(op_ws.recv(), timeout=2.0)
                inbound = decode_frame(wire)
                assert inbound.channel == Channel.STDIN
                assert inbound.payload == b"hello-from-backend"

                # Agent writes a stdout frame.
                await op_ws.send(
                    encode_frame(
                        Frame(
                            op=FrameOp.DATA,
                            channel=Channel.STDOUT,
                            payload=b"hello-from-agent",
                        )
                    )
                )
                from_agent = await asyncio.wait_for(op.inbound.get(), timeout=2.0)
                assert isinstance(from_agent, Frame)
                assert from_agent.channel == Channel.STDOUT
                assert from_agent.payload == b"hello-from-agent"
            finally:
                if not op_ws.closed:
                    await op_ws.close()

            # ---------- step 7: agent finalises ----------
            await tunnel_ws.send(
                json.dumps(
                    {
                        "type": "op_complete",
                        "operation_id": op.operation_id,
                        "outcome": "success",
                    }
                )
            )
            outcome, _err = await asyncio.wait_for(op.completion, timeout=2.0)
            assert outcome == "success"
            assert op.state == OperationState.COMPLETED
        finally:
            with contextlib.suppress(Exception):
                await tunnel_ws.close()

        # ---------- step 8: cleanup ----------
        for _ in range(20):
            await asyncio.sleep(0.05)
            if registry.get(sys_id) is None:
                break
        assert registry.get(sys_id) is None
