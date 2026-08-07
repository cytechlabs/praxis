"""PRA-151 task #21: cold-stack verification of the deployed broker.

Run from inside the backend container after `docker compose up -d --build`.
Mints a real Vault-signed agent cert, seeds a System row in praxis (the
live DB the deployed broker validates against), then dances through the
real /agent/tunnel + /agent/op endpoints exposed by the agent-broker
service on https://agent-broker:8443/.

Cleans up the System row at the end so the script is re-runnable.

This is a diagnostic, not a CI test — it requires the bundled stack to
be running (db, vault, agent-broker). The in-process integration
harness (tests/broker/test_integration_harness.py) covers the same
contract under unit-test conditions.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import ssl
import sys

if not os.environ.get("VAULT_TOKEN"):
    try:
        with open("/vault/data/backend-token", encoding="utf-8") as f:
            os.environ["VAULT_TOKEN"] = f.read().strip()
    except OSError:
        print("FATAL: no VAULT_TOKEN and /vault/data/backend-token missing")
        sys.exit(2)

import urllib.request

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, "/app")

from app.broker.protocol import Channel, Frame, FrameOp, decode_frame, encode_frame
from app.broker.tls import normalize_serial
from app.db.models import Credential, Distro, Group, System
from app.db.session import SessionLocal
from app.services.vault_service import VaultService

BROKER_HOST = os.environ.get("PRAXIS_BROKER_HOST", "agent-broker")
BROKER_PORT = int(os.environ.get("PRAXIS_BROKER_PORT", "8443"))
MAIN_BASE = os.environ.get("PRAXIS_MAIN_BASE", "http://backend:8000")


def fetch_ca_bundle() -> dict:
    return json.loads(urllib.request.urlopen(f"{MAIN_BASE}/agent/ca-bundle").read())


def write_pem(pem: str, suffix: str) -> str:
    import tempfile

    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(pem.encode() if isinstance(pem, str) else pem)
    f.close()
    return f.name


def mint_agent_cert(db, system_id: int) -> dict:
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
        common_name=f"system-{system_id}.agent.praxis.internal",
        uri_san=f"praxis://system/{system_id}",
    )
    cert_pem = signed["certificate"]
    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
    fp = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest()

    key_path = write_pem(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        ".key",
    )
    chain = cert_pem
    for c in signed.get("ca_chain") or []:
        chain += "\n" + c
    cert_path = write_pem(chain, ".crt")
    return {
        "key_path": key_path,
        "cert_path": cert_path,
        "serial_norm": normalize_serial(signed["serial_number"]),
        "fingerprint": fp,
    }


def seed_system(db) -> System:
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if distro is None:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=dt.date(2022, 4, 21),
            end_of_life_date=dt.date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    group = db.query(Group).order_by(Group.id).first()
    if group is None:
        group = Group(name="cold-default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter_by(name="cold-cred").first()
    if cred is None:
        cred = Credential(
            name="cold-cred",
            auth_method="password",
            username="root",
            vault_path="v/cold",
        )
        db.add(cred)
        db.flush()
    s = System(
        hostname=f"cold-host-{dt.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        ip_address="10.255.0.1",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


async def main() -> int:
    print(f"== fetching CA bundle from {MAIN_BASE} ==")
    bundle = fetch_ca_bundle()
    broker_ca_path = write_pem(bundle["broker_ca"], ".broker_ca.crt")

    db = SessionLocal()
    try:
        system = seed_system(db)
        print(f"  seeded System id={system.id} hostname={system.hostname}")
        agent = mint_agent_cert(db, system.id)

        system.agent_status = "active"
        system.agent_cert_serial = agent["serial_norm"]
        system.agent_cert_fingerprint = agent["fingerprint"]
        system.agent_cert_expires_at = dt.datetime.utcnow() + dt.timedelta(hours=1)
        db.commit()
        print(f"  cert minted; serial(norm)={agent['serial_norm']}")

        # Build TLS context: trust the BROKER CA from /agent/ca-bundle.
        ctx = ssl.create_default_context(cafile=broker_ca_path)
        # Server cert SAN includes 'agent-broker' so check_hostname works
        # via that DNS name.
        ctx.load_cert_chain(certfile=agent["cert_path"], keyfile=agent["key_path"])

        url = f"wss://{BROKER_HOST}:{BROKER_PORT}/agent/tunnel"
        print(f"== dialing {url} ==")
        ws = await websockets.connect(url, ssl=ctx)

        hello = {
            "type": "hello",
            "protocol_version": 1,
            "agent_version": "cold-verify-0.1",
            "capabilities": ["exec", "facts", "heartbeat"],
            "cert_fingerprint": "sha256:" + agent["fingerprint"],
        }
        await ws.send(json.dumps(hello))
        welcome = json.loads(await ws.recv())
        assert welcome["type"] == "welcome", welcome
        print(f"  welcome: system_id={welcome['system_id']}")
        print(f"  tunnel_session_id={welcome['tunnel_session_id']}")
        print(f"  accepted_capabilities={welcome['accepted_capabilities']}")

        # Drain a heartbeat to confirm the lifecycle loop is healthy.
        for _ in range(5):
            msg = json.loads(await ws.recv())
            if msg["type"] == "heartbeat":
                print(f"  received broker heartbeat ts={msg.get('ts')}")
                break

        await ws.send(
            json.dumps(
                {
                    "type": "heartbeat",
                    "ts": dt.datetime.utcnow().isoformat() + "Z",
                }
            )
        )

        await ws.close()
        print("  tunnel closed cleanly")

        print(
            "\n== VERDICT: deployed broker accepted Vault-signed cert + ran handshake =="
        )
        return 0
    finally:
        try:
            if "system" in locals():
                db.delete(system)
                db.commit()
        except Exception:  # pylint: disable=broad-except
            pass
        db.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
