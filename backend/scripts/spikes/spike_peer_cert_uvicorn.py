"""DIAGNOSTIC: does the installed Uvicorn surface the mTLS peer cert in
ASGI scope so route handlers can read SAN URI / serial / fingerprint /
NotAfter?

History: Run during PRA-151 task #22 against Uvicorn 0.27.0 — RESULT FAIL.
The TLS layer enforced CERT_REQUIRED (handshake validated against
praxis-agent-ca), but both HTTP and WebSocket scopes had `peer_cert: null`
and no `tls` extension. The PRA-151 broker therefore uses `websockets`
lib + `asyncio.start_server` + explicit `ssl.SSLContext` instead.

Keep this script for future re-verification when Uvicorn versions bump
(there is ongoing upstream PR discussion about exposing peer certs to
ASGI scope). To re-run after a uvicorn upgrade:

    docker compose exec -T backend python /app/scripts/spikes/spike_peer_cert_uvicorn.py

Decision rule for re-run:
    SUCCESS = HTTP and/or WebSocket route can access the presented
              client cert and parse all four fields. We could then
              consider migrating the broker back to FastAPI/Uvicorn.
    FAIL    = current pivot stands.

Prints metadata only — no private keys, no full certs, no raw tokens.
Needs VAULT_TOKEN (script auto-reads /vault/data/backend-token if env
var unset) and a working praxis-agent-ca mount (PRA-150).
"""

from __future__ import annotations

import os

# Set VAULT_TOKEN BEFORE any app imports trigger module-level Vault init.
if not os.environ.get("VAULT_TOKEN"):
    # Compose sets VAULT_TOKEN= (empty) by default; start.sh overlays it.
    # `docker compose exec` skips start.sh so we re-read the file ourselves.
    try:
        with open("/vault/data/backend-token", encoding="utf-8") as _f:
            os.environ["VAULT_TOKEN"] = _f.read().strip()
    except OSError:
        pass

import asyncio
import datetime as dt
import hashlib
import json
import ssl
import sys
import tempfile
import threading
import time
from typing import Any, Dict, Optional

import httpx
import uvicorn
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

PORT = 18443


# ---------- helpers --------------------------------------------------------


def _self_signed_server_cert(hostname: str = "localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _write_pem(key, cert) -> tuple[str, str]:
    tmp_key = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    tmp_crt = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    tmp_key.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    tmp_crt.write(cert.public_bytes(serialization.Encoding.PEM))
    tmp_key.close()
    tmp_crt.close()
    return tmp_key.name, tmp_crt.name


def _mint_agent_cert_via_vault() -> tuple[str, str, str]:
    """Use the PRA-150 service to mint a real agent cert. Returns
    (client_key_pem_path, client_cert_pem_path, agent_ca_path)."""
    sys.path.insert(0, "/app")
    from app.db.session import SessionLocal
    from app.services.vault_service import VaultService

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "placeholder")])
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    db = SessionLocal()
    v = VaultService(db)
    res = v.sign_agent_csr(
        csr_pem=csr_pem,
        common_name="system-1.agent.praxis.internal",
        uri_san="praxis://system/1",
    )
    ca_pem = v.get_agent_ca_bundle()

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
    with open(cert_path, "w") as f:
        f.write(res["certificate"])
        # Append CA chain so client presents a complete chain
        for c in res.get("ca_chain") or []:
            f.write("\n")
            f.write(c)

    ca_path = tempfile.NamedTemporaryFile(delete=False, suffix=".ca").name
    with open(ca_path, "w") as f:
        f.write(ca_pem)

    return key_path, cert_path, ca_path


def _summarize_cert(der_or_pem: bytes) -> Dict[str, Any]:
    try:
        cert = x509.load_der_x509_certificate(der_or_pem)
    except ValueError:
        cert = x509.load_pem_x509_certificate(der_or_pem)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    san_uri = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            san_uri = uris[0]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": cert.subject.rfc4514_string(),
        "serial_hex": format(cert.serial_number, "x"),
        "san_uri": san_uri,
        "fingerprint_prefix": fp[:32],
        "not_after": cert.not_valid_after.isoformat() + "Z",
    }


# ---------- ASGI app -------------------------------------------------------


def _scope_introspection(scope: dict) -> Dict[str, Any]:
    """Extract everything that might carry the peer cert."""
    info: Dict[str, Any] = {
        "type": scope.get("type"),
        "scope_keys": sorted(scope.keys()),
        "extensions_keys": sorted((scope.get("extensions") or {}).keys()),
        "client": scope.get("client"),
        "scheme": scope.get("scheme"),
    }
    # Known TLS extension shape (PEP 3333 / ASGI TLS extension proposal)
    tls_ext = (scope.get("extensions") or {}).get("tls")
    if tls_ext:
        info["tls_extension"] = {k: type(v).__name__ for k, v in tls_ext.items()}
    # Some servers stash transport on scope or in headers
    transport = scope.get("transport")
    if transport is not None:
        info["transport_repr"] = repr(transport)[:120]
    return info


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    elif scope["type"] == "http":
        info = _scope_introspection(scope)
        # Try to find peer cert by every known mechanism
        peer_cert_summary = None
        tls_ext = (scope.get("extensions") or {}).get("tls") or {}
        for field in ("client_cert_chain", "client_cert", "peercert"):
            val = tls_ext.get(field)
            if val:
                try:
                    if isinstance(val, list) and val:
                        peer_cert_summary = _summarize_cert(val[0])
                    else:
                        peer_cert_summary = _summarize_cert(val)
                    info["peer_cert_via"] = f"extensions.tls.{field}"
                    break
                except Exception as e:  # pylint: disable=broad-except
                    info[f"peer_cert_parse_error_{field}"] = str(e)
        info["peer_cert"] = peer_cert_summary
        body = json.dumps(info, default=str).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})
    elif scope["type"] == "websocket":
        # Accept then immediately send introspection then close
        await receive()  # websocket.connect
        await send({"type": "websocket.accept"})
        info = _scope_introspection(scope)
        peer_cert_summary = None
        tls_ext = (scope.get("extensions") or {}).get("tls") or {}
        for field in ("client_cert_chain", "client_cert", "peercert"):
            val = tls_ext.get(field)
            if val:
                try:
                    if isinstance(val, list) and val:
                        peer_cert_summary = _summarize_cert(val[0])
                    else:
                        peer_cert_summary = _summarize_cert(val)
                    info["peer_cert_via"] = f"extensions.tls.{field}"
                    break
                except Exception as e:  # pylint: disable=broad-except
                    info[f"peer_cert_parse_error_{field}"] = str(e)
        info["peer_cert"] = peer_cert_summary
        await send(
            {
                "type": "websocket.send",
                "text": json.dumps(info, default=str),
            }
        )
        await send({"type": "websocket.close", "code": 1000})


# ---------- runner ---------------------------------------------------------


def _run_server(server_key: str, server_crt: str, ca_path: str) -> threading.Thread:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=PORT,
        log_level="warning",
        ssl_keyfile=server_key,
        ssl_certfile=server_crt,
        ssl_ca_certs=ca_path,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    server = uvicorn.Server(config)

    def _serve():
        asyncio.run(server.serve())

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


async def _hit_http(client_key: str, client_crt: str, ca_path: str) -> dict:
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # server cert is self-signed
    ctx.load_cert_chain(certfile=client_crt, keyfile=client_key)
    async with httpx.AsyncClient(verify=ctx) as ac:
        r = await ac.get(f"https://127.0.0.1:{PORT}/")
        return r.json()


async def _hit_ws(client_key: str, client_crt: str, ca_path: str) -> dict:
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=client_crt, keyfile=client_key)
    async with websockets.connect(f"wss://127.0.0.1:{PORT}/", ssl=ctx) as ws:
        msg = await ws.recv()
        return json.loads(msg)


def main():
    print("== minting client cert via PRA-150 ==")
    if "VAULT_TOKEN" not in os.environ:
        # Read backend token if env not set (matches start.sh pattern)
        try:
            with open("/vault/data/backend-token") as f:
                os.environ["VAULT_TOKEN"] = f.read().strip()
        except OSError:
            print("FATAL: no VAULT_TOKEN and /vault/data/backend-token missing")
            sys.exit(2)
    client_key, client_crt, ca_path = _mint_agent_cert_via_vault()
    print(f"  client cert: {_summarize_cert(open(client_crt, 'rb').read())}")

    print("== generating throwaway server cert ==")
    skey, scert = _self_signed_server_cert("localhost")
    server_key, server_crt = _write_pem(skey, scert)

    print("== starting uvicorn with mTLS CERT_REQUIRED ==")
    _run_server(server_key, server_crt, ca_path)
    time.sleep(1.5)  # let uvicorn bind

    print("\n== HTTP GET / ==")
    try:
        info = asyncio.run(_hit_http(client_key, client_crt, ca_path))
        print(json.dumps(info, indent=2))
    except Exception as e:  # pylint: disable=broad-except
        print(f"  HTTP request failed: {e}")

    print("\n== WebSocket / ==")
    try:
        info = asyncio.run(_hit_ws(client_key, client_crt, ca_path))
        print(json.dumps(info, indent=2))
    except Exception as e:  # pylint: disable=broad-except
        print(f"  WS request failed: {e}")

    print("\n== verdict ==")
    print("  SUCCESS = peer_cert.san_uri is 'praxis://system/1' on either path")
    print("  FAIL    = peer_cert is null on both paths -> pivot to websockets lib")


if __name__ == "__main__":
    main()
