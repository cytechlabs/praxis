"""Shared cert + ssl helpers for broker tests. Generates throwaway
self-signed CAs and certs in-memory to avoid hitting real Vault."""

from __future__ import annotations

import datetime as dt
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def mk_ca():
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


def mk_client_cert(ca_key, ca_cert, *, system_id=42, not_after_seconds=3600):
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


def mk_server_cert(ca_key, ca_cert):
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


def write_pair(key, cert):
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


def write_ca(cert):
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".ca.crt")
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.close()
    return f.name


def client_ssl_ctx(client_key_path, client_cert_path, ca_path):
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return ctx
