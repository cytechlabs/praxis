"""Peer mTLS cert extraction + parsing for the agent broker.

Wire/storage format conventions (kept consistent across PRA-150 and PRA-151):

* **Cert serial** is canonicalised to **bare lowercase hex** for storage
  and comparison. Vault returns serials in ``aa:bb:cc`` form; PRA-150
  currently stores that form on ``System.agent_cert_serial``. The
  ``normalize_serial`` helper here strips colons and lowercases so both
  sides compare equal regardless of which side wrote first.
* **Cert SHA-256 fingerprint** is stored internally as bare lowercase
  hex (matching ``hashlib.sha256(der).hexdigest()``). The wire format,
  per ``docs/agent-protocol.md``, prefixes it with ``sha256:`` —
  ``format_fingerprint_for_wire`` / ``parse_fingerprint_from_wire``
  bridge the two.


Uvicorn 0.27 does not surface peer certs in ASGI scope (see
spike_peer_cert_uvicorn.py). The broker uses ``websockets.serve`` +
``asyncio.start_server`` + explicit ``ssl.SSLContext`` instead, which
gives us direct access to the underlying ``SSLSocket``.

Identity model (PRA-150 + PRA-151):
- Real identity is the ``URI SAN`` ``praxis://system/<id>``.
- CN is informational and backend-controlled
  (``system-<id>.agent.praxis.internal``); CSR-supplied CN is discarded
  by Vault.
- Cert serial + SHA-256 fingerprint are recorded on ``System`` at
  bootstrap/renew time and are the tunnel-admission gate.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# URI SAN format: praxis://system/<positive int>
SYSTEM_URI_RE = re.compile(r"^praxis://system/(\d+)$")


FINGERPRINT_WIRE_PREFIX = "sha256:"


def normalize_serial(serial: Optional[str]) -> Optional[str]:
    """Reduce a cert serial to canonical bare lowercase hex with no
    leading-zero padding.

    Accepts Vault-style ``aa:bb:cc:...``, bare hex (any case), or already
    canonical form. Returns ``None`` when input is falsy so callers can
    compare nullable DB columns directly.

    Why the int round-trip: ``format(cert.serial_number, "x")`` from
    cryptography drops leading zero nibbles. A Vault serial of e.g.
    ``0a:bc`` would normalise to ``0abc`` under naive colon-stripping
    but the same cert's parsed integer formats as ``abc``, causing a
    spurious ``serial_mismatch``. Canonicalising via ``int(.., 16)`` on
    both sides puts everyone in the same shape.
    """
    if not serial:
        return None
    cleaned = serial.replace(":", "").lower()
    if not cleaned:
        return None
    try:
        return format(int(cleaned, 16), "x")
    except ValueError:
        # Not valid hex — return the stripped form so the caller's
        # eventual comparison fails loudly instead of silently passing.
        return cleaned


def format_fingerprint_for_wire(bare_hex: str) -> str:
    """Add the ``sha256:`` prefix expected on the wire (per agent-protocol.md)."""
    return FINGERPRINT_WIRE_PREFIX + bare_hex


def parse_fingerprint_from_wire(wire_value: str) -> str:
    """Strip the ``sha256:`` prefix and lowercase. Raises ValueError on
    malformed input — callers translate this into a handshake reject."""
    if not isinstance(wire_value, str):
        raise ValueError(f"fingerprint must be string, got {type(wire_value).__name__}")
    if not wire_value.startswith(FINGERPRINT_WIRE_PREFIX):
        raise ValueError(
            f"fingerprint missing required {FINGERPRINT_WIRE_PREFIX!r} prefix"
        )
    bare = wire_value[len(FINGERPRINT_WIRE_PREFIX) :].lower()
    # SHA-256 hex is exactly 64 chars; bail loudly on anything else.
    if len(bare) != 64 or any(c not in "0123456789abcdef" for c in bare):
        raise ValueError("fingerprint after prefix is not 64-char hex")
    return bare


class PeerCertError(Exception):
    """Raised when the presented client cert fails extraction or parsing."""


@dataclass(frozen=True)
class PeerIdentity:
    """Validated, parsed identity from an agent's mTLS cert.

    The fields here are derived from the cert only. Whether the system_id
    is currently allowed to connect (status, expiry, revocation) is the
    caller's job — typically via ``AgentIdentityService.is_serial_active``.
    """

    system_id: int
    serial_hex: str
    fingerprint_sha256: str
    not_after: datetime  # naive UTC
    subject_cn: Optional[str]


def extract_peer_identity(ssl_object: ssl.SSLObject) -> PeerIdentity:
    """Parse the peer cert from an established SSL session.

    ``ssl_object`` is what
    ``ws.transport.get_extra_info("ssl_object")`` returns. It exposes the
    peer cert as DER bytes via ``getpeercert(binary_form=True)``.

    Raises ``PeerCertError`` for any structural problem: no cert, missing
    URI SAN, bad URI format, malformed cert, etc. Status / expiry checks
    are NOT done here — see callers.
    """
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        raise PeerCertError("no peer cert presented")

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as e:
        raise PeerCertError(f"cert is not valid DER: {e}") from e

    # Serial as canonical lowercase hex (no leading zeros, no colons),
    # matching what normalize_serial() produces for the DB side.
    serial_hex = normalize_serial(format(cert.serial_number, "x"))

    # SHA-256 fingerprint of the DER cert.
    fingerprint = hashlib.sha256(der).hexdigest()

    # NotAfter as naive UTC datetime.
    raw_not_after = cert.not_valid_after_utc  # cryptography >= 42 returns aware
    if raw_not_after.tzinfo is not None:
        not_after = raw_not_after.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        not_after = raw_not_after

    # CN is informational only.
    subject_cn: Optional[str] = None
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            subject_cn = attr.value
            break

    # The real identity is the URI SAN. Reject if absent or malformed.
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as e:
        raise PeerCertError("cert has no SubjectAlternativeName") from e

    uris = san_ext.get_values_for_type(x509.UniformResourceIdentifier)
    if not uris:
        raise PeerCertError("cert SAN has no URI entries")

    system_id = _parse_system_uri(uris)
    if system_id is None:
        raise PeerCertError(
            f"cert SAN URIs do not include a praxis://system/<id>: {uris!r}"
        )

    return PeerIdentity(
        system_id=system_id,
        serial_hex=serial_hex,
        fingerprint_sha256=fingerprint,
        not_after=not_after,
        subject_cn=subject_cn,
    )


def _parse_system_uri(uris: list[str]) -> Optional[int]:
    """Find the first praxis://system/<int> URI in the SAN, return the id."""
    for uri in uris:
        m = SYSTEM_URI_RE.match(uri)
        if m:
            return int(m.group(1))
    return None


def build_server_ssl_context(
    server_certfile: str,
    server_keyfile: str,
    client_ca_certfile: str,
) -> ssl.SSLContext:
    """Build the SSL context for the broker's mTLS listener.

    - Server presents ``server_certfile`` / ``server_keyfile`` to clients.
    - Client must present a cert chained to ``client_ca_certfile``
      (the praxis-agent-ca root).
    - TLS 1.2+ only, default secure ciphers.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=server_certfile, keyfile=server_keyfile)
    ctx.load_verify_locations(cafile=client_ca_certfile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    # PRA-320: ``create_default_context`` enables ``VERIFY_X509_STRICT`` by default as
    # of Python 3.13. On Python 3.14 that strict RFC-5280 check breaks asyncio's
    # server-side client-certificate (mTLS) handshake entirely — the TLS handshake
    # fails before the WebSocket handler ever runs, so every agent tunnel is rejected.
    # This is the actual root cause of the PRA-319 "did not receive a valid HTTP
    # response" broker failure on 3.14; it is NOT a ``websockets.legacy`` problem — it
    # reproduces identically on ``websockets.asyncio`` and on a bare
    # ``asyncio.start_server`` with no websockets at all. Clearing the flag restores
    # a working mTLS handshake on 3.14.
    #
    # This does NOT weaken the shipping 1.0 posture: Python 3.11 (the accepted 1.0
    # runtime) never set ``VERIFY_X509_STRICT`` in ``create_default_context`` (that
    # default landed in 3.13), so the broker already runs without it today — this only
    # makes the behavior explicit and version-independent. The fail-closed mTLS
    # guarantees are unchanged: a client cert is still REQUIRED (``CERT_REQUIRED``) and
    # must chain to the agent CA (``load_verify_locations``), TLS is 1.2+, and
    # ``create_default_context``'s cipher/option hardening is retained.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx
