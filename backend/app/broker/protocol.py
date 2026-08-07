"""PRA-151 wire protocol constants + handshake validation.

The full spec lives in ``docs/agent-protocol.md``; this module is the
machine-readable copy of the parts the broker enforces.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Set

# Protocol versions this broker speaks. Bumped when the wire shape
# changes incompatibly. Agents that announce a version not in this set
# are rejected at handshake.
SUPPORTED_PROTOCOL_VERSIONS: Set[int] = {1}

# Capabilities the broker is prepared to accept from agents. Agents may
# advertise extras (forward-compat); we intersect so the agent learns
# the effective set in the welcome reply.
SERVER_CAPABILITIES: List[str] = [
    "exec",
    "pty",
    "file.read",
    "file.write",
    "file.list",
    "file.checksum",
    "facts",
    "heartbeat",
]

# Heartbeat / liveness defaults (broker advertises these to the agent in
# the welcome reply; agent honors them on its end).
HEARTBEAT_INTERVAL_SECONDS = 30
HEARTBEAT_DEAD_SECONDS = 90

# Sane caps on the control WSS message size + max in-flight ops. The
# control socket carries JSON only; per-op streams have their own limits
# (PRA-151 task #16).
CONTROL_WSS_MAX_MESSAGE_BYTES = 64 * 1024


class HandshakeError(Exception):
    """Raised when the agent's hello is malformed or unacceptable."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# Reject reason codes carried in close frames + audit events.
HANDSHAKE_NOT_JSON = "handshake_not_json"
HANDSHAKE_BAD_TYPE = "handshake_bad_type"
HANDSHAKE_MISSING_FIELD = "handshake_missing_field"
HANDSHAKE_UNSUPPORTED_VERSION = "handshake_unsupported_version"
HANDSHAKE_FINGERPRINT_MISMATCH = "handshake_fingerprint_mismatch"
HANDSHAKE_BAD_CAPABILITIES = "handshake_bad_capabilities"

REQUIRED_HELLO_FIELDS = (
    "type",
    "protocol_version",
    "agent_version",
    "capabilities",
    "cert_fingerprint",
)


def parse_hello(raw_message: Any, *, expected_fingerprint: str) -> Dict[str, Any]:
    """Validate the agent's first message.

    Returns a dict with the validated and normalized fields, ready to
    feed into the welcome builder. Raises ``HandshakeError`` for any
    malformed or unacceptable input.

    ``expected_fingerprint`` is the bare-hex SHA-256 of the cert
    presented at TLS layer. The agent's self-reported
    ``cert_fingerprint`` arrives in wire format (``sha256:<hex>`` per
    docs/agent-protocol.md) and must equal the expected value once the
    prefix is stripped (defense-in-depth against any layer mismatch).
    """
    import json  # local import keeps protocol.py free of side-effect-heavy deps

    from .tls import parse_fingerprint_from_wire  # avoid import cycle at module load

    if not isinstance(raw_message, (str, bytes, bytearray)):
        raise HandshakeError(
            HANDSHAKE_NOT_JSON, f"unexpected message kind {type(raw_message).__name__}"
        )

    try:
        msg = json.loads(raw_message)
    except (ValueError, TypeError) as e:
        raise HandshakeError(HANDSHAKE_NOT_JSON, str(e)) from e

    if not isinstance(msg, dict):
        raise HandshakeError(
            HANDSHAKE_NOT_JSON, "top-level value must be a JSON object"
        )

    for field in REQUIRED_HELLO_FIELDS:
        if field not in msg:
            raise HandshakeError(HANDSHAKE_MISSING_FIELD, field)

    if msg["type"] != "hello":
        raise HandshakeError(HANDSHAKE_BAD_TYPE, repr(msg["type"]))

    version = msg["protocol_version"]
    if not isinstance(version, int) or version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise HandshakeError(HANDSHAKE_UNSUPPORTED_VERSION, repr(version))

    try:
        agent_fp = parse_fingerprint_from_wire(msg["cert_fingerprint"])
    except ValueError as e:
        raise HandshakeError(HANDSHAKE_FINGERPRINT_MISMATCH, str(e)) from e
    if agent_fp != expected_fingerprint:
        # Don't echo either fingerprint in the close reason; it's an
        # internal-only detail.
        raise HandshakeError(HANDSHAKE_FINGERPRINT_MISMATCH, "")

    capabilities = msg["capabilities"]
    if not isinstance(capabilities, list) or not all(
        isinstance(c, str) for c in capabilities
    ):
        raise HandshakeError(HANDSHAKE_BAD_CAPABILITIES, "must be list of strings")

    agent_version = msg["agent_version"]
    if not isinstance(agent_version, str) or not agent_version:
        raise HandshakeError(HANDSHAKE_MISSING_FIELD, "agent_version must be a string")

    return {
        "protocol_version": version,
        "agent_version": agent_version,
        "capabilities": list(capabilities),
        "cert_fingerprint": agent_fp,  # bare hex, matching internal format
    }


# ---------------------------------------------------------------------------
# Per-op WSS frame envelope (PRA-151 task #16)
# ---------------------------------------------------------------------------

# Wire layout: u8 version | u8 op | u8 channel | u8 flags | u32 length | payload
FRAME_HEADER_FORMAT = ">BBBBI"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FORMAT)  # 8 bytes
DEFAULT_MAX_FRAME_PAYLOAD_BYTES = 1 << 20  # 1 MiB per spec


class FrameOp(IntEnum):
    DATA = 0x01
    CLOSE = 0x02
    ERROR = 0x03
    CANCEL_ACK = 0x04


class Channel(IntEnum):
    STDIN = 0x01
    STDOUT = 0x02
    STDERR = 0x03
    PTY = 0x04
    FILE = 0x05
    CONTROL = 0x06


class FrameError(Exception):
    """Raised when a frame fails to encode or decode against the spec."""


@dataclass(frozen=True)
class Frame:
    """One per-op WSS frame. Payload is opaque bytes; channel + op tell
    the consumer how to interpret it (e.g. ``CONTROL`` carries JSON,
    ``STDOUT`` carries raw exec output, ``PTY`` carries terminal bytes)."""

    op: FrameOp
    channel: Channel
    payload: bytes
    flags: int = 0


def encode_frame(
    frame: Frame, *, max_payload: int = DEFAULT_MAX_FRAME_PAYLOAD_BYTES
) -> bytes:
    """Serialise ``frame`` to the wire format. Refuses to emit oversize
    payloads — better to surface programmer errors here than blow past
    the limit on the recv side."""
    if not isinstance(frame.payload, (bytes, bytearray, memoryview)):
        raise FrameError(
            f"payload must be bytes-like, got {type(frame.payload).__name__}"
        )
    payload = bytes(frame.payload)
    if len(payload) > max_payload:
        raise FrameError(f"payload {len(payload)} bytes exceeds max {max_payload}")
    if not 0 <= int(frame.flags) <= 0xFF:
        raise FrameError(f"flags must fit in u8, got {frame.flags}")
    header = struct.pack(
        FRAME_HEADER_FORMAT,
        1,  # protocol_version
        int(frame.op),
        int(frame.channel),
        int(frame.flags),
        len(payload),
    )
    return header + payload


def decode_frame(
    buf: bytes, *, max_payload: int = DEFAULT_MAX_FRAME_PAYLOAD_BYTES
) -> Frame:
    """Parse one frame from ``buf``. The whole buffer is assumed to be
    one complete frame (websockets framing already chunks for us)."""
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise FrameError(f"buffer must be bytes-like, got {type(buf).__name__}")
    if len(buf) < FRAME_HEADER_SIZE:
        raise FrameError(
            f"buffer {len(buf)} bytes shorter than {FRAME_HEADER_SIZE}-byte header"
        )
    version, op_byte, channel_byte, flags, length = struct.unpack(
        FRAME_HEADER_FORMAT, bytes(buf[:FRAME_HEADER_SIZE])
    )
    if version != 1:
        raise FrameError(f"unsupported frame version {version}")
    if length > max_payload:
        raise FrameError(f"declared length {length} exceeds max {max_payload}")
    if len(buf) - FRAME_HEADER_SIZE != length:
        raise FrameError(
            f"declared length {length} does not match remaining buffer "
            f"{len(buf) - FRAME_HEADER_SIZE}"
        )
    try:
        op = FrameOp(op_byte)
    except ValueError as e:
        raise FrameError(f"unknown frame op 0x{op_byte:02x}") from e
    try:
        channel = Channel(channel_byte)
    except ValueError as e:
        raise FrameError(f"unknown channel 0x{channel_byte:02x}") from e
    payload = bytes(buf[FRAME_HEADER_SIZE:])
    return Frame(op=op, channel=channel, payload=payload, flags=flags)


def negotiate_capabilities(agent_caps: List[str]) -> List[str]:
    """Return the set of capabilities both sides agree on, in a stable order.

    Unknown agent-advertised capabilities are dropped silently
    (forward-compat). The broker rejects a request for a capability not
    in this intersection at op_request time, not at handshake time.
    """
    server = set(SERVER_CAPABILITIES)
    accepted = [cap for cap in SERVER_CAPABILITIES if cap in server & set(agent_caps)]
    return accepted
