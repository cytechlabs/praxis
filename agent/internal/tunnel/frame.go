// Per-op WSS frame envelope (PRA-151 task #16). Wire layout matches
// the broker side (app/broker/protocol.py) byte-for-byte:
//
//	| u8 protocol_version | u8 op | u8 channel | u8 flags | u32 length | payload |
//
// All multibyte fields are big-endian. Constants and limits match
// the broker so a malformed frame is rejected at the same boundary
// on both sides.

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameOp values — keep in sync with FrameOp in app/broker/protocol.py.
type FrameOp uint8

const (
	FrameOpData      FrameOp = 0x01 // streaming chunk on a channel
	FrameOpClose     FrameOp = 0x02 // clean end of channel (or whole op for control)
	FrameOpError     FrameOp = 0x03 // abnormal end; payload is JSON {code, detail}
	FrameOpCancelAck FrameOp = 0x04 // acks a control-WSS op_cancel
)

// Channel values — keep in sync with Channel in app/broker/protocol.py.
type Channel uint8

const (
	ChannelStdin   Channel = 0x01 // backend -> agent
	ChannelStdout  Channel = 0x02 // agent -> backend
	ChannelStderr  Channel = 0x03 // agent -> backend
	ChannelPty     Channel = 0x04 // bidirectional (raw PTY bytes)
	ChannelFile    Channel = 0x05 // direction depends on op
	ChannelControl Channel = 0x06 // op-specific control JSON (e.g. PTY resize)
)

const (
	frameProtocolVersion uint8 = 1

	// FrameHeaderSize is the fixed-size prefix on every frame.
	FrameHeaderSize = 8

	// DefaultMaxFramePayload mirrors the 1 MiB cap broker enforces.
	DefaultMaxFramePayload = 1 << 20
)

// Frame is one decoded per-op WSS frame.
type Frame struct {
	Op      FrameOp
	Channel Channel
	Flags   uint8
	Payload []byte
}

// EncodeFrame serialises “f“ to the wire format. Returns an error
// (rather than truncating) when payload exceeds “maxPayload“ so
// programmer mistakes surface here instead of being rejected on the
// recv side.
func EncodeFrame(f Frame, maxPayload int) ([]byte, error) {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxFramePayload
	}
	if len(f.Payload) > maxPayload {
		return nil, fmt.Errorf("frame: payload %d bytes exceeds max %d", len(f.Payload), maxPayload)
	}
	if !validOp(f.Op) {
		return nil, fmt.Errorf("frame: unknown op 0x%02x", uint8(f.Op))
	}
	if !validChannel(f.Channel) {
		return nil, fmt.Errorf("frame: unknown channel 0x%02x", uint8(f.Channel))
	}
	out := make([]byte, FrameHeaderSize+len(f.Payload))
	out[0] = frameProtocolVersion
	out[1] = uint8(f.Op)
	out[2] = uint8(f.Channel)
	out[3] = f.Flags
	binary.BigEndian.PutUint32(out[4:8], uint32(len(f.Payload)))
	copy(out[FrameHeaderSize:], f.Payload)
	return out, nil
}

// DecodeFrame parses one complete frame from “buf“. Caller is
// responsible for chunking — websockets framing already gives us one
// message per Read, so a single frame per call is the common path.
//
// Returns an error for any structural or limit violation. The agent
// surfaces these as “op_complete(error, reason="bad_frame")“ so the
// broker stops waiting on the op.
func DecodeFrame(buf []byte, maxPayload int) (Frame, error) {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxFramePayload
	}
	if len(buf) < FrameHeaderSize {
		return Frame{}, fmt.Errorf("frame: %d bytes shorter than %d-byte header",
			len(buf), FrameHeaderSize)
	}
	version := buf[0]
	if version != frameProtocolVersion {
		return Frame{}, fmt.Errorf("frame: unsupported version %d", version)
	}
	op := FrameOp(buf[1])
	if !validOp(op) {
		return Frame{}, fmt.Errorf("frame: unknown op 0x%02x", uint8(op))
	}
	ch := Channel(buf[2])
	if !validChannel(ch) {
		return Frame{}, fmt.Errorf("frame: unknown channel 0x%02x", uint8(ch))
	}
	flags := buf[3]
	length := binary.BigEndian.Uint32(buf[4:8])
	if int(length) > maxPayload {
		return Frame{}, fmt.Errorf("frame: declared length %d exceeds max %d",
			length, maxPayload)
	}
	if int(length) != len(buf)-FrameHeaderSize {
		return Frame{}, fmt.Errorf(
			"frame: declared length %d does not match remaining buffer %d",
			length, len(buf)-FrameHeaderSize,
		)
	}
	payload := make([]byte, length)
	copy(payload, buf[FrameHeaderSize:])
	return Frame{Op: op, Channel: ch, Flags: flags, Payload: payload}, nil
}

func validOp(op FrameOp) bool {
	switch op {
	case FrameOpData, FrameOpClose, FrameOpError, FrameOpCancelAck:
		return true
	}
	return false
}

func validChannel(ch Channel) bool {
	switch ch {
	case ChannelStdin, ChannelStdout, ChannelStderr,
		ChannelPty, ChannelFile, ChannelControl:
		return true
	}
	return false
}

// ErrEmptyBuf is reserved for future zero-length frame surfaces; not
// returned today but documented so callers don't silently swallow a
// future change.
var ErrEmptyBuf = errors.New("frame: empty buffer")
