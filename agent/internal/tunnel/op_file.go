// File primitives (PRA-152 task #5b).
//
// file_get:  agent -> broker. Read a regular file from disk and stream
//            it back over the per-op WSS. One ChannelControl JSON
//            header frame, then ChannelFile Data frames, then a
//            ChannelFile Close frame.
//
// file_put:  broker -> agent. Receive a file from the broker and
//            write it atomically (tempfile -> fsync -> rename) into
//            the target path. One inbound ChannelControl JSON header,
//            then ChannelFile Data frames, then ChannelFile Close.
//
// Sandboxing in #5b is deliberately minimal: agent runs as root, the
// only client is a mTLS-authenticated broker, so we trust broker
// authorisation. We still refuse obvious foot-guns (writes into
// /proc, /sys, /dev, /run) and non-regular files in either direction.

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// opConnWriter serialises Writes on the per-op WSS so concurrent
// senders (exec stdout + stderr, file_get header + data) don't
// violate websocket single-writer semantics.
type opConnWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *opConnWriter) writeFrame(ctx context.Context, f Frame) error {
	wire, err := EncodeFrame(f, DefaultMaxFramePayload)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.Write(ctx, websocket.MessageBinary, wire)
}

// fileChunk caps Data-frame payload for file_get. Same size as exec
// stdout — small enough that a wedged broker shows up as Write
// blocking rather than as runaway memory.
const fileChunk = 32 * 1024

// blockedPutPrefixes are virtual / device trees we never write into.
// Reads from /proc are sometimes useful so file_get is unaffected.
var blockedPutPrefixes = []string{"/proc", "/sys", "/dev", "/run"}

type fileGetParams struct {
	path     string
	maxBytes int64
	rejected string
}

type filePutParams struct {
	path      string
	mode      os.FileMode
	overwrite bool
	maxBytes  int64
	rejected  string
}

type fileHeader struct {
	Type string `json:"type"`
	Size int64  `json:"size"`
	Mode string `json:"mode,omitempty"`
}

// runFileGet reads the requested path off disk and streams it.
// Returns the outcome the caller posts as op_complete.
func (p *opPump) runFileGet(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	fp := parseFileGetParams(raw)
	if fp.rejected != "" {
		return opOutcomeError(fp.rejected)
	}

	info, err := os.Lstat(fp.path)
	if err != nil {
		if os.IsNotExist(err) {
			return opOutcomeError("not_found")
		}
		if os.IsPermission(err) {
			return opOutcomeError("denied")
		}
		return opOutcomeError("read_failed")
	}
	if info.IsDir() {
		return opOutcomeError("is_directory")
	}
	if !info.Mode().IsRegular() {
		// Devices, FIFOs, sockets, symlinks — refuse so a read can't
		// block forever or do something host-weird.
		return opOutcomeError("not_regular")
	}
	size := info.Size()
	if fp.maxBytes > 0 && size > fp.maxBytes {
		return opOutcomeError("too_large")
	}

	f, err := os.Open(fp.path)
	if err != nil {
		if os.IsPermission(err) {
			return opOutcomeError("denied")
		}
		return opOutcomeError("read_failed")
	}
	defer f.Close() //nolint:errcheck

	w := &opConnWriter{conn: conn}

	header := fileHeader{
		Type: "file_header",
		Size: size,
		Mode: fmt.Sprintf("%#o", info.Mode().Perm()),
	}
	headerRaw, _ := json.Marshal(header)
	if err := w.writeFrame(ctx, Frame{
		Op: FrameOpData, Channel: ChannelControl, Payload: headerRaw,
	}); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return opOutcomeCancelled()
		}
		return opOutcomeError("op_stream_closed")
	}

	buf := make([]byte, fileChunk)
	for {
		if ctx.Err() != nil {
			return opOutcomeCancelled()
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			err := w.writeFrame(ctx, Frame{
				Op: FrameOpData, Channel: ChannelFile,
				Payload: append([]byte(nil), buf[:n]...),
			})
			if err != nil {
				if errors.Is(ctx.Err(), context.Canceled) {
					return opOutcomeCancelled()
				}
				return opOutcomeError("op_stream_closed")
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return opOutcomeError("read_failed")
		}
	}
	if err := w.writeFrame(ctx, Frame{Op: FrameOpClose, Channel: ChannelFile}); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return opOutcomeCancelled()
		}
		return opOutcomeError("op_stream_closed")
	}
	// Graceful WSS close so the broker drains buffered frames before
	// runOp's deferred CloseNow rips the underlying TCP. Bounded so a
	// non-responsive broker can't stall us.
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelClose()
	_ = closeWSSGracefully(closeCtx, conn)
	return opOutcomeSuccess()
}

// closeWSSGracefully sends a normal close frame and waits for the
// peer's close ACK, bounded by ctx. Any error is non-fatal — the
// caller still relies on runOp's deferred CloseNow as the backstop.
func closeWSSGracefully(ctx context.Context, conn *websocket.Conn) error {
	done := make(chan error, 1)
	go func() { done <- conn.Close(websocket.StatusNormalClosure, "done") }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runFilePut accepts an inbound ChannelControl header followed by
// ChannelFile Data frames terminated by a Close. Writes atomically
// via tempfile + fsync + rename in the same directory as the target.
func (p *opPump) runFilePut(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	fp := parseFilePutParams(raw)
	if fp.rejected != "" {
		return opOutcomeError(fp.rejected)
	}

	dir := filepath.Dir(fp.path)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return opOutcomeError("parent_missing")
		}
		return opOutcomeError("denied")
	}
	if !dirInfo.IsDir() {
		return opOutcomeError("parent_missing")
	}

	// First overwrite check — refuse before opening a temp at all.
	// We re-check immediately before rename to close the race window.
	if reason := checkOverwriteAllowed(fp.path, fp.overwrite); reason != "" {
		return opOutcomeError(reason)
	}

	tmp, err := os.CreateTemp(dir, ".praxis-put-*.tmp")
	if err != nil {
		return opOutcomeError("denied")
	}
	tmpPath := tmp.Name()
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	defer cleanup()

	// Apply requested mode to the tempfile so it lands with the right
	// perms after rename. CreateTemp uses 0600 by default.
	mode := fp.mode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return opOutcomeError("write_failed")
	}

	written, perr := p.filePutReceive(ctx, conn, tmp, fp.maxBytes)
	if perr != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return opOutcomeCancelled()
		}
		return opOutcomeError(perr.Error())
	}
	_ = written // surfaced as op_complete bytes is deferred per design lock

	if err := tmp.Sync(); err != nil {
		return opOutcomeError("write_failed")
	}
	if err := tmp.Close(); err != nil {
		return opOutcomeError("write_failed")
	}

	// Re-check overwrite right before rename (race window narrowed).
	if reason := checkOverwriteAllowed(fp.path, fp.overwrite); reason != "" {
		return opOutcomeError(reason)
	}

	if err := os.Rename(tmpPath, fp.path); err != nil {
		return opOutcomeError("write_failed")
	}
	cleaned = true // rename consumed it; cleanup must not unlink target
	return opOutcomeSuccess()
}

// filePutReceive runs the inbound loop: one ChannelControl header
// frame first, then ChannelFile Data frames terminated by a Close.
// Strict — anything off-script is bad_header / bad_frame.
func (p *opPump) filePutReceive(ctx context.Context, conn *websocket.Conn, dst io.Writer, maxBytes int64) (int64, error) {
	headerSeen := false
	declared := int64(0)
	var written int64
	for {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return written, ctx.Err()
			}
			return written, errors.New("op_stream_closed")
		}
		if mt != websocket.MessageBinary {
			return written, errors.New("bad_frame")
		}
		f, err := DecodeFrame(raw, p.maxFrame)
		if err != nil {
			p.log.Printf("file_put: decode: %v", err)
			return written, errors.New("bad_frame")
		}
		if !headerSeen {
			// Must be a ChannelControl Data frame with valid header.
			if f.Channel != ChannelControl || f.Op != FrameOpData {
				return written, errors.New("bad_header")
			}
			var hdr fileHeader
			if jerr := json.Unmarshal(f.Payload, &hdr); jerr != nil || hdr.Type != "file_header" {
				return written, errors.New("bad_header")
			}
			declared = hdr.Size
			if maxBytes > 0 && declared > maxBytes {
				return written, errors.New("too_large")
			}
			headerSeen = true
			continue
		}
		// Post-header frames must be on ChannelFile (Data or Close).
		if f.Channel != ChannelFile {
			return written, errors.New("bad_frame")
		}
		switch f.Op {
		case FrameOpData:
			if maxBytes > 0 && written+int64(len(f.Payload)) > maxBytes {
				return written, errors.New("too_large")
			}
			if declared > 0 && written+int64(len(f.Payload)) > declared {
				return written, errors.New("bad_frame")
			}
			n, werr := dst.Write(f.Payload)
			written += int64(n)
			if werr != nil {
				return written, errors.New("write_failed")
			}
		case FrameOpClose:
			// Header declared a size — enforce it on close. A short
			// upload (broker said 100, sent 10 + CLOSE) would otherwise
			// silently install a truncated file. declared==0 means
			// "unknown / empty" and is allowed to match any written.
			if declared > 0 && written != declared {
				return written, errors.New("size_mismatch")
			}
			return written, nil
		default:
			return written, errors.New("bad_frame")
		}
	}
}

func checkOverwriteAllowed(path string, overwrite bool) string {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		return "denied"
	}
	// Always refuse to clobber non-regular targets — symlinks,
	// directories, devices.
	if info.Mode()&os.ModeSymlink != 0 {
		return "is_symlink"
	}
	if info.IsDir() {
		return "is_directory"
	}
	if !info.Mode().IsRegular() {
		return "not_regular"
	}
	if !overwrite {
		return "exists"
	}
	return ""
}

// ---------- params parsing ----------

func parseFileGetParams(raw map[string]any) fileGetParams {
	var p fileGetParams
	path, ok := raw["path"].(string)
	if !ok || path == "" {
		p.rejected = "invalid_params"
		return p
	}
	if !validateAbsPath(path) {
		p.rejected = "invalid_params"
		return p
	}
	p.path = path
	if mb, ok := raw["max_bytes"].(float64); ok && mb > 0 {
		p.maxBytes = int64(mb)
	}
	return p
}

func parseFilePutParams(raw map[string]any) filePutParams {
	var p filePutParams
	path, ok := raw["path"].(string)
	if !ok || path == "" {
		p.rejected = "invalid_params"
		return p
	}
	if !validateAbsPath(path) {
		p.rejected = "invalid_params"
		return p
	}
	if isBlockedPutPath(path) {
		p.rejected = "blocked_path"
		return p
	}
	p.path = path
	if m, ok := raw["mode"].(string); ok && m != "" {
		mode, err := parseFileMode(m)
		if err != nil {
			p.rejected = "invalid_params"
			return p
		}
		p.mode = mode
	}
	if ow, ok := raw["overwrite"].(bool); ok {
		p.overwrite = ow
	}
	if mb, ok := raw["max_bytes"].(float64); ok && mb > 0 {
		p.maxBytes = int64(mb)
	}
	return p
}

// validateAbsPath enforces:
//   - non-empty
//   - absolute
//   - no NUL byte
//   - Clean(path) == path (no double-slashes, no trailing slash, no
//     redundant . segments). This means "/etc/../root/x" is rejected
//     because Clean produces "/root/x". Caller is expected to send
//     already-normalised paths.
func validateAbsPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.ContainsRune(path, 0) {
		return false
	}
	if !filepath.IsAbs(path) {
		return false
	}
	if filepath.Clean(path) != path {
		return false
	}
	return true
}

func isBlockedPutPath(path string) bool {
	for _, prefix := range blockedPutPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// parseFileMode accepts "0644", "644", or "0o644". Rejects anything
// outside 12 bits (perm + sticky/setuid/setgid).
func parseFileMode(s string) (os.FileMode, error) {
	s = strings.TrimPrefix(s, "0o")
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	if v > 0o7777 {
		return 0, fmt.Errorf("mode out of range")
	}
	return os.FileMode(v), nil
}
