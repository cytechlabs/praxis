// File primitives tests (PRA-152 task #5b).

package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// runFileOpTest is the shared scaffold for file_get / file_put tests.
// Sends op_request + op_nonce, runs opScript, returns op_complete.
func runFileOpTest(
	t *testing.T,
	opID int,
	opType string,
	params map[string]any,
	opScript func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request),
	timeout time.Duration,
) map[string]any {
	t.Helper()
	complete := make(chan map[string]any, 1)
	scriptDone := make(chan struct{})
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": opID, "op_type": opType,
				"params": params,
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": opID, "nonce": fmt.Sprintf("n%d", opID),
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			defer close(scriptDone)
			opScript(t, ctx, c, r)
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	var msg map[string]any
	select {
	case msg = <-complete:
	case <-time.After(timeout):
		t.Fatal("file op never completed")
		return nil
	}
	select {
	case <-scriptDone:
	case <-time.After(timeout):
		t.Fatal("opScript did not finish after op_complete")
		return nil
	}
	return msg
}

// collectFileGetStream reads the per-op WSS for one file_get session:
// header (ChannelControl Data) followed by ChannelFile Data frames
// terminated by ChannelFile Close. Returns header + concatenated bytes.
type fileGetResult struct {
	header fileHeader
	body   []byte
}

func collectFileGetStream(ctx context.Context, c *websocket.Conn) fileGetResult {
	var r fileGetResult
	headerSeen, fileClosed := false, false
	for ctx.Err() == nil && !fileClosed {
		mt, raw, err := c.Read(ctx)
		if err != nil {
			return r
		}
		if mt != websocket.MessageBinary {
			continue
		}
		f, err := DecodeFrame(raw, DefaultMaxFramePayload)
		if err != nil {
			return r
		}
		switch f.Channel {
		case ChannelControl:
			if f.Op == FrameOpData && !headerSeen {
				_ = json.Unmarshal(f.Payload, &r.header)
				headerSeen = true
			}
		case ChannelFile:
			switch f.Op {
			case FrameOpData:
				r.body = append(r.body, f.Payload...)
			case FrameOpClose:
				fileClosed = true
			}
		}
	}
	return r
}

// ---------- file_get ----------

func TestFileGetHappyPath(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.bin")
	want := []byte("hello world")
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var got fileGetResult
	msg := runFileOpTest(t, 2001, "file_get",
		map[string]any{"path": src},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			got = collectFileGetStream(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
	}
	if got.header.Type != "file_header" || got.header.Size != int64(len(want)) {
		t.Fatalf("header=%+v want size=%d", got.header, len(want))
	}
	if !bytes.Equal(got.body, want) {
		t.Fatalf("body=%q want %q", got.body, want)
	}
}

func TestFileGetLargeFileChunked(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "big.bin")
	want := make([]byte, 8*1024*1024) // 8 MiB
	_, _ = rand.Read(want)
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var got fileGetResult
	msg := runFileOpTest(t, 2002, "file_get",
		map[string]any{"path": src},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			got = collectFileGetStream(ctx, c)
		},
		15*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if !bytes.Equal(got.body, want) {
		t.Fatalf("body mismatch: got %d bytes want %d", len(got.body), len(want))
	}
}

func TestFileGetNotFound(t *testing.T) {
	msg := runFileOpTest(t, 2003, "file_get",
		map[string]any{"path": "/nonexistent/path/here"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
		},
		5*time.Second,
	)
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if msg["error"].(map[string]any)["reason"] != "not_found" {
		t.Fatalf("reason=%v", msg["error"])
	}
}

func TestFileGetIsDirectory(t *testing.T) {
	msg := runFileOpTest(t, 2004, "file_get",
		map[string]any{"path": "/tmp"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "is_directory" {
		t.Fatalf("reason=%v", msg["error"])
	}
}

func TestFileGetTooLarge(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "big.txt")
	_ = os.WriteFile(src, make([]byte, 100), 0o644)
	msg := runFileOpTest(t, 2005, "file_get",
		map[string]any{"path": src, "max_bytes": float64(10)},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "too_large" {
		t.Fatalf("reason=%v", msg["error"])
	}
}

func TestFileGetNonRegularFile(t *testing.T) {
	// Symlink should be rejected as not_regular (we Lstat).
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real.txt")
	_ = os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	msg := runFileOpTest(t, 2006, "file_get",
		map[string]any{"path": link},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "not_regular" {
		t.Fatalf("reason=%v", msg["error"])
	}
}

func TestFileGetInvalidPath(t *testing.T) {
	for _, p := range []string{"", "relative", "/etc/../root/x", "/with\x00nul"} {
		t.Run(p, func(t *testing.T) {
			msg := runFileOpTest(t, 2007, "file_get",
				map[string]any{"path": p},
				func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
					_, _, _ = c.Read(ctx)
				},
				5*time.Second,
			)
			if msg["error"].(map[string]any)["reason"] != "invalid_params" {
				t.Fatalf("path=%q reason=%v", p, msg["error"])
			}
		})
	}
}

// ---------- file_put ----------

// putFile is a helper that writes header + N data frames + close on
// the per-op WSS. Returns when the broker side has finished sending.
func putFile(ctx context.Context, c *websocket.Conn, body []byte) {
	hdr := fileHeader{Type: "file_header", Size: int64(len(body))}
	hdrRaw, _ := json.Marshal(hdr)
	wire, _ := EncodeFrame(Frame{
		Op: FrameOpData, Channel: ChannelControl, Payload: hdrRaw,
	}, DefaultMaxFramePayload)
	_ = c.Write(ctx, websocket.MessageBinary, wire)

	const chunk = 32 * 1024
	for i := 0; i < len(body); i += chunk {
		end := i + chunk
		if end > len(body) {
			end = len(body)
		}
		w, _ := EncodeFrame(Frame{
			Op: FrameOpData, Channel: ChannelFile, Payload: body[i:end],
		}, DefaultMaxFramePayload)
		_ = c.Write(ctx, websocket.MessageBinary, w)
	}
	closeF, _ := EncodeFrame(Frame{Op: FrameOpClose, Channel: ChannelFile}, DefaultMaxFramePayload)
	_ = c.Write(ctx, websocket.MessageBinary, closeF)
}

func TestFilePutHappyPath(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "out.bin")
	want := []byte("uploaded contents\n")
	msg := runFileOpTest(t, 2101, "file_put",
		map[string]any{"path": dst, "mode": "0644"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, want)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file=%q want %q", got, want)
	}
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%v want 0644", info.Mode().Perm())
	}
}

func TestFilePutDefaultModeIs0600(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "secret")
	runFileOpTest(t, 2102, "file_put",
		map[string]any{"path": dst},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, []byte("x"))
		},
		5*time.Second,
	)
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v want 0600", info.Mode().Perm())
	}
}

func TestFilePutOverwriteFalseRejects(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "exists.txt")
	original := []byte("original")
	_ = os.WriteFile(dst, original, 0o644)
	msg := runFileOpTest(t, 2103, "file_put",
		map[string]any{"path": dst},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, []byte("new"))
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "exists" {
		t.Fatalf("reason=%v", msg["error"])
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, original) {
		t.Fatalf("file mutated: got %q", got)
	}
}

func TestFilePutOverwriteTrueReplaces(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "replace.txt")
	_ = os.WriteFile(dst, []byte("old"), 0o644)
	want := []byte("new")
	msg := runFileOpTest(t, 2104, "file_put",
		map[string]any{"path": dst, "overwrite": true},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, want)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("file=%q want %q", got, want)
	}
}

func TestFilePutBlockedPath(t *testing.T) {
	for _, p := range []string{"/proc/x", "/sys/x", "/dev/x", "/run/x"} {
		t.Run(p, func(t *testing.T) {
			msg := runFileOpTest(t, 2105, "file_put",
				map[string]any{"path": p},
				func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
					_, _, _ = c.Read(ctx)
				},
				5*time.Second,
			)
			if msg["error"].(map[string]any)["reason"] != "blocked_path" {
				t.Fatalf("path=%q reason=%v", p, msg["error"])
			}
		})
	}
}

func TestFilePutSymlinkTargetRefused(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real.txt")
	_ = os.WriteFile(real, []byte("x"), 0o644)
	link := filepath.Join(tmp, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	msg := runFileOpTest(t, 2106, "file_put",
		map[string]any{"path": link, "overwrite": true},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, []byte("new"))
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "is_symlink" {
		t.Fatalf("reason=%v", msg["error"])
	}
	// Real target must be untouched.
	got, _ := os.ReadFile(real)
	if string(got) != "x" {
		t.Fatalf("real target mutated: %q", got)
	}
}

func TestFilePutTooLargeMidStream(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "out.bin")
	msg := runFileOpTest(t, 2107, "file_put",
		map[string]any{"path": dst, "max_bytes": float64(10)},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, make([]byte, 1024))
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "too_large" {
		t.Fatalf("reason=%v", msg["error"])
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst should not exist after rejected put: err=%v", err)
	}
}

func TestFilePutBadHeader(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "out.bin")
	msg := runFileOpTest(t, 2108, "file_put",
		map[string]any{"path": dst},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Send a non-header frame first — should be bad_header.
			f, _ := EncodeFrame(Frame{
				Op: FrameOpData, Channel: ChannelFile, Payload: []byte("oops"),
			}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, f)
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "bad_header" {
		t.Fatalf("reason=%v", msg["error"])
	}
}

func TestFilePutShortUploadRejected(t *testing.T) {
	// Broker declares size=100 in header but only sends 10 bytes
	// before CLOSE. Agent must reject as size_mismatch and leave no
	// file behind — otherwise a truncated upload silently installs.
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "short.bin")
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 2111, "op_type": "file_put",
				"params": map[string]any{"path": dst},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 2111, "nonce": "n2111",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Header claims 100 bytes...
			hdr := fileHeader{Type: "file_header", Size: 100}
			hdrRaw, _ := json.Marshal(hdr)
			wire, _ := EncodeFrame(Frame{
				Op: FrameOpData, Channel: ChannelControl, Payload: hdrRaw,
			}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, wire)
			// ...but only send 10 bytes...
			data, _ := EncodeFrame(Frame{
				Op: FrameOpData, Channel: ChannelFile, Payload: make([]byte, 10),
			}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, data)
			// ...then CLOSE early.
			closeF, _ := EncodeFrame(Frame{Op: FrameOpClose, Channel: ChannelFile}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, closeF)
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()
	select {
	case msg := <-complete:
		if msg["outcome"] != "error" {
			t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
		}
		if msg["error"].(map[string]any)["reason"] != "size_mismatch" {
			t.Fatalf("reason=%v want size_mismatch", msg["error"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("op never completed")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("dst should not exist after rejected put: err=%v", err)
	}
	// No leftover tempfile.
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover tempfile: %s", e.Name())
		}
	}
}

func TestFilePutEmpty(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "empty.bin")
	msg := runFileOpTest(t, 2109, "file_put",
		map[string]any{"path": dst},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			putFile(ctx, c, nil)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("size=%d want 0", info.Size())
	}
}

func TestFilePutAtomicOnExistingFile(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "x.txt")
	original := []byte("ORIGINAL")
	_ = os.WriteFile(dst, original, 0o644)

	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 2110, "op_type": "file_put",
				"params": map[string]any{"path": dst, "overwrite": true, "max_bytes": float64(10)},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 2110, "nonce": "n2110",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Send oversized file — should fail mid-stream and
			// leave the original untouched.
			putFile(ctx, c, make([]byte, 1024))
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()
	select {
	case msg := <-complete:
		if msg["outcome"] != "error" {
			t.Fatalf("expected error; got %v", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("op never completed")
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, original) {
		t.Fatalf("original mutated by failed put: %q", got)
	}
	// No leftover .praxis-put-*.tmp in the dir.
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover tempfile: %s", e.Name())
		}
	}
}
