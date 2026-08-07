// PTY primitive tests (PRA-152 task #5c).

//go:build linux

package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// readPtyUntilClose drains ChannelPty Data frames from the per-op
// WSS until the connection closes (which the agent does after sending
// CLOSE on ChannelPty + a graceful WSS close). Returns the
// concatenated payload. Tests must wait for the natural close —
// returning early would close the broker side, which the agent
// correctly interprets as "broker disconnected, kill child" and
// would poison the outcome.
func readPtyUntilClose(ctx context.Context, c *websocket.Conn) []byte {
	var buf []byte
	for ctx.Err() == nil {
		mt, raw, err := c.Read(ctx)
		if err != nil {
			return buf
		}
		if mt != websocket.MessageBinary {
			continue
		}
		f, derr := DecodeFrame(raw, DefaultMaxFramePayload)
		if derr != nil {
			return buf
		}
		if f.Channel == ChannelPty && f.Op == FrameOpData {
			buf = append(buf, f.Payload...)
		}
		// Don't return on ChannelPty Close — keep reading until the
		// conn itself closes so we don't tear down the broker side
		// while the agent is mid-graceful-close.
	}
	return buf
}

// runPtyOpTest is the shared scaffold for pty tests.
//
// Waits for BOTH op_complete on the control WSS AND opScript to fully
// return before returning. Without that wait, a test reading a `got`
// variable assigned inside opScript can race the broker handler
// goroutine — op_complete arrives, test returns, asserts on `got`
// before the broker handler has actually finished writing to it.
func runPtyOpTest(
	t *testing.T,
	opID int,
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
				"type": "op_request", "operation_id": opID, "op_type": "pty",
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
		t.Fatal("pty op never completed")
		return nil
	}
	// op_complete arrived; ensure the broker handler has finished
	// writing to any captured-in-closure variables before we return.
	select {
	case <-scriptDone:
	case <-time.After(timeout):
		t.Fatal("opScript did not finish after op_complete")
		return nil
	}
	return msg
}

// sendPty sends one ChannelPty Data frame.
func sendPty(ctx context.Context, c *websocket.Conn, data []byte) {
	w, _ := EncodeFrame(Frame{
		Op: FrameOpData, Channel: ChannelPty, Payload: data,
	}, DefaultMaxFramePayload)
	_ = c.Write(ctx, websocket.MessageBinary, w)
}

// sendPtyClose sends a ChannelPty Close (EOF on stdin).
func sendPtyClose(ctx context.Context, c *websocket.Conn) {
	w, _ := EncodeFrame(Frame{Op: FrameOpClose, Channel: ChannelPty}, DefaultMaxFramePayload)
	_ = c.Write(ctx, websocket.MessageBinary, w)
}

// sendPtyControl sends a ChannelControl Data frame with the given
// JSON message.
func sendPtyControl(ctx context.Context, c *websocket.Conn, msg map[string]any) {
	raw, _ := json.Marshal(msg)
	w, _ := EncodeFrame(Frame{
		Op: FrameOpData, Channel: ChannelControl, Payload: raw,
	}, DefaultMaxFramePayload)
	_ = c.Write(ctx, websocket.MessageBinary, w)
}

// ---------- happy path / I/O ----------

func TestPtyHappyPathEcho(t *testing.T) {
	var got []byte
	msg := runPtyOpTest(t, 3001,
		map[string]any{
			"cmd":  "/bin/sh",
			"args": []any{"-c", "echo hello-pty"},
		},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			got = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if !strings.Contains(string(got), "hello-pty") {
		t.Fatalf("output=%q missing 'hello-pty'", got)
	}
}

// TestPtyTrailingOutputDelivered ensures the bounded post-Wait drain
// actually lets the outbound pump flush the final screenful before
// the master is closed. Cancelling
// the bridge + closing master before outbound got its drain window
// could drop trailing bytes silently.
func TestPtyTrailingOutputDelivered(t *testing.T) {
	// Print a sentinel as the very last thing the child does and
	// exit immediately. The sentinel must arrive on the broker side
	// even though the child is dead by the time we tear down. The
	// outbound-in-main-goroutine restructure ensures master is
	// always being read from the moment we have it, so this works
	// even when the child finishes in microseconds.
	const sentinel = "BYE-trailing-sentinel"
	var got []byte
	msg := runPtyOpTest(t, 3010,
		map[string]any{
			"cmd":  "/bin/sh",
			"args": []any{"-c", "printf '%s\\n' '" + sentinel + "'"},
		},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			got = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if !strings.Contains(string(got), sentinel) {
		t.Fatalf("trailing output dropped: got=%q want sentinel=%q", got, sentinel)
	}
}

func TestPtyStdinForwarded(t *testing.T) {
	// `cat` echoes stdin to stdout under a PTY (line-buffered). Send
	// "ping\n" + EOF (CLOSE on ChannelPty), expect "ping" echoed back
	// and clean exit. 300ms wait gives the inbound goroutine time to
	// forward "ping\n" to the PTY on slow CI runners before EOT
	// arrives — cat would otherwise exit on EOT without processing.
	var got []byte
	msg := runPtyOpTest(t, 3002,
		map[string]any{"cmd": "/bin/cat"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			sendPty(ctx, c, []byte("ping\n"))
			time.Sleep(300 * time.Millisecond)
			sendPty(ctx, c, []byte{0x04}) // EOT
			got = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if !strings.Contains(string(got), "ping") {
		t.Fatalf("output=%q missing 'ping'", got)
	}
}

// ---------- resize ----------

func TestPtyResizeAffectsSize(t *testing.T) {
	// stty size reports rows/cols of the controlling terminal.
	// Spawn an interactive sh, send `stty size`, then resize, then
	// send `stty size` again. The two readings should differ.
	var got []byte
	msg := runPtyOpTest(t, 3003,
		map[string]any{
			"cmd": "/bin/sh",
			// Print the initial size, then poll up to 2s for the
			// kernel TTY size to change. Prints the new size and
			// exits as soon as the resize is observed — avoids the
			// timing race of "send resize between two fixed sleeps".
			"args": []any{"-c",
				"stty size; for i in $(seq 1 100); do " +
					"sz=$(stty size); " +
					"if [ \"$sz\" != \"24 80\" ]; then echo \"$sz\"; exit 0; fi; " +
					"sleep 0.02; done; exit 1",
			},
			"rows": float64(24),
			"cols": float64(80),
		},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Wait for the initial stty to land, then resize. The
			// shell loop will exit as soon as it observes the change.
			time.Sleep(100 * time.Millisecond)
			sendPtyControl(ctx, c, map[string]any{
				"type": "pty_resize",
				"rows": float64(40),
				"cols": float64(120),
			})
			got = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	out := string(got)
	if !strings.Contains(out, "24 80") {
		t.Fatalf("output=%q missing initial '24 80'", out)
	}
	if !strings.Contains(out, "40 120") {
		t.Fatalf("output=%q missing resized '40 120'", out)
	}
}

// ---------- signals ----------

func TestPtySignalSIGINT(t *testing.T) {
	// `cat` blocks on stdin. Send SIGINT — child should die,
	// agent should report success with non-zero exit (130 = 128+2).
	msg := runPtyOpTest(t, 3004,
		map[string]any{"cmd": "/bin/cat"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			time.Sleep(80 * time.Millisecond)
			sendPtyControl(ctx, c, map[string]any{
				"type": "pty_signal", "signal": "INT",
			})
			_ = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	exit := int(msg["exit_code"].(float64))
	if exit != 130 && exit != -1 {
		t.Fatalf("exit_code=%d want 130 (or -1 if killed)", exit)
	}
}

// ---------- cancel / timeout ----------

func TestPtyCancelMidRun(t *testing.T) {
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 3005, "op_type": "pty",
				"params": map[string]any{"cmd": "/bin/sleep", "args": []any{"30"}},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 3005, "nonce": "n3005",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			time.Sleep(150 * time.Millisecond)
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 3005,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = readPtyUntilClose(ctx, c)
		},
	}
	cfg := startDualBroker(t, d)
	cancelAgent := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancelAgent()
	select {
	case msg := <-complete:
		if msg["outcome"] != "cancelled" {
			t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled pty op never completed")
	}
}

func TestPtyTimeoutFires(t *testing.T) {
	msg := runPtyOpTest(t, 3006,
		map[string]any{"cmd": "/bin/sleep", "args": []any{"30"}, "timeout_s": 0.5},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
	}
	if msg["error"].(map[string]any)["reason"] != "timeout" {
		t.Fatalf("reason=%v want timeout", msg["error"])
	}
}

// ---------- errors / edge cases ----------

func TestPtyInvalidParamsMissingCmd(t *testing.T) {
	msg := runPtyOpTest(t, 3007,
		map[string]any{},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
		},
		5*time.Second,
	)
	if msg["error"].(map[string]any)["reason"] != "invalid_params" {
		t.Fatalf("reason=%v want invalid_params", msg["error"])
	}
}

func TestPtyMalformedControlIgnored(t *testing.T) {
	// Send a Control frame with garbage JSON; agent must log + ignore
	// (NOT terminate the op). Then sh should still run normally.
	var got []byte
	msg := runPtyOpTest(t, 3008,
		map[string]any{"cmd": "/bin/sh", "args": []any{"-c", "echo after-bad-control"}},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Send malformed JSON on control channel.
			bad, _ := EncodeFrame(Frame{
				Op: FrameOpData, Channel: ChannelControl, Payload: []byte("{not json"),
			}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, bad)
			got = readPtyUntilClose(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success (malformed control should not terminate); full=%v",
			msg["outcome"], msg)
	}
	if !strings.Contains(string(got), "after-bad-control") {
		t.Fatalf("output=%q missing expected text", got)
	}
}

// TestPtyBrokerDisconnectKillsChild covers the production scenario
// where the per-op WSS drops while an interactive command
// is still running. The agent must kill the child and report the
// outcome promptly instead of leaking a root process attached to a
// dead transport.
func TestPtyBrokerDisconnectKillsChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "cat.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			pid := strings.TrimSpace(string(b))
			if pid != "" {
				_ = exec.Command("kill", "-9", pid).Run()
			}
		}
	})
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 3011, "op_type": "pty",
				"params": map[string]any{
					"cmd":  "/bin/sh",
					"args": []any{"-c", "echo $$ > " + pidFile + "; exec /bin/cat"},
				},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 3011, "nonce": "n3011",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			// Read op_attach, wait for cat to actually be running,
			// then SLAM the per-op WSS shut while child is still
			// alive. Agent must detect, kill, and report.
			_, _, _ = c.Read(ctx)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			_ = c.CloseNow()
		},
	}
	cfg := startDualBroker(t, d)
	cancelAgent := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancelAgent()

	deadline := 5 * time.Second
	start := time.Now()
	select {
	case msg := <-complete:
		// op_stream_closed is the expected outcome: broker dropped
		// the per-op WSS while the child was alive.
		if msg["outcome"] != "error" {
			t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
		}
		if msg["error"].(map[string]any)["reason"] != "op_stream_closed" {
			t.Fatalf("reason=%v want op_stream_closed", msg["error"])
		}
	case <-time.After(deadline):
		t.Fatalf("agent never reported op_complete after broker disconnect — child likely leaked")
	}
	t.Logf("agent reported within %s after broker disconnect", time.Since(start))

	// Child must be dead — no zombie /proc entry alive.
	time.Sleep(200 * time.Millisecond)
	if pidBytes, err := os.ReadFile(pidFile); err == nil && len(pidBytes) > 0 {
		pid := strings.TrimSpace(string(pidBytes))
		if _, err := os.Stat("/proc/" + pid); err == nil {
			statusBytes, _ := os.ReadFile("/proc/" + pid + "/status")
			if !strings.Contains(string(statusBytes), "Z (zombie)") {
				t.Fatalf("child pid=%s still alive after broker disconnect; status=%s",
					pid, string(statusBytes))
			}
		}
	}
}

func TestPtyCancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pty-grandchild.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			pid := strings.TrimSpace(string(b))
			if pid != "" {
				_ = exec.Command("kill", "-9", pid).Run()
			}
		}
	})
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 3009, "op_type": "pty",
				"params": map[string]any{
					"cmd":  "/bin/sh",
					"args": []any{"-c", fmt.Sprintf("sleep 60 & echo $! > %s; sleep 60", pidFile)},
				},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 3009, "nonce": "n3009",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 3009,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = readPtyUntilClose(ctx, c)
		},
	}
	cfg := startDualBroker(t, d)
	cancelAgent := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancelAgent()
	select {
	case msg := <-complete:
		if msg["outcome"] != "cancelled" {
			t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("cancelled pty op never completed")
	}
	time.Sleep(200 * time.Millisecond)
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil || len(pidBytes) == 0 {
		t.Fatalf("grandchild pid file missing: %v", err)
	}
	pid := strings.TrimSpace(string(pidBytes))
	if _, err := os.Stat("/proc/" + pid); err == nil {
		statusBytes, _ := os.ReadFile("/proc/" + pid + "/status")
		if !strings.Contains(string(statusBytes), "Z (zombie)") {
			t.Fatalf("grandchild pid=%s still alive after pty cancel; status=%s",
				pid, string(statusBytes))
		}
	}
}
