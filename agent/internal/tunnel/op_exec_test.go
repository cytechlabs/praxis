// Exec primitive tests (PRA-152 task #5a). All tests stand up the
// dualBroker from op_test.go, send op_request(op_type=exec) +
// op_nonce on the control WSS, and assert frames + op_complete.

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

// execOpScript reads op_attach, then collects all Data/Close frames
// off stdout + stderr until both channels see CLOSE. Sends nothing
// inbound. Returns collected payloads keyed by channel.
type execStreams struct {
	stdout []byte
	stderr []byte
}

func collectExecFrames(ctx context.Context, c *websocket.Conn) execStreams {
	var s execStreams
	stdoutClosed, stderrClosed := false, false
	for ctx.Err() == nil && (!stdoutClosed || !stderrClosed) {
		mt, raw, err := c.Read(ctx)
		if err != nil {
			return s
		}
		if mt != websocket.MessageBinary {
			continue
		}
		f, err := DecodeFrame(raw, DefaultMaxFramePayload)
		if err != nil {
			return s
		}
		switch f.Channel {
		case ChannelStdout:
			switch f.Op {
			case FrameOpData:
				s.stdout = append(s.stdout, f.Payload...)
			case FrameOpClose:
				stdoutClosed = true
			}
		case ChannelStderr:
			switch f.Op {
			case FrameOpData:
				s.stderr = append(s.stderr, f.Payload...)
			case FrameOpClose:
				stderrClosed = true
			}
		}
	}
	return s
}

// runExecOpTest is the shared scaffold: set up dualBroker, send
// op_request + op_nonce with the given params, run the supplied
// opScript, return the op_complete payload.
//
// Waits for BOTH op_complete on the control WSS AND opScript to
// fully return before returning. Without that wait, a test reading
// a `streams` variable assigned inside opScript can race the broker
// handler goroutine — op_complete arrives, test returns, asserts on
// `streams` before the broker handler has actually finished writing.
func runExecOpTest(
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
				"type": "op_request", "operation_id": opID, "op_type": "exec",
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
		t.Fatal("exec op never completed")
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

func TestExecHappyPathStdout(t *testing.T) {
	var streams execStreams
	msg := runExecOpTest(t, 1001,
		map[string]any{"cmd": "echo", "args": []any{"hello"}},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx) // op_attach
			streams = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
	}
	if int(msg["exit_code"].(float64)) != 0 {
		t.Fatalf("exit_code=%v want 0", msg["exit_code"])
	}
	if !strings.Contains(string(streams.stdout), "hello") {
		t.Fatalf("stdout=%q missing 'hello'", string(streams.stdout))
	}
}

func TestExecNonZeroExit(t *testing.T) {
	msg := runExecOpTest(t, 1002,
		map[string]any{"cmd": "false"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success (success=we ran it); full=%v", msg["outcome"], msg)
	}
	if int(msg["exit_code"].(float64)) != 1 {
		t.Fatalf("exit_code=%v want 1", msg["exit_code"])
	}
}

func TestExecStderrSeparate(t *testing.T) {
	var streams execStreams
	msg := runExecOpTest(t, 1003,
		map[string]any{
			"cmd":  "sh",
			"args": []any{"-c", "echo out; echo err >&2"},
		},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			streams = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
	}
	if !strings.Contains(string(streams.stdout), "out") {
		t.Fatalf("stdout=%q missing 'out'", string(streams.stdout))
	}
	if !strings.Contains(string(streams.stderr), "err") {
		t.Fatalf("stderr=%q missing 'err'", string(streams.stderr))
	}
	if strings.Contains(string(streams.stdout), "err") {
		t.Fatalf("stderr leaked into stdout: %q", string(streams.stdout))
	}
}

func TestExecStdinEcho(t *testing.T) {
	var streams execStreams
	msg := runExecOpTest(t, 1004,
		map[string]any{"cmd": "cat"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			// Send three stdin Data frames + CLOSE on stdin; agent
			// should echo back via stdout.
			for _, line := range []string{"alpha\n", "beta\n", "gamma\n"} {
				wire, _ := EncodeFrame(Frame{
					Op: FrameOpData, Channel: ChannelStdin, Payload: []byte(line),
				}, DefaultMaxFramePayload)
				_ = c.Write(ctx, websocket.MessageBinary, wire)
			}
			closeWire, _ := EncodeFrame(Frame{
				Op: FrameOpClose, Channel: ChannelStdin,
			}, DefaultMaxFramePayload)
			_ = c.Write(ctx, websocket.MessageBinary, closeWire)
			streams = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
	}
	got := string(streams.stdout)
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout=%q missing %q", got, want)
		}
	}
}

func TestExecCancelMidRun(t *testing.T) {
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 1005, "op_type": "exec",
				"params": map[string]any{"cmd": "sleep", "args": []any{"30"}},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 1005, "nonce": "n1005",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			time.Sleep(150 * time.Millisecond)
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 1005,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
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
		t.Fatal("cancelled exec never completed")
	}
}

func TestExecTimeoutFires(t *testing.T) {
	msg := runExecOpTest(t, 1006,
		map[string]any{"cmd": "sleep", "args": []any{"30"}, "timeout_s": 0.5},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
	}
	errFld, _ := msg["error"].(map[string]any)
	if errFld["reason"] != "timeout" {
		t.Fatalf("reason=%v want timeout", errFld["reason"])
	}
}

func TestExecSpawnFailedOnMissingBinary(t *testing.T) {
	msg := runExecOpTest(t, 1007,
		map[string]any{"cmd": "/no/such/binary"},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
	}
	errFld, _ := msg["error"].(map[string]any)
	if errFld["reason"] != "spawn_failed" {
		t.Fatalf("reason=%v want spawn_failed", errFld["reason"])
	}
}

func TestExecInvalidParamsMissingCmd(t *testing.T) {
	msg := runExecOpTest(t, 1008,
		map[string]any{},
		func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
		},
		5*time.Second,
	)
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
	}
	errFld, _ := msg["error"].(map[string]any)
	if errFld["reason"] != "invalid_params" {
		t.Fatalf("reason=%v want invalid_params", errFld["reason"])
	}
}

// TestExecCancelCompletesWhenGrandchildHoldsPipe spawns a child that
// uses setsid to put a long-lived grandchild in its own session +
// process group, with the grandchild inheriting stdout/stderr from
// the parent. After cancel, kill -pgid kills the parent but the
// setsid'd grandchild survives and keeps the write end of the pipe
// open. Without the explicit pipe close in the drain timeout path,
// pumpPipe.r.Read() blocks forever and the op hangs. Test must
// complete promptly (well under the 5s budget).
func TestExecCancelCompletesWhenGrandchildHoldsPipe(t *testing.T) {
	if _, err := os.Stat("/usr/bin/setsid"); err != nil {
		if _, err := os.Stat("/bin/setsid"); err != nil {
			t.Skip("setsid not available")
		}
	}
	pidFile := filepath.Join(t.TempDir(), "setsid.pid")
	t.Cleanup(func() {
		// Reap the detached setsid'd sleep if still alive — would
		// otherwise linger up to 60s past the test in CI.
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		pid := strings.TrimSpace(string(b))
		if pid == "" {
			return
		}
		_ = exec.Command("kill", "-9", pid).Run()
	})
	complete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 1010, "op_type": "exec",
				"params": map[string]any{
					"cmd": "sh",
					"args": []any{"-c",
						// setsid puts the sleep in a new session so
						// kill -pgid won't reach it. Record its pid so
						// t.Cleanup can reap it if the test ends with
						// it still alive.
						"setsid sh -c 'echo $$ > " + pidFile + "; exec sleep 60' & exec sleep 60",
					},
				},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 1010, "nonce": "n1010",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			time.Sleep(200 * time.Millisecond)
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 1010,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
		},
	}
	cfg := startDualBroker(t, d)
	cancelAgent := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancelAgent()

	deadline := 3 * time.Second
	start := time.Now()
	select {
	case msg := <-complete:
		if msg["outcome"] != "cancelled" {
			t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
		}
	case <-time.After(deadline):
		t.Fatalf("op did not complete within %s — drain hung on grandchild fd", deadline)
	}
	t.Logf("completed in %s (must be ~drainAfterKill=250ms)", time.Since(start))
}

// TestExecCancelKillsProcessGroup spawns a parent that backgrounds a
// long-running grandchild and writes the grandchild's PID to a temp
// file before exiting. After cancel we verify the grandchild PID is
// no longer alive — proving Setpgid + kill -pgid actually killed the
// whole tree, not just the parent.
func TestExecCancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	t.Cleanup(func() {
		// Belt-and-suspenders: reap if kill -pgid somehow missed.
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
				"type": "op_request", "operation_id": 1009, "op_type": "exec",
				"params": map[string]any{
					"cmd": "sh",
					"args": []any{
						"-c",
						// Spawn a backgrounded sleep, write its pid,
						// then sleep ourselves so cancel fires while
						// we're still alive.
						fmt.Sprintf("sleep 60 & echo $! > %s; sleep 60", pidFile),
					},
				},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 1009, "nonce": "n1009",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			// Wait for grandchild pid to land on disk.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 1009,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, _, _ = c.Read(ctx)
			_ = collectExecFrames(ctx, c)
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
		t.Fatal("cancelled exec never completed")
	}
	// Give kill -pgid a moment to propagate.
	time.Sleep(200 * time.Millisecond)
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil || len(pidBytes) == 0 {
		t.Fatalf("grandchild pid file missing: %v", err)
	}
	pid := strings.TrimSpace(string(pidBytes))
	// /proc/<pid> should be gone (or zombie). If it's an alive
	// process that's not us, we leaked.
	if _, err := os.Stat("/proc/" + pid); err == nil {
		// Also check it's actually a process state we'd consider alive.
		statusBytes, _ := os.ReadFile("/proc/" + pid + "/status")
		if !strings.Contains(string(statusBytes), "Z (zombie)") {
			t.Fatalf("grandchild pid=%s still alive after cancel; status=%s",
				pid, string(statusBytes))
		}
	}
}
