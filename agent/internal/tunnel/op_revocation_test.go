// Revocation tests for the exec primitive: gated start (op_ready) and
// verified process-group termination on cancel.

//go:build linux

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"
)

// gatedExecBroker drives one exec op with await_ready=true. opScript runs on
// the per-op socket after the leading op_attach has been read. cancelOn
// controls the control-socket op_cancel: "" sends none, "attach" sends it as
// soon as the op attaches (while it waits at the gate), and any other value is
// a file path: the cancel is sent once that file exists (the process is up).
func gatedExecBroker(
	t *testing.T,
	opID int,
	params map[string]any,
	cancelOn string,
	opScript func(t *testing.T, ctx context.Context, c *websocket.Conn, attach map[string]any),
) map[string]any {
	t.Helper()
	complete := make(chan map[string]any, 1)
	attached := make(chan struct{}, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": opID, "op_type": "exec",
				"params": params, "await_ready": true,
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": opID, "nonce": fmt.Sprintf("n%d", opID),
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			if cancelOn != "" {
				select {
				case <-attached:
				case <-time.After(3 * time.Second):
				}
				if cancelOn != "attach" {
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						if b, err := os.ReadFile(cancelOn); err == nil && len(b) > 0 {
							break
						}
						time.Sleep(25 * time.Millisecond)
					}
				}
				cancel, _ := json.Marshal(map[string]any{"type": "op_cancel", "operation_id": opID})
				_ = c.Write(ctx, websocket.MessageText, cancel)
			}
			drainOpComplete(ctx, c, complete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			_, raw, err := c.Read(ctx)
			if err != nil {
				return
			}
			var attach map[string]any
			_ = json.Unmarshal(raw, &attach)
			select {
			case attached <- struct{}{}:
			default:
			}
			opScript(t, ctx, c, attach)
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
		return msg
	case <-time.After(15 * time.Second):
		t.Fatal("gated exec op never completed")
		return nil
	}
}

func sendOpReady(ctx context.Context, c *websocket.Conn, opID int) {
	raw, _ := json.Marshal(map[string]any{"type": "op_ready", "operation_id": opID})
	_ = c.Write(ctx, websocket.MessageText, raw)
}

// A gated agent announces await_ready in op_attach and starts nothing while
// the broker withholds op_ready. A refusal (here: the broker closes the
// socket) leaves no marker and reports not_started.
func TestGatedExecRefusedStartRunsNothing(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	var sawAwaitReady bool
	msg := gatedExecBroker(t, 3101,
		map[string]any{"cmd": "touch", "args": []any{marker}},
		"",
		func(t *testing.T, ctx context.Context, c *websocket.Conn, attach map[string]any) {
			sawAwaitReady, _ = attach["await_ready"].(bool)
			// Refuse: close without op_ready.
			_ = c.Close(websocket.StatusPolicyViolation, "system_not_active")
		})
	if !sawAwaitReady {
		t.Fatal("op_attach did not carry await_ready=true")
	}
	if msg["outcome"] != "error" {
		t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
	}
	if e, _ := msg["error"].(map[string]any); e["reason"] != "op_not_authorized" {
		t.Fatalf("error=%v want op_not_authorized", msg["error"])
	}
	if msg["termination"] != "not_started" {
		t.Fatalf("termination=%v want not_started", msg["termination"])
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("process ran even though the broker never sent op_ready")
	}
}

// With op_ready the same op runs normally.
func TestGatedExecRunsAfterOpReady(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	msg := gatedExecBroker(t, 3102,
		map[string]any{"cmd": "touch", "args": []any{marker}},
		"",
		func(t *testing.T, ctx context.Context, c *websocket.Conn, attach map[string]any) {
			sendOpReady(ctx, c, 3102)
			_ = collectExecFrames(ctx, c)
		})
	if msg["outcome"] != "success" {
		t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected marker after op_ready: %v", err)
	}
}

// A cancel that arrives while the op waits at the gate starts nothing and is
// reported as not_started, never as confirmed.
func TestGatedExecCancelBeforeReadyReportsNotStarted(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	msg := gatedExecBroker(t, 3103,
		map[string]any{"cmd": "touch", "args": []any{marker}},
		"attach",
		func(t *testing.T, ctx context.Context, c *websocket.Conn, attach map[string]any) {
			// Never send op_ready; wait for the agent to give up.
			_, _, _ = c.Read(ctx)
		})
	if msg["outcome"] != "cancelled" {
		t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
	}
	if msg["termination"] != "not_started" {
		t.Fatalf("termination=%v want not_started", msg["termination"])
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("process ran after cancel at the gate")
	}
}

// Cancelling a running exec reports confirmed only because the process group
// (parent and backgrounded grandchild) was verified gone.
func TestExecCancelReportsConfirmedTermination(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			_ = exec.Command("kill", "-9", strings.TrimSpace(string(b))).Run()
		}
	})
	msg := gatedExecBroker(t, 3104,
		map[string]any{
			"cmd":  "sh",
			"args": []any{"-c", fmt.Sprintf("sleep 60 & echo $! > %s; sleep 60", pidFile)},
		},
		pidFile,
		func(t *testing.T, ctx context.Context, c *websocket.Conn, attach map[string]any) {
			sendOpReady(ctx, c, 3104)
			_ = collectExecFrames(ctx, c)
		})
	if msg["outcome"] != "cancelled" {
		t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
	}
	if msg["termination"] != "confirmed" {
		t.Fatalf("termination=%v want confirmed; full=%v", msg["termination"], msg)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild pid not recorded: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if live, _ := groupHasLiveMembers(pid); live {
		t.Fatalf("grandchild group %d still has live members after confirmed", pid)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		// A zombie still answers kill(pid, 0); only a live process is a failure.
		if st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); !strings.Contains(string(st), ") Z") {
			t.Fatalf("grandchild %d is still alive", pid)
		}
	}
}

func TestGroupHasLiveMembersTracksProcessGroup(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	defer func() { _ = syscall.Kill(-pgid, syscall.SIGKILL); _ = cmd.Wait() }()

	alive, ok := groupHasLiveMembers(pgid)
	if !ok || !alive {
		t.Fatalf("running group: alive=%v ok=%v want true,true", alive, ok)
	}
	if got := verifyGroupStopped(pgid); got != terminationConfirmed {
		t.Fatalf("verifyGroupStopped=%q want %q", got, terminationConfirmed)
	}
	// The leader is now a zombie until reaped; a zombie is not a live member.
	if alive, ok := groupHasLiveMembers(pgid); !ok || alive {
		t.Fatalf("after kill: alive=%v ok=%v want false,true", alive, ok)
	}
}

// errFS wraps an fs.FS and fails opens of chosen paths, so incomplete proc
// visibility can be simulated without privileged mounts.
type errFS struct {
	fs.FS
	fail map[string]error
}

func (e errFS) Open(name string) (fs.File, error) {
	if err, ok := e.fail[name]; ok {
		return nil, err
	}
	return e.FS.Open(name)
}

func statLine(pid int, state string, pgrp int) []byte {
	return []byte(fmt.Sprintf("%d (sh) %s 1 %d 1 0 0\n", pid, state, pgrp))
}

func inspectorFor(proc fs.FS, probeErr error, hidden bool) procInspector {
	return procInspector{
		proc:   proc,
		probe:  func(int) error { return probeErr },
		kill:   func(int) error { return nil },
		hidden: func() bool { return hidden },
	}
}

func TestInspectGroupIsConservative(t *testing.T) {
	const pg = 500
	live := fstest.MapFS{"501/stat": {Data: statLine(501, "S", pg)}}
	zombie := fstest.MapFS{"501/stat": {Data: statLine(501, "Z", pg)}}
	other := fstest.MapFS{"900/stat": {Data: statLine(900, "S", 1)}}
	eacces := errFS{FS: zombie, fail: map[string]error{"501/stat": fs.ErrPermission}}
	gone := errFS{FS: zombie, fail: map[string]error{"501/stat": fs.ErrNotExist}}
	noProc := errFS{FS: zombie, fail: map[string]error{".": errors.New("no /proc")}}
	garbage := fstest.MapFS{"501/stat": {Data: []byte("not a stat line")}}
	short := fstest.MapFS{"501/stat": {Data: []byte("501 (sh) S 1")}}

	cases := []struct {
		name string
		in   procInspector
		want groupState
	}{
		{"live member", inspectorFor(live, nil, false), groupLive},
		{"only a zombie", inspectorFor(zombie, nil, false), groupGone},
		{"kernel says ESRCH", inspectorFor(other, syscall.ESRCH, false), groupGone},
		{"ESRCH beats hidden", inspectorFor(other, syscall.ESRCH, true), groupGone},
		{"EPERM means members exist", inspectorFor(other, syscall.EPERM, false), groupLive},
		{"scan empty but kernel says members", inspectorFor(other, nil, false), groupUnknown},
		{"hidden processes", inspectorFor(zombie, nil, true), groupUnknown},
		{"no process table", inspectorFor(noProc, nil, false), groupUnknown},
		{"unreadable entry", inspectorFor(eacces, nil, false), groupUnknown},
		{"unparseable entry", inspectorFor(garbage, nil, false), groupUnknown},
		{"truncated entry", inspectorFor(short, nil, false), groupUnknown},
		{"entry vanished mid-scan", inspectorFor(gone, nil, false), groupUnknown},
	}
	for _, c := range cases {
		if got := inspectGroup(pg, c.in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// A vanished entry with the rest of the group accounted for is gone.
func TestInspectGroupVanishedEntryWithZombieAccounted(t *testing.T) {
	proc := errFS{
		FS: fstest.MapFS{
			"501/stat": {Data: statLine(501, "Z", 500)},
			"502/stat": {Data: statLine(502, "S", 500)},
		},
		fail: map[string]error{"502/stat": fs.ErrNotExist},
	}
	if got := inspectGroup(500, inspectorFor(proc, nil, false)); got != groupGone {
		t.Fatalf("got %v want gone", got)
	}
}

func TestVerifyReportsUnconfirmedWhenGroupCannotBeInspected(t *testing.T) {
	in := inspectorFor(errFS{FS: fstest.MapFS{}, fail: map[string]error{".": errors.New("denied")}}, syscall.EPERM, false)
	in.probe = func(int) error { return nil }
	start := time.Now()
	if got := verifyGroupStoppedWith(2147483000, in, 150*time.Millisecond); got != terminationUnconfirmed {
		t.Fatalf("got %q want unconfirmed", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("verification was not bounded")
	}
}

func TestVerifyIgnoresFailedSignalAndStillRequiresEvidence(t *testing.T) {
	in := inspectorFor(fstest.MapFS{"501/stat": {Data: statLine(501, "S", 500)}}, nil, false)
	in.kill = func(int) error { return syscall.EPERM }
	if got := verifyGroupStoppedWith(500, in, 100*time.Millisecond); got != terminationUnconfirmed {
		t.Fatalf("got %q want unconfirmed", got)
	}
}
