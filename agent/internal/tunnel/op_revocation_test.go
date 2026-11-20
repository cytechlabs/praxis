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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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
		tunnelScript: func(_ *testing.T, ctx context.Context, c *websocket.Conn, _ map[string]any) {
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
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, _ *http.Request) {
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
		func(_ *testing.T, _ context.Context, c *websocket.Conn, attach map[string]any) {
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
		func(_ *testing.T, ctx context.Context, c *websocket.Conn, _ map[string]any) {
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
		func(_ *testing.T, ctx context.Context, c *websocket.Conn, _ map[string]any) {
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
		func(_ *testing.T, ctx context.Context, c *websocket.Conn, _ map[string]any) {
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

// refusedHandshake runs a gated exec whose broker answers op_attach with the
// given frame instead of a valid op_ready, then keeps the socket open so the
// refusal can only come from the agent rejecting that frame. The refusal must
// also arrive well inside opReadyTimeout, which proves the frame was rejected
// rather than the wait timing out.
func refusedHandshake(t *testing.T, opID int, mt websocket.MessageType, payload []byte) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "ran")
	wrote := make(chan error, 1)
	start := time.Now()
	msg := gatedExecBroker(t, opID,
		map[string]any{"cmd": "touch", "args": []any{marker}},
		"",
		func(_ *testing.T, ctx context.Context, c *websocket.Conn, _ map[string]any) {
			wrote <- c.Write(ctx, mt, payload)
			_, _, _ = c.Read(ctx)
		})
	elapsed := time.Since(start)
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("broker could not send the handshake frame: %v", err)
		}
	default:
		t.Fatal("broker never sent the handshake frame")
	}
	if elapsed >= opReadyTimeout/2 {
		t.Fatalf("refusal took %v: not a prompt rejection of the frame (ready timeout %v)", elapsed, opReadyTimeout)
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
		t.Fatal("process ran although the handshake was not a valid op_ready")
	}
}

// op_ready must arrive as a text frame; the same bytes in a binary frame are
// a refusal and nothing starts.
func TestGatedExecBinaryOpReadyIsRefused(t *testing.T) {
	refusedHandshake(t, 3105, websocket.MessageBinary,
		[]byte(`{"type":"op_ready","operation_id":3105}`))
}

// A text frame that is not valid JSON is a refusal and nothing starts. The
// type field is present and correct in every payload. A syntax error leaves
// the destination empty, but a value that does not fit its Go type (the
// out-of-range number) fails after "type" was already decoded, so only the
// decode error check keeps that payload from being treated as op_ready.
func TestGatedExecMalformedOpReadyIsRefused(t *testing.T) {
	refusedHandshake(t, 3106, websocket.MessageText, []byte(`{"type":"op_ready"`))
	refusedHandshake(t, 3109, websocket.MessageText, []byte(`{"type":"op_ready"} trailing`))
	refusedHandshake(t, 3110, websocket.MessageText, []byte(`{"type":"op_ready","operation_id":}`))
	// A number outside float64 range fails decoding after "type" was seen.
	refusedHandshake(t, 3111, websocket.MessageText, []byte(`{"type":"op_ready","extra":1e999}`))
}

// Well-formed JSON of the wrong type (or the wrong shape) is a refusal and
// nothing starts.
func TestGatedExecWrongHandshakeMessageIsRefused(t *testing.T) {
	refusedHandshake(t, 3107, websocket.MessageText, []byte(`{"type":"op_attach","operation_id":3107}`))
	refusedHandshake(t, 3108, websocket.MessageText, []byte(`["op_ready"]`))
}

// An op cancelled before the process is spawned starts nothing and reports
// not_started rather than a termination verdict.
func TestRunExecCancelledBeforeSpawnStartsNothing(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// No connection is needed: the op must return before touching it.
	out := (&opPump{}).runExec(ctx, 1, nil, map[string]any{"cmd": "touch", "args": []any{marker}})
	if out.outcome != "cancelled" {
		t.Fatalf("outcome=%q want cancelled", out.outcome)
	}
	if out.extra["termination"] != terminationNotStarted {
		t.Fatalf("termination=%v want %q", out.extra["termination"], terminationNotStarted)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("process ran although the op was cancelled before spawn")
	}
}

func TestProcHidesFor(t *testing.T) {
	const visible = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
	cases := []struct {
		name   string
		euid   int
		mounts string
		err    error
		want   bool
	}{
		{"root sees all even with hidepid", 0, "proc /proc proc rw,hidepid=2 0 0\n", nil, false},
		{"root never needs the mount table", 0, "", errors.New("unreadable"), false},
		{"unreadable mount table is assumed hidden", 1000, "", errors.New("unreadable"), true},
		{"hidepid=2", 1000, "proc /proc proc rw,hidepid=2 0 0\n", nil, true},
		{"hidepid=invisible", 1000, "proc /proc proc rw,hidepid=invisible,gid=1 0 0\n", nil, true},
		{"hidepid=1", 1000, visible + "proc /proc proc rw,hidepid=1 0 0\n", nil, true},
		{"plain proc", 1000, visible, nil, false},
		{"hidepid=0", 1000, "proc /proc proc rw,hidepid=0 0 0\n", nil, false},
		{"hidepid on another mount point", 1000, "proc /elsewhere proc rw,hidepid=2 0 0\n" + visible, nil, false},
		{"short and blank lines are skipped", 1000, "\nproc /proc\n" + visible, nil, false},
	}
	for _, c := range cases {
		got := procHidesFor(c.euid, func() ([]byte, error) { return []byte(c.mounts), c.err })
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// An unknown group is never reported as gone: it is alive with ok=false.
func TestLiveMembersOfNeverClaimsGoneForUnknown(t *testing.T) {
	cases := []struct {
		state     groupState
		alive, ok bool
	}{
		{groupLive, true, true},
		{groupGone, false, true},
		{groupUnknown, true, false},
	}
	for _, c := range cases {
		if alive, ok := liveMembersOf(c.state); alive != c.alive || ok != c.ok {
			t.Errorf("state %v: got alive=%v ok=%v want %v,%v", c.state, alive, ok, c.alive, c.ok)
		}
	}
	// End to end through the inspector: hidden processes yield unknown.
	in := inspectorFor(fstest.MapFS{}, nil, true)
	if alive, ok := liveMembersOf(inspectGroup(500, in)); !alive || ok {
		t.Fatalf("hidden proc table: alive=%v ok=%v want true,false", alive, ok)
	}
}

func TestParseProcStat(t *testing.T) {
	cases := []struct {
		name, raw   string
		state, pgrp string
		ok          bool
	}{
		{"plain", "501 (sh) S 1 500 1 0", "S", "500", true},
		{"comm with spaces and parens", "501 (a) b (c)) Z 1 77 1 0", "Z", "77", true},
		{"no closing paren", "501 sh S 1 500", "", "", false},
		{"nothing after comm", "501 (sh)", "", "", false},
		{"too few fields", "501 (sh) S 1", "", "", false},
	}
	for _, c := range cases {
		state, pgrp, ok := parseProcStat([]byte(c.raw))
		if state != c.state || pgrp != c.pgrp || ok != c.ok {
			t.Errorf("%s: got %q %q %v want %q %q %v", c.name, state, pgrp, ok, c.state, c.pgrp, c.ok)
		}
	}
}

// A cancelled bridge whose peer has stopped reading must return cleanly and
// promptly: neither the stalled outbound writer nor the inbound reader may
// hold the op open or turn the cancel into a protocol error.
func TestRunBridgeCancelWithStalledPeerReturnsClean(t *testing.T) {
	before := runtime.NumGoroutine()
	stop := make(chan struct{})
	var handlers atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		handlers.Add(1)
		defer handlers.Add(-1)
		defer c.CloseNow() //nolint:errcheck // best-effort close of a test server socket at handler exit
		<-stop             // never reads: the writer backs up
	}))
	defer func() {
		close(stop)
		waitHandlersExit(t, &handlers)
		srv.Close()
		assertNoGoroutineLeak(t, before)
	}()

	big := make([]byte, 512*1024)
	outbox := make([]Frame, 64)
	for i := range outbox {
		outbox[i] = Frame{Op: FrameOpData, Channel: ChannelStdout, Payload: big}
	}
	p := &opPump{maxFrame: DefaultMaxFramePayload, log: &captureLogger{}}

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		done := make(chan *bridgeErr, 1)
		go func() { done <- p.runBridge(ctx, conn, outbox) }()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case be := <-done:
			if be != nil {
				t.Fatalf("iteration %d: cancel reported %q, want clean", i, be.reason)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: runBridge did not return after cancel", i)
		}
		_ = conn.CloseNow()
	}
}

// How a reaped exec is reported: a timeout or protocol error is an error, a
// non-zero exit is still a success carrying its code, and only a non-exit
// wait failure is a spawn failure.
func TestExecOutcomeResolution(t *testing.T) {
	live := context.Background()
	expired, cancelExpired := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelExpired()
	<-expired.Done()
	exitErr := exec.Command("sh", "-c", "exit 7").Run()

	if o := execOutcome(live, expired, time.Second, nil, nil, 0); o.error == nil || o.error.Reason != "timeout" {
		t.Errorf("timeout: got %+v", o)
	}
	if o := execOutcome(live, live, 0, errors.New("bad_frame"), nil, 0); o.error == nil || o.error.Reason != "bad_frame" {
		t.Errorf("inbound error: got %+v", o)
	}
	if o := execOutcome(live, live, 0, nil, errors.New("pipe"), 0); o.error == nil || o.error.Reason != "spawn_failed" {
		t.Errorf("non-exit wait failure: got %+v", o)
	}
	o := execOutcome(live, live, 0, nil, exitErr, 0)
	if o.outcome != "success" || o.exitCode == nil || *o.exitCode != 7 {
		t.Errorf("exit 7: got %+v", o)
	}
}

// waitHandlersExit blocks until every test server handler has returned.
func waitHandlersExit(t *testing.T, n *atomic.Int32) {
	t.Helper()
	for i := 0; i < 100 && n.Load() > 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if left := n.Load(); left > 0 {
		t.Errorf("%d test server handlers did not exit", left)
	}
}

// assertNoGoroutineLeak fails unless the goroutine count settles back to at
// most before.
func assertNoGoroutineLeak(t *testing.T, before int) {
	t.Helper()
	var after int
	for i := 0; i < 100; i++ {
		after = runtime.NumGoroutine()
		if after <= before {
			t.Logf("goroutines: %d before, %d after", before, after)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: %d before, %d after", before, after)
}

// A bridge cancelled before it starts sends nothing and reports clean no
// matter which side notices first. The two sides race, so the loop runs until
// both completion orders have been observed (bounded), and every iteration
// must be clean.
func TestRunBridgePreCancelledIsCleanInEitherOrder(t *testing.T) {
	before := runtime.NumGoroutine()
	var handlers atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		handlers.Add(1)
		defer handlers.Add(-1)
		defer c.CloseNow() //nolint:errcheck // best-effort close of a test server socket at handler exit
		// Returns once the client closes its side.
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer func() {
		waitHandlersExit(t, &handlers)
		srv.Close()
		assertNoGoroutineLeak(t, before)
	}()

	var inboundFirst, outboundFirst atomic.Int32
	p := &opPump{maxFrame: DefaultMaxFramePayload, log: &captureLogger{}}
	p.bridgeFirst = func(in bool) {
		if in {
			inboundFirst.Add(1)
		} else {
			outboundFirst.Add(1)
		}
	}
	outbox := []Frame{{Op: FrameOpData, Channel: ChannelStdout, Payload: []byte("x")}}

	deadline := time.Now().Add(20 * time.Second)
	for i := 0; i < 5000 && time.Now().Before(deadline); i++ {
		if i >= 200 && inboundFirst.Load() > 0 && outboundFirst.Load() > 0 {
			break
		}
		conn, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if be := p.runBridge(ctx, conn, outbox); be != nil {
			t.Fatalf("iteration %d: cancelled bridge reported %q, want clean", i, be.reason)
		}
		_ = conn.CloseNow()
	}
	if inboundFirst.Load() == 0 || outboundFirst.Load() == 0 {
		t.Fatalf("completion orders not both observed: inbound-first=%d outbound-first=%d",
			inboundFirst.Load(), outboundFirst.Load())
	}
}
