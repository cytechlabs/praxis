// Exec primitive (PRA-152 task #5a). Runs one non-PTY command,
// streams stdin/stdout/stderr over the per-op WSS, and reports the
// exit code in op_complete. No shell, no user switching, no env
// merge — see op_exec.go's runExec doc for the full contract.

//go:build linux

package tunnel

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

// safeDefaultPath is what we hand the child when caller didn't pin
// a PATH. Matches Debian /etc/login.defs minimum so common admin
// commands resolve without leaking the agent's full env.
const safeDefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// stdoutChunk caps how much pipe data we put in one frame. Small
// enough to keep latency low for interactive output; well under the
// 1 MiB frame cap so backpressure shows up as Write blocking on the
// socket rather than as a pipe-stall.
const stdoutChunk = 32 * 1024

// drainAfterKill bounds how long we wait for the child's stdout/
// stderr pipes to flush after we kill it. Without this, a wedged
// pipe could keep the op goroutine alive indefinitely after cancel.
const drainAfterKill = 250 * time.Millisecond

type execParams struct {
	cmd      string
	args     []string
	cwd      string
	env      []string
	timeout  time.Duration
	rejected string // non-empty when params failed validation
}

// runExec validates params, spawns the process, runs the bridge,
// and returns an opOutcome the caller posts as op_complete. The
// connection's deferred CloseNow at the runOp layer handles WSS
// teardown.
func (p *opPump) runExec(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	ep := parseExecParams(raw)
	if ep.rejected != "" {
		return opOutcomeError(ep.rejected)
	}

	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	if ep.timeout > 0 {
		var cancelTimeout context.CancelFunc
		execCtx, cancelTimeout = context.WithTimeout(execCtx, ep.timeout)
		defer cancelTimeout()
	}

	cmd := exec.CommandContext(execCtx, ep.cmd, ep.args...)
	cmd.Env = ep.env
	if ep.cwd != "" {
		cmd.Dir = ep.cwd
	}
	// New process group so we can SIGKILL the whole tree on cancel.
	// Without this, the child's children outlive the op.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return opOutcomeError("spawn_failed")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return opOutcomeError("spawn_failed")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return opOutcomeError("spawn_failed")
	}
	// Backstop closers: we may need to forcibly close the pipe read
	// ends after the drain timeout to unblock pumpPipe goroutines
	// stuck in a blocking syscall on the underlying fd. Context
	// cancellation does NOT unblock kernel pipe reads — only closing
	// the fd does. Wait() closes the WRITE end internally, but if a
	// grandchild was reparented (e.g. setsid) and still holds its own
	// write fd, our read end stays open until we close it ourselves.
	stdoutCloser := stdout
	stderrCloser := stderr

	if err := cmd.Start(); err != nil {
		p.log.Printf("op=%d exec start failed: %v", opID, err)
		return opOutcomeError("spawn_failed")
	}
	pgid := cmd.Process.Pid // setpgid makes pgid == pid

	// Per-op WSS writer mutex (websockets is single-writer; stdout
	// + stderr pumps both produce frames concurrently).
	w := &opConnWriter{conn: conn}

	bridgeCtx, cancelBridge := context.WithCancel(execCtx)
	defer cancelBridge()

	var (
		inboundErr  error
		stdinClosed bool
		mu          sync.Mutex
	)
	closeStdinOnce := func() {
		mu.Lock()
		defer mu.Unlock()
		if stdinClosed {
			return
		}
		stdinClosed = true
		_ = stdin.Close()
	}
	defer closeStdinOnce()

	// Inbound runs in a goroutine because it reads from conn (WSS),
	// independent of the child's pipes.
	inboundDone := make(chan struct{})
	go func() {
		defer close(inboundDone)
		err := p.execInbound(bridgeCtx, conn, stdin, closeStdinOnce)
		if err != nil {
			mu.Lock()
			if inboundErr == nil {
				inboundErr = err
			}
			mu.Unlock()
			cancelExec()
		}
	}()

	// Outbound pumps: stdout + stderr. We MUST drain these before
	// cmd.Wait — Wait closes the parent's pipe read ends, which can
	// make pump.Read return EOF before the goroutine has read any
	// data the child wrote (especially under low GOMAXPROCS where
	// the pump goroutine may not run until after the child has
	// exited and Wait is racing to close the pipes). Run pumps in
	// goroutines, but hold cmd.Wait until both pumps return.
	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		_ = pumpPipe(bridgeCtx, w, stdout, ChannelStdout, p.maxFrame)
	}()
	go func() {
		defer close(stderrDone)
		_ = pumpPipe(bridgeCtx, w, stderr, ChannelStderr, p.maxFrame)
	}()

	// Wait for both pumps to return (pipe EOF after child closes its
	// write ends), then call cmd.Wait to reap. If the bridge context
	// is cancelled (op_cancel, timeout, inbound protocol error), the
	// process is killed via execCtx → exec.CommandContext, slave
	// pipes close, pumps exit naturally.
	pumpsDone := make(chan struct{})
	go func() {
		<-stdoutDone
		<-stderrDone
		close(pumpsDone)
	}()
	// Normal path: wait indefinitely for pumps to drain via natural
	// pipe EOF after the child exits.
	// Cancel/timeout path: bridgeCtx fires; give pumps a short window
	// to drain whatever's left, then force the read ends closed so a
	// grandchild holding a write fd can't stall us forever.
	select {
	case <-pumpsDone:
	case <-bridgeCtx.Done():
		select {
		case <-pumpsDone:
		case <-time.After(drainAfterKill):
			_ = stdoutCloser.Close()
			_ = stderrCloser.Close()
			<-pumpsDone
		}
	}

	waitErr := cmd.Wait()
	// Kill stragglers (grandchildren in the process group).
	_ = syscall.Kill(-pgid, syscall.SIGKILL)

	// Tear down inbound: cancelBridge wakes ptyInbound's conn.Read
	// (returns ctx-cancelled, returns nil). Bounded wait so a wedged
	// inbound can't stall completion.
	cancelBridge()
	closeStdinOnce()
	select {
	case <-inboundDone:
	case <-time.After(drainAfterKill):
	}

	// Send CLOSE on stdout + stderr so broker sees clean EOF.
	_ = w.writeFrame(context.Background(), Frame{Op: FrameOpClose, Channel: ChannelStdout})
	_ = w.writeFrame(context.Background(), Frame{Op: FrameOpClose, Channel: ChannelStderr})

	// Graceful WSS close so the broker drains buffered frames before
	// runOp's deferred CloseNow rips the underlying TCP. Bounded so a
	// non-responsive broker can't stall us.
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelClose()
	_ = closeWSSGracefully(closeCtx, conn)

	// Outcome resolution:
	//   - parent ctx cancelled (user op_cancel) → cancelled.
	//     runOp's caller-level check also enforces this; we set it
	//     here so the exit_code field stays nil.
	//   - timeout fired → error/timeout.
	//   - inbound protocol error → error/<reason>.
	//   - normal exit (zero or not) → success/<exit_code>.
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return opOutcomeCancelled()
	case ep.timeout > 0 && errors.Is(execCtx.Err(), context.DeadlineExceeded):
		return opOutcomeError("timeout")
	case inboundErr != nil:
		return opOutcomeError(inboundErr.Error())
	}
	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			// Wait failed for a non-exit reason (e.g. broken pipe to
			// child setup). Treat as runtime error.
			return opOutcomeError("spawn_failed")
		}
	}
	return opOutcomeSuccessExit(exitCode)
}

// parseExecParams pulls validated values out of the JSON params map.
// On failure, sets rejected to the op_complete reason and returns.
func parseExecParams(raw map[string]any) execParams {
	var p execParams
	cmd, _ := raw["cmd"].(string)
	if cmd == "" {
		p.rejected = "invalid_params"
		return p
	}
	// cmd is taken verbatim: exec.Command treats names without "/"
	// as PATH-resolvable and absolute/relative paths as literal.
	p.cmd = cmd
	if a, ok := raw["args"].([]any); ok {
		for _, v := range a {
			s, ok := v.(string)
			if !ok {
				p.rejected = "invalid_params"
				return p
			}
			p.args = append(p.args, s)
		}
	}
	if cwd, ok := raw["cwd"].(string); ok && cwd != "" {
		if !strings.HasPrefix(cwd, "/") {
			p.rejected = "invalid_params"
			return p
		}
		p.cwd = cwd
	}
	if envM, ok := raw["env"].(map[string]any); ok {
		havePATH := false
		for k, v := range envM {
			s, ok := v.(string)
			if !ok {
				p.rejected = "invalid_params"
				return p
			}
			if k == "PATH" {
				havePATH = true
			}
			p.env = append(p.env, k+"="+s)
		}
		if !havePATH {
			p.env = append(p.env, "PATH="+safeDefaultPath)
		}
	} else {
		// No env supplied: minimal safe default — PATH (from agent
		// if set, else /etc/login.defs minimum) + LANG=C.UTF-8.
		path := os.Getenv("PATH")
		if path == "" {
			path = safeDefaultPath
		}
		p.env = []string{"PATH=" + path, "LANG=C.UTF-8"}
	}
	if t, ok := raw["timeout_s"].(float64); ok && t > 0 {
		p.timeout = time.Duration(t * float64(time.Second))
	}
	return p
}

// pumpPipe reads from a child pipe and writes Data frames on the
// given channel. Returns nil on EOF (normal); cancellation and
// pipe-broken errors are also normal here. Real WSS write failures
// are returned but the caller currently only logs them — outcome
// resolution lives in runExec.
func pumpPipe(ctx context.Context, w *opConnWriter, r io.ReadCloser, ch Channel, maxFrame int) error {
	defer r.Close() //nolint:errcheck
	if maxFrame <= 0 {
		maxFrame = DefaultMaxFramePayload
	}
	chunk := stdoutChunk
	if chunk > maxFrame {
		chunk = maxFrame
	}
	buf := make([]byte, chunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := w.writeFrame(ctx, Frame{
				Op: FrameOpData, Channel: ch, Payload: append([]byte(nil), buf[:n]...),
			}); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || isPipeClosed(err) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

func isPipeClosed(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "file already closed") ||
		strings.Contains(err.Error(), "broken pipe"))
}

// execInbound reads frames from the per-op WSS and routes them.
// Stdin Data → write to child stdin. Stdin Close → EOF on stdin.
// Bad frames or frames on unsupported channels for exec produce a
// bridgeErr-equivalent (error string returned), which causes the
// op to fail with that reason.
func (p *opPump) execInbound(
	ctx context.Context, conn *websocket.Conn, stdin io.WriteCloser, closeStdin func(),
) error {
	for {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Broker closed the per-op WSS abnormally; not a protocol
			// violation we can pin on the broker, but the op can't
			// continue without inbound either. Surface as op_stream_closed.
			return errors.New("op_stream_closed")
		}
		if mt != websocket.MessageBinary {
			// Spec: per-op WSS frames are binary. Tolerate stray text.
			continue
		}
		f, err := DecodeFrame(raw, p.maxFrame)
		if err != nil {
			p.log.Printf("exec inbound: %v", err)
			return errors.New("bad_frame")
		}
		switch f.Channel {
		case ChannelStdin:
			switch f.Op {
			case FrameOpData:
				if _, werr := stdin.Write(f.Payload); werr != nil {
					// Child closed stdin (EPIPE) — not an error from
					// our side; just stop forwarding stdin.
					closeStdin()
					// Drain remaining inbound until ctx ends so the
					// broker doesn't see TCP backpressure.
					return drainInbound(ctx, conn)
				}
			case FrameOpClose:
				closeStdin()
			default:
				// Error/CancelAck on stdin from broker is unexpected;
				// log and ignore (forward-compat).
				p.log.Printf("exec inbound: unexpected op 0x%02x on stdin", uint8(f.Op))
			}
		default:
			// Other channels (control, etc.) — no exec-specific
			// signals defined in #5a; ignore.
		}
	}
}

// drainInbound reads-and-drops until ctx ends, after the child has
// closed stdin. Keeps the WSS healthy (back-pressure-free) while we
// wait for stdout/stderr to finish.
func drainInbound(ctx context.Context, conn *websocket.Conn) error {
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return nil // benign — broker closed; not our concern now
		}
	}
}
