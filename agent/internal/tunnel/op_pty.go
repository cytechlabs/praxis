// PTY primitive (PRA-152 task #5c). Spawns one interactive shell
// (or any cmd) under a pseudo-terminal, streams raw bytes both
// directions over ChannelPty, and accepts pty_resize / pty_signal
// control frames over ChannelControl. Reuses exec's env policy and
// process-group cleanup model.
//
// Design lock notes:
//   - Explicit cmd required; no default shell.
//   - rows/cols default 24x80, clamped to [1, 1000].
//   - TERM defaults to xterm-256color when env doesn't set it.
//   - No agent-originated initial-window frame.
//   - Raw read-to-frame; no output coalescing in v1.
//   - Malformed binary envelope is bad_frame; malformed control JSON
//     inside a valid envelope is logged + ignored (advisory frames).

//go:build linux

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

const (
	defaultPtyRows uint16 = 24
	defaultPtyCols uint16 = 80
	maxPtyDim      uint16 = 1000
	defaultPtyTerm        = "xterm-256color"
	ptyOutChunk           = 32 * 1024
)

type ptyParams struct {
	cmd      string
	args     []string
	cwd      string
	env      []string
	rows     uint16
	cols     uint16
	timeout  time.Duration
	rejected string
}

// runPty validates params, spawns the child under a PTY, runs the
// bidirectional bridge + control loop, and returns the outcome.
func (p *opPump) runPty(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	pp := parsePtyParams(raw)
	if pp.rejected != "" {
		return opOutcomeError(pp.rejected)
	}

	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	if pp.timeout > 0 {
		var cancelTimeout context.CancelFunc
		execCtx, cancelTimeout = context.WithTimeout(execCtx, pp.timeout)
		defer cancelTimeout()
	}

	cmd := exec.CommandContext(execCtx, pp.cmd, pp.args...)
	cmd.Env = pp.env
	if pp.cwd != "" {
		cmd.Dir = pp.cwd
	}
	// Setsid is required for the child to take the PTY as its
	// controlling terminal; pty.StartWithSize handles allocating the
	// PTY but we still need session leadership for ctty semantics.
	// Setpgid is implied by Setsid (new session = new pgid). We rely
	// on -cmd.Process.Pid for kill since pgid == pid in this setup.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: pp.rows, Cols: pp.cols})
	if err != nil {
		p.log.Printf("op=%d pty start failed: %v", opID, err)
		return opOutcomeError("spawn_failed")
	}
	pgid := cmd.Process.Pid // setsid makes pgid == pid

	w := &opConnWriter{conn: conn}

	// Run outbound (master -> ChannelPty Data frames) in the MAIN
	// goroutine so master is always being actively read from the
	// moment we have it. Background it via a goroutine and the Go
	// scheduler may not schedule the outbound goroutine before a
	// fast-exiting child closes the slave — Linux PTY semantics
	// then drop any unread bytes from the buffer. cmd.Wait runs in
	// the background; we collect waitErr after master.Read returns
	// EIO/EOF (which it does once the slave fd refcount hits zero).
	inboundCtx, cancelInbound := context.WithCancel(execCtx)
	defer cancelInbound()

	var inboundErr error
	inboundDone := make(chan struct{})

	// Inbound: ChannelPty Data -> write to master; ChannelPty Close
	// -> close master (EOF to child); ChannelControl Data -> parse
	// pty_resize / pty_signal. Bad envelope = bad_frame (fatal);
	// bad control JSON = logged + ignored. Broker disconnect (any
	// non-ctx read error) -> op_stream_closed + cancelExec.
	go func() {
		defer close(inboundDone)
		err := p.ptyInbound(inboundCtx, conn, master, pgid)
		if err != nil {
			inboundErr = err
			// Kill the child so we don't leave the op running on a
			// poisoned / disconnected stream.
			cancelExec()
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	// Drive outbound until master returns EIO/EOF (slave closed,
	// child exited). This is the synchronisation point — we DO NOT
	// proceed past here until every available PTY byte has been
	// drained. Eliminates the race where a fast-exiting child loses
	// its trailing output to a not-yet-scheduled outbound goroutine.
	_ = ptyOutbound(execCtx, w, master)

	waitErr := <-waitCh
	// Kill the process group so any descendants spawned from the
	// shell die with the session. setsid set pgid == pid; -pid
	// targets the whole group.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)

	// Tear down inbound: cancel ctx so a pending conn.Read returns
	// with ctx.Err() set (returning nil from ptyInbound). Bounded so
	// a wedged inbound can't stall completion.
	cancelInbound()
	select {
	case <-inboundDone:
	case <-time.After(drainAfterKill):
		_ = master.Close() // last-resort backstop
		<-inboundDone
	}

	// Send a CLOSE on ChannelPty so the broker sees clean EOF.
	_ = w.writeFrame(context.Background(), Frame{Op: FrameOpClose, Channel: ChannelPty})

	// Graceful WSS close so broker drains the trailing screenful
	// before runOp's deferred CloseNow rips the TCP.
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelClose()
	_ = closeWSSGracefully(closeCtx, conn)

	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return opOutcomeCancelled()
	case pp.timeout > 0 && errors.Is(execCtx.Err(), context.DeadlineExceeded):
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
			return opOutcomeError("spawn_failed")
		}
	}
	return opOutcomeSuccessExit(exitCode)
}

// ptyInbound routes incoming frames. Returns non-nil on protocol
// violations (bad envelope); control-payload errors are advisory
// and only logged.
func (p *opPump) ptyInbound(
	ctx context.Context, conn *websocket.Conn, master *os.File, pgid int,
) error {
	masterClosed := false
	closeMaster := func() {
		if masterClosed {
			return
		}
		masterClosed = true
		_ = master.Close()
	}
	for {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			// ctx cancelled = clean teardown initiated by us after
			// cmd.Wait → benign, return nil.
			if ctx.Err() != nil {
				return nil
			}
			// Otherwise the broker is gone (clean close, TCP reset,
			// hangup) while the child may still be running. Surface
			// as op_stream_closed so the wrapper kills the child
			// instead of leaving a root process attached to a dead
			// transport.
			return errors.New("op_stream_closed")
		}
		if mt != websocket.MessageBinary {
			return errors.New("bad_frame")
		}
		f, derr := DecodeFrame(raw, p.maxFrame)
		if derr != nil {
			p.log.Printf("pty inbound: %v", derr)
			return errors.New("bad_frame")
		}
		switch f.Channel {
		case ChannelPty:
			switch f.Op {
			case FrameOpData:
				if _, werr := master.Write(f.Payload); werr != nil {
					// Master closed (child dead). Stop forwarding.
					closeMaster()
					return nil
				}
			case FrameOpClose:
				closeMaster()
			default:
				p.log.Printf("pty inbound: unexpected op 0x%02x on pty channel", uint8(f.Op))
			}
		case ChannelControl:
			if f.Op != FrameOpData {
				p.log.Printf("pty inbound: unexpected op 0x%02x on control", uint8(f.Op))
				continue
			}
			handlePtyControl(p.log, master, pgid, f.Payload)
		default:
			// Stdin/stdout/stderr/file have no meaning in a PTY
			// session — ignore with a log so a confused broker
			// doesn't poison the op.
			p.log.Printf("pty inbound: ignoring frame on channel 0x%02x", uint8(f.Channel))
		}
	}
}

func handlePtyControl(log Logger, master *os.File, pgid int, payload []byte) {
	var msg map[string]any
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("pty control: bad JSON: %v", err)
		return
	}
	switch t, _ := msg["type"].(string); t {
	case "pty_resize":
		rows, cols := readWinsize(msg)
		if rows == 0 || cols == 0 {
			log.Printf("pty control: resize out of range rows=%v cols=%v",
				msg["rows"], msg["cols"])
			return
		}
		if err := pty.Setsize(master, &pty.Winsize{Rows: rows, Cols: cols}); err != nil {
			log.Printf("pty control: resize failed: %v", err)
		}
	case "pty_signal":
		sigName, _ := msg["signal"].(string)
		sig, ok := allowedPtySignal(sigName)
		if !ok {
			log.Printf("pty control: unsupported signal %q", sigName)
			return
		}
		// kill the process group so backgrounded jobs in the shell
		// see the signal too.
		if err := syscall.Kill(-pgid, sig); err != nil {
			log.Printf("pty control: signal %s failed: %v", sigName, err)
		}
	default:
		log.Printf("pty control: unknown type %q", t)
	}
}

func readWinsize(msg map[string]any) (uint16, uint16) {
	rows, _ := msg["rows"].(float64)
	cols, _ := msg["cols"].(float64)
	if rows < 1 || rows > float64(maxPtyDim) {
		return 0, 0
	}
	if cols < 1 || cols > float64(maxPtyDim) {
		return 0, 0
	}
	return uint16(rows), uint16(cols)
}

func allowedPtySignal(name string) (syscall.Signal, bool) {
	switch name {
	case "INT":
		return syscall.SIGINT, true
	case "TERM":
		return syscall.SIGTERM, true
	case "QUIT":
		return syscall.SIGQUIT, true
	case "HUP":
		return syscall.SIGHUP, true
	}
	return 0, false
}

// ptyOutbound reads from the PTY master and emits one Data frame
// per read. Returns nil on EOF / closed master / cancellation.
func ptyOutbound(ctx context.Context, w *opConnWriter, master *os.File) error {
	buf := make([]byte, ptyOutChunk)
	for {
		n, rerr := master.Read(buf)
		if n > 0 {
			err := w.writeFrame(ctx, Frame{
				Op: FrameOpData, Channel: ChannelPty,
				Payload: append([]byte(nil), buf[:n]...),
			})
			if err != nil {
				return err
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || isPipeClosed(rerr) || errors.Is(rerr, context.Canceled) {
				return nil
			}
			// PTY master closed by us during teardown — also benign.
			if strings.Contains(rerr.Error(), "input/output error") {
				return nil
			}
			return rerr
		}
	}
}

// parsePtyParams reuses the exec env model with PTY-specific extras.
func parsePtyParams(raw map[string]any) ptyParams {
	var p ptyParams
	cmd, _ := raw["cmd"].(string)
	if cmd == "" {
		p.rejected = "invalid_params"
		return p
	}
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
	term, _ := raw["term"].(string)
	if term == "" {
		term = defaultPtyTerm
	}
	if envM, ok := raw["env"].(map[string]any); ok {
		havePATH, haveTERM := false, false
		for k, v := range envM {
			s, ok := v.(string)
			if !ok {
				p.rejected = "invalid_params"
				return p
			}
			switch k {
			case "PATH":
				havePATH = true
			case "TERM":
				haveTERM = true
			}
			p.env = append(p.env, k+"="+s)
		}
		if !havePATH {
			p.env = append(p.env, "PATH="+safeDefaultPath)
		}
		if !haveTERM {
			p.env = append(p.env, "TERM="+term)
		}
	} else {
		path := os.Getenv("PATH")
		if path == "" {
			path = safeDefaultPath
		}
		p.env = []string{
			"PATH=" + path,
			"LANG=C.UTF-8",
			"TERM=" + term,
		}
	}
	rows, cols := defaultPtyRows, defaultPtyCols
	if r, ok := raw["rows"].(float64); ok && r >= 1 && r <= float64(maxPtyDim) {
		rows = uint16(r)
	}
	if c, ok := raw["cols"].(float64); ok && c >= 1 && c <= float64(maxPtyDim) {
		cols = uint16(c)
	}
	p.rows = rows
	p.cols = cols
	if t, ok := raw["timeout_s"].(float64); ok && t > 0 {
		p.timeout = time.Duration(t * float64(time.Second))
	}
	return p
}
