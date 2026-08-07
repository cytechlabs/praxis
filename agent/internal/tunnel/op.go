// Op orchestration on the agent side (PRA-152 task #4).
//
// Recv loop in tunnel.go forwards op_request / op_nonce / op_cancel
// here. We pair request + nonce by operation_id (order-agnostic),
// dial /agent/op with X-Praxis-Op-Nonce, send op_attach, run the
// frame pump, and post op_complete on the control WSS when the op
// terminates. op_cancel from the broker cancels the per-op context,
// closes the per-op WSS, and posts op_complete(cancelled).
//
// Stub behavior (Q1-B from the design lock): every op writes a
// single STDOUT frame `stub: op_type=<X>` followed by CLOSE, then
// reports op_complete(success). Real exec / pty / file primitives
// land in PRA-152 task #5+.
//
// Protocol error tightening:
//
//   - Failure to dial /agent/op after receiving the nonce reports
//     op_complete(error, reason="op_dial_failed").
//   - Frame decode failure during the bridge reports
//     op_complete(error, reason="bad_frame").
//   - Per-op WSS abnormal close before our outbound finishes reports
//     op_complete(error, reason="op_stream_closed").
//   - op_cancel reports op_complete(cancelled).
//   - Only a clean, completed outbound run reports op_complete(success).

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// DefaultOpPairTimeout is how long an unpaired op_request or op_nonce
// is held before we drop it. Configurable for tests.
const DefaultOpPairTimeout = 5 * time.Second

// stubExtraDelayForTests injects an artificial pause inside the stub
// before frames are written, giving cancel-during-op tests a
// deterministic window to deliver op_cancel. Production code never
// touches this; only the test in op_test.go sets it.
var stubExtraDelayForTests time.Duration

// controlSender writes a JSON message on the control WSS. The pump
// uses it for op_complete; the heartbeat loop uses it for its own
// payloads. Implementation must be safe for concurrent callers
// (websockets requires single-writer semantics; controlWriter
// serialises with a mutex).
type controlSender func(ctx context.Context, msg map[string]any) error

type opPump struct {
	cfg         Config
	tlsCfg      *tls.Config
	sendCtl     controlSender
	log         Logger
	maxFrame    int
	pairTimeout time.Duration

	mu      sync.Mutex
	pending map[int]*pendingOp
	active  map[int]*activeOp
}

func newOpPump(cfg Config, tlsCfg *tls.Config, send controlSender, log Logger, pair time.Duration) *opPump {
	if pair <= 0 {
		pair = DefaultOpPairTimeout
	}
	return &opPump{
		cfg:         cfg,
		tlsCfg:      tlsCfg,
		sendCtl:     send,
		log:         log,
		maxFrame:    DefaultMaxFramePayload,
		pairTimeout: pair,
		pending:     make(map[int]*pendingOp),
		active:      make(map[int]*activeOp),
	}
}

// pendingOp holds the half-state we received first, waiting for its
// counterpart to arrive. Either request or nonce will be set. When
// op_cancel arrives during the pending window we mark cancelled so
// the late counterpart is dropped (we already reported op_complete
// to the broker; starting the op now would be a protocol violation).
type pendingOp struct {
	request   map[string]any
	nonce     string
	timer     *time.Timer
	cancelled bool
}

type activeOp struct {
	cancel context.CancelFunc
}

// handleControl is called by tunnel.go's recv loop when the message
// type is op_request, op_nonce, or op_cancel. ctx is the lifecycle
// context — when it cancels (tunnel torn down) any in-flight ops
// die with it.
func (p *opPump) handleControl(ctx context.Context, msg map[string]any) {
	switch t, _ := msg["type"].(string); t {
	case "op_request":
		opID, ok := intField(msg, "operation_id")
		if !ok {
			p.log.Printf("op_request missing operation_id; ignoring")
			return
		}
		p.acceptRequest(ctx, opID, msg)
	case "op_nonce":
		opID, ok := intField(msg, "operation_id")
		if !ok {
			p.log.Printf("op_nonce missing operation_id; ignoring")
			return
		}
		nonce, _ := msg["nonce"].(string)
		if nonce == "" {
			p.log.Printf("op_nonce missing nonce field for op=%d; ignoring", opID)
			return
		}
		p.acceptNonce(ctx, opID, nonce)
	case "op_cancel":
		opID, ok := intField(msg, "operation_id")
		if !ok {
			p.log.Printf("op_cancel missing operation_id; ignoring")
			return
		}
		p.cancelOp(opID)
	}
}

// shutdown cancels every active op + tears down pending pairings.
// Called when the tunnel is closing so we don't leak goroutines.
func (p *opPump) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for opID, a := range p.active {
		a.cancel()
		delete(p.active, opID)
	}
	for opID, pend := range p.pending {
		if pend.timer != nil {
			pend.timer.Stop()
		}
		delete(p.pending, opID)
	}
}

func (p *opPump) acceptRequest(ctx context.Context, opID int, msg map[string]any) {
	p.mu.Lock()
	if _, alreadyActive := p.active[opID]; alreadyActive {
		p.mu.Unlock()
		p.log.Printf("op_request op=%d duplicate (already active); ignoring", opID)
		return
	}
	pend, exists := p.pending[opID]
	if exists {
		if pend.cancelled {
			pend.request = msg
			p.mu.Unlock()
			p.log.Printf("op_request op=%d arrived after cancel; dropping", opID)
			return
		}
		if pend.request != nil {
			// Duplicate request — keep the original, don't start a
			// second goroutine.
			p.mu.Unlock()
			p.log.Printf("op_request op=%d duplicate (already pending); ignoring", opID)
			return
		}
		// Nonce arrived first; this completes the pair.
		pend.request = msg
		nonce := pend.nonce
		if pend.timer != nil {
			pend.timer.Stop()
		}
		delete(p.pending, opID)
		p.mu.Unlock()
		p.startOp(ctx, opID, msg, nonce)
		return
	}
	// Lone request — wait for nonce.
	pp := &pendingOp{request: msg}
	pp.timer = time.AfterFunc(p.pairTimeout, func() { p.expirePending(opID) })
	p.pending[opID] = pp
	p.mu.Unlock()
}

func (p *opPump) acceptNonce(ctx context.Context, opID int, nonce string) {
	p.mu.Lock()
	if _, alreadyActive := p.active[opID]; alreadyActive {
		p.mu.Unlock()
		p.log.Printf("op_nonce op=%d duplicate (already active); ignoring", opID)
		return
	}
	pend, exists := p.pending[opID]
	if exists {
		if pend.cancelled {
			pend.nonce = nonce
			p.mu.Unlock()
			p.log.Printf("op_nonce op=%d arrived after cancel; dropping", opID)
			return
		}
		if pend.nonce != "" {
			p.mu.Unlock()
			p.log.Printf("op_nonce op=%d duplicate (already pending); ignoring", opID)
			return
		}
		pend.nonce = nonce
		req := pend.request
		if pend.timer != nil {
			pend.timer.Stop()
		}
		delete(p.pending, opID)
		p.mu.Unlock()
		p.startOp(ctx, opID, req, nonce)
		return
	}
	pp := &pendingOp{nonce: nonce}
	pp.timer = time.AfterFunc(p.pairTimeout, func() { p.expirePending(opID) })
	p.pending[opID] = pp
	p.mu.Unlock()
}

func (p *opPump) expirePending(opID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pend, ok := p.pending[opID]
	if !ok {
		return
	}
	delete(p.pending, opID)
	if pend.cancelled {
		// Already reported op_complete(cancelled); nothing to log.
		return
	}
	have := "request"
	if pend.nonce != "" {
		have = "nonce"
	}
	p.log.Printf("op=%d half-state %q expired after %s; dropping", opID, have, p.pairTimeout)
}

func (p *opPump) cancelOp(opID int) {
	p.mu.Lock()
	if a, ok := p.active[opID]; ok {
		a.cancel()
		p.mu.Unlock()
		// Don't delete here — the goroutine cleans up via deferred
		// finishActive() and sends op_complete(cancelled) itself.
		return
	}
	if pend, ok := p.pending[opID]; ok {
		// Mark cancelled but keep the entry so a late counterpart is
		// absorbed (and dropped) rather than starting the op after we
		// already reported it complete. The timer cleans up silently.
		pend.cancelled = true
		p.mu.Unlock()
		p.log.Printf("op=%d cancel arrived during pending; reporting cancelled", opID)
		go p.sendCancelledForPending(opID)
		return
	}
	p.mu.Unlock()
	p.log.Printf("op=%d cancel for unknown operation; ignoring", opID)
}

// sendCancelledForPending posts op_complete(cancelled) when op_cancel
// arrives before the pending op ever became active. Runs off the
// pump mutex so a slow control-WSS write can't stall the recv loop.
func (p *opPump) sendCancelledForPending(opID int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := opOutcomeCancelled().toMessage(opID, 0)
	if err := p.sendCtl(ctx, msg); err != nil {
		p.log.Printf("op=%d op_complete(cancelled) send failed: %v", opID, err)
	}
}

func (p *opPump) startOp(parent context.Context, opID int, request map[string]any, nonce string) {
	opType, _ := request["op_type"].(string)
	params, _ := request["params"].(map[string]any)
	opCtx, cancel := context.WithCancel(parent)
	p.mu.Lock()
	p.active[opID] = &activeOp{cancel: cancel}
	p.mu.Unlock()
	go p.runOp(opCtx, opID, opType, nonce, params)
}

func (p *opPump) finishActive(opID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, opID)
}

// runOp owns one operation end-to-end: dial, attach, dispatch by
// op_type, op_complete. Always exits via the deferred sender so
// EVERY op gets exactly one op_complete on the control WSS.
//
// Defer ordering matters (PRA-155 #2b-a). Defers fire LIFO, and the
// broker terminalizes the op on clean per-op WSS close BEFORE it
// processes the control-WSS op_complete. If we deferred conn.CloseNow
// separately, it would fire FIRST, the broker would mark the op
// completed without result_metadata, and the later op_complete carrying
// inline result fields (facts payload, exit_code, etc.) would be
// dropped. The unified defer below sends op_complete first, then closes
// the per-op WSS — closing the race for every op_type, not just facts.
func (p *opPump) runOp(ctx context.Context, opID int, opType, nonce string, params map[string]any) {
	defer p.finishActive(opID)

	start := time.Now()
	var outcome opOutcome
	var conn *websocket.Conn

	defer func() {
		// Use parent-of-ctx for the op_complete send so a cancelled
		// op still reports completion. If the tunnel itself is gone
		// the send fails harmlessly; we log and move on.
		sendCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		msg := outcome.toMessage(opID, time.Since(start))
		if err := p.sendCtl(sendCtx, msg); err != nil {
			p.log.Printf("op=%d op_complete send failed: %v", opID, err)
		}
		// Per-op WSS close happens AFTER op_complete is on the wire,
		// so the broker has already routed inline result fields into
		// op.result_metadata before its /agent/op handler sees the
		// clean close and terminalizes the op.
		if conn != nil {
			_ = conn.CloseNow()
		}
	}()

	opURL := strings.TrimSuffix(p.cfg.BrokerURL, "/") + "/agent/op"
	dialOpts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: p.tlsCfg},
		},
		HTTPHeader: http.Header{"X-Praxis-Op-Nonce": []string{nonce}},
	}
	var err error
	conn, _, err = websocket.Dial(ctx, opURL, dialOpts)
	if err != nil {
		p.log.Printf("op=%d dial /agent/op failed: %v", opID, err)
		outcome = opOutcomeError("op_dial_failed")
		return
	}
	conn.SetReadLimit(int64(DefaultMaxFramePayload + FrameHeaderSize + 1024))

	// op_attach is JSON text per spec; subsequent frames are binary.
	attach, _ := json.Marshal(map[string]any{
		"type":         "op_attach",
		"operation_id": opID,
	})
	if err := conn.Write(ctx, websocket.MessageText, attach); err != nil {
		p.log.Printf("op=%d op_attach send failed: %v", opID, err)
		outcome = opOutcomeError("op_stream_closed")
		return
	}

	// Dispatch by op_type. Each handler owns its own bridge and is
	// responsible for closing inbound + outbound frames cleanly. The
	// returned outcome is what we report on op_complete; the handler
	// is allowed to return zero opOutcome only when ctx was cancelled
	// (we map that to opOutcomeCancelled below).
	switch opType {
	case "exec":
		outcome = p.runExec(ctx, opID, conn, params)
	case "file_get":
		outcome = p.runFileGet(ctx, opID, conn, params)
	case "file_put":
		outcome = p.runFilePut(ctx, opID, conn, params)
	case "pty":
		outcome = p.runPty(ctx, opID, conn, params)
	case "facts":
		outcome = p.runFacts(ctx, opID, conn, params)
	default:
		outcome = p.runStub(ctx, opID, conn, opType)
	}

	// If ctx cancelled and the handler reported success/error from
	// torn-down state, override with cancelled — op_cancel always wins.
	if errors.Is(ctx.Err(), context.Canceled) && outcome.outcome != "error" {
		outcome = opOutcomeCancelled()
	}
}

// runStub is the placeholder handler for op_types we don't implement
// yet. Writes "stub: op_type=<X>" on STDOUT then CLOSE and returns
// success. Used by tests; will go away when all op_types are real.
func (p *opPump) runStub(ctx context.Context, opID int, conn *websocket.Conn, opType string) opOutcome {
	stub := []byte(fmt.Sprintf("stub: op_type=%s", opType))
	outbox := []Frame{
		{Op: FrameOpData, Channel: ChannelStdout, Payload: stub},
		{Op: FrameOpClose, Channel: ChannelStdout, Payload: nil},
	}
	if d := stubExtraDelayForTests; d > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}
	if be := p.runBridge(ctx, conn, outbox); be != nil {
		return opOutcomeError(be.reason)
	}
	return opOutcomeSuccess()
}

// bridgeErr carries a reason code matching the spec's op_complete.error.reason.
type bridgeErr struct{ reason string }

// runBridge runs send + recv concurrently on the per-op WSS. Sender
// pushes the supplied outbox; receiver decodes inbound frames (logged
// at debug volume for the stub). First failure wins; the other side
// is cancelled and drained. Returns nil iff outbound completed
// without protocol error.
func (p *opPump) runBridge(ctx context.Context, conn *websocket.Conn, outbox []Frame) *bridgeErr {
	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	outErrCh := make(chan *bridgeErr, 1)
	inErrCh := make(chan *bridgeErr, 1)
	go func() { outErrCh <- p.opOutboundLoop(bridgeCtx, conn, outbox) }()
	go func() { inErrCh <- p.opInboundLoop(bridgeCtx, conn) }()

	// Inbound protocol errors fail-fast so a malicious or buggy peer
	// can't keep us pumping into a poisoned stream. Outbound errors
	// (write failures) propagate the same way.
	var outboundErr, inboundErr *bridgeErr
	select {
	case outboundErr = <-outErrCh:
		cancel()
		inboundErr = <-inErrCh
	case e := <-inErrCh:
		if e != nil {
			cancel()
			<-outErrCh
			return e
		}
		// Inbound returned nil (clean) — wait for outbound.
		outboundErr = <-outErrCh
	}
	if outboundErr != nil {
		return outboundErr
	}
	return inboundErr
}

func (p *opPump) opOutboundLoop(ctx context.Context, conn *websocket.Conn, outbox []Frame) *bridgeErr {
	for _, f := range outbox {
		if ctx.Err() != nil {
			return nil
		}
		wire, err := EncodeFrame(f, p.maxFrame)
		if err != nil {
			p.log.Printf("op outbound: encode %v", err)
			return &bridgeErr{reason: "op_stream_closed"}
		}
		if err := conn.Write(ctx, websocket.MessageBinary, wire); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return &bridgeErr{reason: "op_stream_closed"}
		}
	}
	return nil
}

func (p *opPump) opInboundLoop(ctx context.Context, conn *websocket.Conn) *bridgeErr {
	for {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Cancelled by us — clean shutdown, not an error.
				return nil
			}
			return &bridgeErr{reason: "op_stream_closed"}
		}
		if mt != websocket.MessageBinary {
			// Spec: per-op WSS frames are binary. Tolerate but
			// don't try to decode text frames (server might send
			// unexpected JSON during edge cases).
			continue
		}
		f, err := DecodeFrame(raw, p.maxFrame)
		if err != nil {
			p.log.Printf("op inbound: %v", err)
			return &bridgeErr{reason: "bad_frame"}
		}
		// Stub: log + drop. Real handlers live in PRA-152 task #5+.
		_ = f
	}
}

// ----- op_complete shape per the locked broker spec -----

type opOutcome struct {
	outcome  string
	exitCode *int   // nil when not applicable
	error    *opErr // nil for success
	// extra carries op-type-specific top-level fields on op_complete.
	// The broker's _route_op_complete captures any top-level keys
	// outside {type, operation_id, outcome, error} into
	// op.result_metadata, so adding new fields here does not require
	// changes on the Python side. Used by op_type=facts to return
	// inline facts + partial_errors without a per-op stream.
	extra map[string]any
}

type opErr struct {
	Reason string `json:"reason"`
}

func (o opOutcome) toMessage(opID int, dur time.Duration) map[string]any {
	msg := map[string]any{
		"type":         "op_complete",
		"operation_id": opID,
		"outcome":      o.outcome,
		"duration_ms":  dur.Milliseconds(),
	}
	if o.exitCode != nil {
		msg["exit_code"] = *o.exitCode
	} else {
		msg["exit_code"] = nil
	}
	if o.error != nil {
		msg["error"] = o.error
	} else {
		msg["error"] = nil
	}
	for k, v := range o.extra {
		// Reserved wire keys must not be overridden by handler extras.
		switch k {
		case "type", "operation_id", "outcome", "error", "exit_code", "duration_ms":
			continue
		}
		msg[k] = v
	}
	return msg
}

func opOutcomeSuccess() opOutcome {
	zero := 0
	return opOutcome{outcome: "success", exitCode: &zero}
}

func opOutcomeSuccessExit(code int) opOutcome {
	c := code
	return opOutcome{outcome: "success", exitCode: &c}
}

func opOutcomeCancelled() opOutcome {
	// exit_code intentionally nil per spec ("omitted or null").
	return opOutcome{outcome: "cancelled"}
}

func opOutcomeError(reason string) opOutcome {
	return opOutcome{outcome: "error", error: &opErr{Reason: reason}}
}

// intField extracts an int from a JSON-decoded message map. JSON
// numbers come in as float64; we reject anything else so a typo'd
// "operation_id":"12" surfaces as a missing field, not 0.
func intField(msg map[string]any, key string) (int, bool) {
	v, ok := msg[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}
