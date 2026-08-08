package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ---------------------------------------------------------------------------
// Frame envelope unit tests (mirror PRA-151 task #16 broker tests)
// ---------------------------------------------------------------------------

func TestFrameRoundTrip(t *testing.T) {
	f := Frame{Op: FrameOpData, Channel: ChannelStdout, Payload: []byte("hello world")}
	wire, err := EncodeFrame(f, DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeFrame(wire, DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Op != f.Op || got.Channel != f.Channel || string(got.Payload) != string(f.Payload) {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, f)
	}
}

func TestFrameRoundTripEmptyPayload(t *testing.T) {
	f := Frame{Op: FrameOpClose, Channel: ChannelControl, Payload: nil}
	wire, err := EncodeFrame(f, DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeFrame(wire, DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Op != FrameOpClose || got.Channel != ChannelControl || len(got.Payload) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestFrameEncodeRefusesOversize(t *testing.T) {
	f := Frame{Op: FrameOpData, Channel: ChannelStdout, Payload: make([]byte, 200)}
	if _, err := EncodeFrame(f, 100); err == nil {
		t.Fatal("expected oversize error on encode")
	}
}

func TestFrameDecodeRefusesOversizeDeclared(t *testing.T) {
	wire, err := EncodeFrame(Frame{Op: FrameOpData, Channel: ChannelStdout, Payload: make([]byte, 200)}, DefaultMaxFramePayload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeFrame(wire, 100); err == nil {
		t.Fatal("expected oversize error on decode")
	}
}

func TestFrameDecodeUnknownOp(t *testing.T) {
	bad := []byte{1, 0xFE, 1, 0, 0, 0, 0, 0}
	if _, err := DecodeFrame(bad, DefaultMaxFramePayload); err == nil {
		t.Fatal("expected unknown op error")
	}
}

func TestFrameDecodeUnknownChannel(t *testing.T) {
	bad := []byte{1, 1, 0xFE, 0, 0, 0, 0, 0}
	if _, err := DecodeFrame(bad, DefaultMaxFramePayload); err == nil {
		t.Fatal("expected unknown channel error")
	}
}

func TestFrameDecodeShortBuffer(t *testing.T) {
	if _, err := DecodeFrame([]byte{1, 1, 1}, DefaultMaxFramePayload); err == nil {
		t.Fatal("expected short-buffer error")
	}
}

func TestFrameDecodeLengthMismatch(t *testing.T) {
	wire := []byte{1, 1, 1, 0, 0, 0, 0, 10}
	wire = append(wire, []byte("abcde")...)
	if _, err := DecodeFrame(wire, DefaultMaxFramePayload); err == nil {
		t.Fatal("expected length-mismatch error")
	}
}

// ---------------------------------------------------------------------------
// Op-orchestration end-to-end tests
//
// We stand up an httptest server that serves /agent/tunnel + /agent/op
// off the same listener, then drive the agent through Run() against it.
// ---------------------------------------------------------------------------

// dualBroker is a single http.Handler that routes /agent/tunnel and
// /agent/op to per-test scripts. Lets a test orchestrate both ends
// from one place.
type dualBroker struct {
	t *testing.T

	tunnelScript func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any)
	opScript     func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request)

	// correlateOps replaces opScript on /agent/op with a handler that
	// reads the leading op_attach itself, so the nonce presented in the
	// request header and the operation ID announced on that same
	// connection are recorded as one pair. Tests that assert nonce
	// routing set this instead of supplying an opScript.
	correlateOps bool

	tunnelConns atomic.Int32
	opConns     atomic.Int32

	mu        sync.Mutex
	opRecords []opConnRecord
}

// opConnRecord is one accepted /agent/op connection: the nonce the
// agent presented in X-Praxis-Op-Nonce paired with the operation ID it
// announced in op_attach on that same connection. err is set instead of
// opID when the connection never produced a usable op_attach.
type opConnRecord struct {
	nonce string
	opID  int
	err   error
}

func (d *dualBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/agent/tunnel":
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.SetReadLimit(int64(DefaultMaxFramePayload + FrameHeaderSize + 1024))
		defer c.CloseNow() //nolint:errcheck
		d.tunnelConns.Add(1)
		// Read hello + send a minimal welcome.
		mt, raw, err := c.Read(r.Context())
		if err != nil || mt != websocket.MessageText {
			return
		}
		var hello map[string]any
		_ = json.Unmarshal(raw, &hello)
		welcome, _ := json.Marshal(map[string]any{
			"type":                       "welcome",
			"system_id":                  42,
			"tunnel_session_id":          fmt.Sprintf("s-%d", time.Now().UnixNano()),
			"cert_fingerprint":           hello["cert_fingerprint"],
			"heartbeat_interval_seconds": 30,
			"heartbeat_dead_seconds":     90,
		})
		if err := c.Write(r.Context(), websocket.MessageText, welcome); err != nil {
			return
		}
		if d.tunnelScript != nil {
			d.tunnelScript(d.t, r.Context(), c, hello)
		} else {
			<-r.Context().Done()
		}
	case "/agent/op":
		nonce := r.Header.Get("X-Praxis-Op-Nonce")
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.SetReadLimit(int64(DefaultMaxFramePayload + FrameHeaderSize + 1024))
		defer c.CloseNow() //nolint:errcheck
		d.opConns.Add(1)
		switch {
		case d.correlateOps:
			d.serveCorrelatedOp(r.Context(), c, nonce)
		case d.opScript != nil:
			d.opScript(d.t, r.Context(), c, r)
		default:
			<-r.Context().Done()
		}
	default:
		http.NotFound(w, r)
	}
}

// serveCorrelatedOp records the nonce-to-operation-ID relationship for
// one accepted /agent/op connection, then drains frames until the agent
// closes the stream. Problems are recorded rather than reported from
// this goroutine so the owning test decides how and when to fail.
func (d *dualBroker) serveCorrelatedOp(ctx context.Context, c *websocket.Conn, nonce string) {
	mt, raw, err := c.Read(ctx)
	if err != nil {
		d.recordOpConn(opConnRecord{nonce: nonce, err: fmt.Errorf("read op_attach: %w", err)})
		return
	}
	if mt != websocket.MessageText {
		d.recordOpConn(opConnRecord{nonce: nonce, err: fmt.Errorf("first op message was %v, want text op_attach", mt)})
		return
	}
	var attach map[string]any
	if err := json.Unmarshal(raw, &attach); err != nil {
		d.recordOpConn(opConnRecord{nonce: nonce, err: fmt.Errorf("decode op_attach: %w", err)})
		return
	}
	if msgType, _ := attach["type"].(string); msgType != "op_attach" {
		d.recordOpConn(opConnRecord{nonce: nonce, err: fmt.Errorf("first op message type %q, want op_attach", msgType)})
		return
	}
	opID, ok := attach["operation_id"].(float64)
	if !ok {
		d.recordOpConn(opConnRecord{nonce: nonce, err: fmt.Errorf("op_attach operation_id %v is not a number", attach["operation_id"])})
		return
	}
	d.recordOpConn(opConnRecord{nonce: nonce, opID: int(opID)})
	drainFramesUntil(ctx, c, FrameOpClose)
}

// recordOpConn appends one observation under the harness mutex so
// concurrent op connections cannot race each other.
func (d *dualBroker) recordOpConn(rec opConnRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opRecords = append(d.opRecords, rec)
}

// opConnRecords returns a snapshot of the observations recorded so far.
func (d *dualBroker) opConnRecords() []opConnRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]opConnRecord(nil), d.opRecords...)
}

// waitForOpConnRecords polls until at least n op connections have been
// recorded. op_complete can reach the control WSS before the broker
// goroutine has finished reading op_attach, so tests wait on the
// records themselves instead of assuming an arrival order.
func waitForOpConnRecords(t *testing.T, d *dualBroker, n int, timeout time.Duration) []opConnRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		recs := d.opConnRecords()
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorded %d op connection(s); want %d (records=%v)", len(recs), n, recs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertOpConnPairings checks that the accepted op connections carry
// exactly the wanted nonce-to-operation-ID relationships. It compares
// pairs, not the set of nonces: two nonces swapped between operations
// produce the same set but must still fail here. Ordering is not part
// of the comparison, so parallel connections may arrive either way
// round.
func assertOpConnPairings(t *testing.T, recs []opConnRecord, want map[string]int) {
	t.Helper()
	got := make(map[string]int, len(recs))
	for _, rec := range recs {
		if rec.err != nil {
			t.Errorf("op connection with nonce %q produced no usable op_attach: %v", rec.nonce, rec.err)
			continue
		}
		if prev, dup := got[rec.nonce]; dup {
			t.Errorf("nonce %q was accepted on two op connections (operation %d then %d)", rec.nonce, prev, rec.opID)
			continue
		}
		got[rec.nonce] = rec.opID
	}
	for nonce, wantID := range want {
		gotID, ok := got[nonce]
		if !ok {
			t.Errorf("no op connection presented nonce %q; recorded pairings=%v", nonce, got)
			continue
		}
		if gotID != wantID {
			t.Errorf("nonce %q attached to operation %d; want operation %d", nonce, gotID, wantID)
		}
	}
	for nonce, gotID := range got {
		if _, ok := want[nonce]; !ok {
			t.Errorf("unexpected op connection: nonce %q attached to operation %d", nonce, gotID)
		}
	}
}

// startDualBroker mirrors startBroker (tunnel_test.go) but routes
// both /agent/tunnel and /agent/op via a single handler.
func startDualBroker(t *testing.T, h *dualBroker) Config {
	t.Helper()
	ca := newCA(t)
	srvCert, srvKey := ca.issueServerLeaf(t)
	pair, _ := tls.X509KeyPair(srvCert, srvKey)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.caPEM)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	agentCert, agentKey := ca.issueClientLeaf(t)
	dir := t.TempDir()
	cp := filepath.Join(dir, "c.pem")
	kp := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(cp, agentCert, 0o600)
	_ = os.WriteFile(kp, agentKey, 0o600)
	_ = os.WriteFile(caPath, ca.caPEM, 0o600)
	return Config{
		BrokerURL:    convertHTTPSToWSS(t, srv.URL),
		CertFile:     cp,
		KeyFile:      kp,
		BrokerCAFile: caPath,
		AgentVersion: "test",
	}
}

// driveAgent runs Run with sub-second tunables, lets the test inspect
// the async behavior, and cancels at the end.
//
// Cancelling only asks Run to stop. Until it actually returns it keeps
// reading package-level state that other tests in this package
// override, so cleanup waits for the goroutine to finish instead of
// letting it outlive the test that started it.
func driveAgent(t *testing.T, cfg Config, opts RunOptions) (cancel func()) {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = &captureLogger{}
	}
	if opts.OpPairTimeout == 0 {
		opts.OpPairTimeout = 1 * time.Second
	}
	ctx, c := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = Run(ctx, cfg, opts)
	}()
	t.Cleanup(func() {
		c()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Errorf("agent Run did not exit after cancel")
		}
	})
	return c
}

// ---------------------------------------------------------------------------
// Op happy path + ordering
// ---------------------------------------------------------------------------

func TestOpHappyPath(t *testing.T) {
	opComplete := make(chan map[string]any, 1)
	opAttachSeen := make(chan map[string]any, 1)
	stubFrameSeen := make(chan Frame, 1)

	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			// Send op_request then op_nonce in that order.
			req, _ := json.Marshal(map[string]any{
				"type":         "op_request",
				"operation_id": 100,
				"op_type":      "_test_stub",
				"params":       map[string]any{},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 100,
				"nonce":        "test-nonce-100",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			// Drain — wait for op_complete from agent.
			for ctx.Err() == nil {
				mt, raw, err := c.Read(ctx)
				if err != nil {
					return
				}
				if mt != websocket.MessageText {
					continue
				}
				var msg map[string]any
				_ = json.Unmarshal(raw, &msg)
				if t, _ := msg["type"].(string); t == "op_complete" {
					select {
					case opComplete <- msg:
					default:
					}
				}
			}
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			// First message must be op_attach (text JSON).
			mt, raw, err := c.Read(ctx)
			if err != nil || mt != websocket.MessageText {
				return
			}
			var attach map[string]any
			_ = json.Unmarshal(raw, &attach)
			select {
			case opAttachSeen <- attach:
			default:
			}
			// Subsequent: agent sends our stub STDOUT frame + CLOSE.
			for ctx.Err() == nil {
				mt, raw, err := c.Read(ctx)
				if err != nil {
					return
				}
				if mt != websocket.MessageBinary {
					continue
				}
				f, err := DecodeFrame(raw, DefaultMaxFramePayload)
				if err != nil {
					return
				}
				if f.Op == FrameOpData && f.Channel == ChannelStdout {
					select {
					case stubFrameSeen <- f:
					default:
					}
				}
				if f.Op == FrameOpClose {
					return
				}
			}
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	select {
	case attach := <-opAttachSeen:
		if attach["type"] != "op_attach" {
			t.Fatalf("attach type=%v", attach["type"])
		}
		if id, _ := attach["operation_id"].(float64); int(id) != 100 {
			t.Fatalf("attach operation_id=%v", attach["operation_id"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never received op_attach on /agent/op")
	}

	select {
	case f := <-stubFrameSeen:
		want := "stub: op_type=_test_stub"
		if string(f.Payload) != want {
			t.Fatalf("stub payload=%q want %q", string(f.Payload), want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never received stub STDOUT frame")
	}

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "success" {
			t.Fatalf("outcome=%v want success; full msg=%v", msg["outcome"], msg)
		}
		if msg["operation_id"].(float64) != 100 {
			t.Fatalf("operation_id=%v", msg["operation_id"])
		}
		if _, ok := msg["duration_ms"]; !ok {
			t.Fatalf("op_complete missing duration_ms; full msg=%v", msg)
		}
		if _, ok := msg["exit_code"]; !ok {
			t.Fatalf("op_complete missing exit_code; full msg=%v", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never received op_complete")
	}
}

func TestOpReverseOrderPairing(t *testing.T) {
	opComplete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			// Send op_nonce FIRST, then op_request — pairing must be
			// order-agnostic.
			nonce, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 200,
				"nonce":        "test-200",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			time.Sleep(20 * time.Millisecond)
			req, _ := json.Marshal(map[string]any{
				"type":         "op_request",
				"operation_id": 200,
				"op_type":      "_test_stub",
				"params":       map[string]any{},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			drainOpComplete(ctx, c, opComplete)
		},
		opScript: stubOpScript(t, FrameOpClose),
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "success" {
			t.Fatalf("outcome=%v full=%v", msg["outcome"], msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("op never completed under reverse-order pairing")
	}
}

func TestOpHalfStateTimesOut(t *testing.T) {
	logger := &captureLogger{}
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			// Send only op_nonce — request never arrives. Wait for
			// the agent's pair-timeout to fire and log.
			nonce, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 300,
				"nonce":        "lonely",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			<-ctx.Done()
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
		OpPairTimeout:  150 * time.Millisecond,
		Logger:         logger,
	})
	defer cancel()

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if logger.contains(`half-state "nonce" expired`) {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("half-state never expired; logs=%v", logger.snapshot())
}

func TestOpDuplicateNonceIgnored(t *testing.T) {
	// Repeated op_request / op_nonce for one operation_id must not start
	// a second goroutine or a second op WSS, and a replacement nonce for
	// an already-active operation must never reach /agent/op.
	d := &dualBroker{
		t:            t,
		correlateOps: true,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type":         "op_request",
				"operation_id": 400,
				"op_type":      "_test_stub",
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 400,
				"nonce":        "n400",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			// Spam duplicates of both messages. All should be no-ops.
			for i := 0; i < 5; i++ {
				_ = c.Write(ctx, websocket.MessageText, req)
				_ = c.Write(ctx, websocket.MessageText, nonce)
			}
			// A different nonce for the same operation must be ignored
			// too. If it were honored the agent would dial /agent/op
			// again and present it there.
			replacement, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 400,
				"nonce":        "n400-replacement",
			})
			_ = c.Write(ctx, websocket.MessageText, replacement)
			<-ctx.Done()
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	// Wait for the one legitimate connection, then keep waiting so a
	// duplicate dial has time to manifest before the assertions run.
	waitForOpConnRecords(t, d, 1, 3*time.Second)
	time.Sleep(800 * time.Millisecond)
	if got := d.opConns.Load(); got != 1 {
		t.Fatalf("expected exactly 1 op WSS, got %d (duplicates were started)", got)
	}
	// Connection count alone would not prove the accepted connection was
	// the intended one, so pin the surviving pairing exactly.
	assertOpConnPairings(t, d.opConnRecords(), map[string]int{"n400": 400})
}

// ---------------------------------------------------------------------------
// Cancel + protocol error paths
// ---------------------------------------------------------------------------

func TestOpCancelMidOp(t *testing.T) {
	// Make the stub stall so the cancel reliably arrives mid-op.
	stubExtraDelayForTests = 2 * time.Second
	t.Cleanup(func() { stubExtraDelayForTests = 0 })

	opComplete := make(chan map[string]any, 1)
	holdRecvForever := make(chan struct{})
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 500, "op_type": "_test_stub",
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 500, "nonce": "n500",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			// Wait briefly for op WSS to attach, then send op_cancel.
			time.Sleep(150 * time.Millisecond)
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 500,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			drainOpComplete(ctx, c, opComplete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			// Read op_attach but DON'T read the stub frames — keep
			// the op WSS in flight so the cancel context can fire
			// while the agent is mid-stream.
			_, _, _ = c.Read(ctx)
			// Block until the test ends so the stub never naturally
			// completes — cancel should win.
			select {
			case <-ctx.Done():
			case <-holdRecvForever:
			}
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()
	defer close(holdRecvForever)

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "cancelled" {
			t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled op never reported op_complete")
	}
}

func TestOpDialFailureReportsError(t *testing.T) {
	opComplete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 600, "op_type": "_test_stub",
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 600, "nonce": "n600",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, opComplete)
		},
	}
	// The control WSS stays healthy while /agent/op answers 500, so the
	// websocket upgrade for the operation fails and the agent has to
	// report op_dial_failed.
	cfg, killOpEndpoint := startDualBrokerWithDeadOp(t, d)
	defer killOpEndpoint()
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "error" {
			t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
		}
		errFld, ok := msg["error"].(map[string]any)
		if !ok {
			t.Fatalf("error field shape: %v", msg["error"])
		}
		if errFld["reason"] != "op_dial_failed" {
			t.Fatalf("reason=%v want op_dial_failed", errFld["reason"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("op_dial_failed never reported")
	}
}

func TestOpCancelDuringPending(t *testing.T) {
	// op_request arrives, op_cancel arrives BEFORE op_nonce —
	// pump must still post op_complete(cancelled) to the broker
	// (otherwise it waits for nonce TTL).
	opComplete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 700, "op_type": "_test_stub",
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			// Cancel before the nonce.
			cancel, _ := json.Marshal(map[string]any{
				"type": "op_cancel", "operation_id": 700,
			})
			_ = c.Write(ctx, websocket.MessageText, cancel)
			// Late nonce — must NOT start an op.
			time.Sleep(50 * time.Millisecond)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 700, "nonce": "late",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, opComplete)
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
		OpPairTimeout:  500 * time.Millisecond,
	})
	defer cancel()

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "cancelled" {
			t.Fatalf("outcome=%v want cancelled; full=%v", msg["outcome"], msg)
		}
		if id, _ := msg["operation_id"].(float64); int(id) != 700 {
			t.Fatalf("operation_id=%v want 700", msg["operation_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending cancel did not produce op_complete(cancelled)")
	}
	// Late nonce must not have triggered a /agent/op dial.
	time.Sleep(300 * time.Millisecond)
	if got := d.opConns.Load(); got != 0 {
		t.Fatalf("late nonce after cancel started %d op WSS; want 0", got)
	}
}

func TestOpBadInboundFrameReportsBadFrame(t *testing.T) {
	// Hold outbound long enough for the broker's bad frame to arrive
	// on inbound; otherwise the stub completes before the wire frame
	// lands and the bridge exits success.
	stubExtraDelayForTests = 500 * time.Millisecond
	t.Cleanup(func() { stubExtraDelayForTests = 0 })

	opComplete := make(chan map[string]any, 1)
	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type": "op_request", "operation_id": 800, "op_type": "_test_stub",
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type": "op_nonce", "operation_id": 800, "nonce": "n800",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			drainOpComplete(ctx, c, opComplete)
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			// Read op_attach
			_, _, err := c.Read(ctx)
			if err != nil {
				return
			}
			// Send a structurally invalid frame: unknown op byte.
			bad := []byte{1, 0xFE, 1, 0, 0, 0, 0, 0}
			_ = c.Write(ctx, websocket.MessageBinary, bad)
			<-ctx.Done()
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "error" {
			t.Fatalf("outcome=%v want error; full=%v", msg["outcome"], msg)
		}
		errFld, ok := msg["error"].(map[string]any)
		if !ok {
			t.Fatalf("error field shape: %v", msg["error"])
		}
		if errFld["reason"] != "bad_frame" {
			t.Fatalf("reason=%v want bad_frame", errFld["reason"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bad inbound frame did not surface op_complete(error)")
	}
}

func TestOpTwoParallelOpsCompleteIndependently(t *testing.T) {
	completes := make(chan map[string]any, 4)
	d := &dualBroker{
		t:            t,
		correlateOps: true,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			for _, opID := range []int{901, 902} {
				req, _ := json.Marshal(map[string]any{
					"type": "op_request", "operation_id": opID, "op_type": "_test_stub",
				})
				_ = c.Write(ctx, websocket.MessageText, req)
				nonce, _ := json.Marshal(map[string]any{
					"type":         "op_nonce",
					"operation_id": opID,
					"nonce":        fmt.Sprintf("n%d", opID),
				})
				_ = c.Write(ctx, websocket.MessageText, nonce)
			}
			drainOpComplete(ctx, c, completes)
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	seen := map[int]string{}
	deadline := time.After(4 * time.Second)
	for len(seen) < 2 {
		select {
		case msg := <-completes:
			id := int(msg["operation_id"].(float64))
			seen[id] = msg["outcome"].(string)
		case <-deadline:
			t.Fatalf("only saw %d op_complete; want 2 (seen=%v)", len(seen), seen)
		}
	}
	for _, id := range []int{901, 902} {
		if seen[id] != "success" {
			t.Fatalf("op=%d outcome=%q want success", id, seen[id])
		}
	}

	// Each operation must have carried its own nonce onto its own op
	// connection. A set of accepted nonces would still match if the two
	// were swapped, so assert the pairing itself.
	recs := waitForOpConnRecords(t, d, 2, 3*time.Second)
	assertOpConnPairings(t, recs, map[string]int{"n901": 901, "n902": 902})
}

// startDualBrokerWithDeadOp serves /agent/tunnel via the supplied
// dualBroker but returns 500 for /agent/op so websocket.Dial fails
// upgrade — exercises the op_dial_failed path.
func startDualBrokerWithDeadOp(t *testing.T, d *dualBroker) (Config, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/tunnel", func(w http.ResponseWriter, r *http.Request) {
		d.ServeHTTP(w, r)
	})
	mux.HandleFunc("/agent/op", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "synthetic dial failure", http.StatusInternalServerError)
	})

	ca := newCA(t)
	srvCert, srvKey := ca.issueServerLeaf(t)
	pair, _ := tls.X509KeyPair(srvCert, srvKey)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.caPEM)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()

	agentCert, agentKey := ca.issueClientLeaf(t)
	dir := t.TempDir()
	cp := filepath.Join(dir, "c.pem")
	kp := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(cp, agentCert, 0o600)
	_ = os.WriteFile(kp, agentKey, 0o600)
	_ = os.WriteFile(caPath, ca.caPEM, 0o600)
	cfg := Config{
		BrokerURL:    convertHTTPSToWSS(t, srv.URL),
		CertFile:     cp,
		KeyFile:      kp,
		BrokerCAFile: caPath,
		AgentVersion: "test",
	}
	return cfg, srv.Close
}

// ---------------------------------------------------------------------------
// Helpers shared across op tests
// ---------------------------------------------------------------------------

// stubOpScript reads op_attach + drains any binary frames the agent
// sends (the stub: STDOUT then CLOSE). Returns when CLOSE arrives.
func stubOpScript(t *testing.T, until FrameOp) func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
	return func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
		// op_attach
		_, _, err := c.Read(ctx)
		if err != nil {
			return
		}
		drainFramesUntil(ctx, c, until)
	}
}

// drainFramesUntil reads binary frames until one carrying until arrives,
// the connection fails, or ctx ends.
func drainFramesUntil(ctx context.Context, c *websocket.Conn, until FrameOp) {
	for ctx.Err() == nil {
		mt, raw, err := c.Read(ctx)
		if err != nil {
			return
		}
		if mt != websocket.MessageBinary {
			continue
		}
		f, err := DecodeFrame(raw, DefaultMaxFramePayload)
		if err != nil {
			return
		}
		if f.Op == until {
			return
		}
	}
}

// drainOpComplete reads the control WSS until an op_complete arrives
// or ctx ends. Used by tunnelScripts that just want the outcome.
func drainOpComplete(ctx context.Context, c *websocket.Conn, sink chan<- map[string]any) {
	for ctx.Err() == nil {
		mt, raw, err := c.Read(ctx)
		if err != nil {
			return
		}
		if mt != websocket.MessageText {
			continue
		}
		var msg map[string]any
		_ = json.Unmarshal(raw, &msg)
		if t, _ := msg["type"].(string); t == "op_complete" {
			select {
			case sink <- msg:
			default:
			}
		}
	}
}

// Sanity that net is referenced — used by issueServerLeaf (in
// tunnel_test.go), but the linter sometimes flags this file's
// imports independently.
var _ = net.IP{}
