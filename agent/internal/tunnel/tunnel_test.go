package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ---------------------------------------------------------------------------
// In-process test broker
// ---------------------------------------------------------------------------

// brokerHandler is the test counterpart to app.broker.handlers in
// the Python broker. Mirrors only what the agent's task #3 needs:
// accept the WSS, read hello, send welcome, optionally exchange
// heartbeats, optionally send bye, optionally inject malformed
// frames. Fully synchronous via callbacks so each test can script
// the conversation it wants.
type brokerHandler struct {
	t *testing.T

	// Optional script: runs after the welcome is sent. Receives the
	// websocket.Conn and may send/recv whatever the test needs.
	// Default: read frames forever, echoing nothing — keeps the
	// connection alive until the agent or watchdog drops it.
	script func(t *testing.T, ctx context.Context, c *websocket.Conn)

	// Welcome heartbeat tunables. The agent adopts whatever the broker
	// advertises AFTER clamping to safe bounds (PRA-260), so tests can no
	// longer force a sub-second cadence through the welcome. A test that
	// needs a faster-than-bounds cadence must set suppressHeartbeatTunables
	// so the welcome omits these fields, leaving the (trusted, unclamped)
	// RunOptions values in force.
	heartbeatInterval float64 // seconds; 0 -> 30
	heartbeatDead     float64 // seconds; 0 -> 90
	// suppressHeartbeatTunables omits the heartbeat_*_seconds keys from the
	// welcome entirely so RunOptions fallbacks win.
	suppressHeartbeatTunables bool

	// Counters tests assert on.
	connections atomic.Int32
	hellos      atomic.Int32

	// Welcome session id observed by clients across reconnects.
	mu       sync.Mutex
	sessions []string
}

func (b *brokerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.t.Helper()
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Browsers don't dial us — agent only. Skip origin check
		// noise.
		InsecureSkipVerify: true,
	})
	if err != nil {
		b.t.Logf("broker accept: %v", err)
		return
	}
	defer c.CloseNow() //nolint:errcheck
	b.connections.Add(1)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	mt, raw, err := c.Read(ctx)
	if err != nil {
		b.t.Logf("broker read hello: %v", err)
		return
	}
	if mt != websocket.MessageText {
		b.t.Logf("broker hello: not text frame")
		return
	}
	var hello map[string]any
	if err := json.Unmarshal(raw, &hello); err != nil {
		b.t.Logf("broker hello parse: %v", err)
		return
	}
	if t, _ := hello["type"].(string); t != "hello" {
		b.t.Logf("broker hello type=%q", t)
		return
	}
	b.hellos.Add(1)

	sessionID := fmt.Sprintf("session-%d", b.connections.Load())
	b.mu.Lock()
	b.sessions = append(b.sessions, sessionID)
	b.mu.Unlock()

	welcomeMsg := map[string]any{
		"type":                  "welcome",
		"system_id":             42, // matches startBroker's cfg.SystemID
		"tunnel_session_id":     sessionID,
		"cert_fingerprint":      hello["cert_fingerprint"],
		"accepted_capabilities": hello["capabilities"],
		"server_time":           time.Now().UTC().Format(time.RFC3339Nano),
	}
	if !b.suppressHeartbeatTunables {
		hbi := b.heartbeatInterval
		if hbi == 0 {
			hbi = 30
		}
		hbd := b.heartbeatDead
		if hbd == 0 {
			hbd = 90
		}
		welcomeMsg["heartbeat_interval_seconds"] = hbi
		welcomeMsg["heartbeat_dead_seconds"] = hbd
	}
	welcome, _ := json.Marshal(welcomeMsg)
	if err := c.Write(ctx, websocket.MessageText, welcome); err != nil {
		b.t.Logf("broker send welcome: %v", err)
		return
	}

	if b.script != nil {
		b.script(b.t, ctx, c)
		return
	}
	// Default: drain frames until the peer closes.
	for ctx.Err() == nil {
		_, _, err := c.Read(ctx)
		if err != nil {
			return
		}
	}
}

func (b *brokerHandler) sessionsSnapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]string, len(b.sessions))
	copy(cp, b.sessions)
	return cp
}

// ---------------------------------------------------------------------------
// Cert minting + TLS setup
// ---------------------------------------------------------------------------

type pkiBundle struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newCA(t *testing.T) *pkiBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca self sign: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &pkiBundle{caCert: cert, caKey: key, caPEM: pemBytes}
}

// issueServerLeaf mints a leaf cert with both DNS and IP SANs so
// httptest URLs (which use 127.0.0.1) verify cleanly without forcing
// the agent's tls.Config to override ServerName.
func (b *pkiBundle) issueServerLeaf(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	return b.issueLeaf(t, "broker.test",
		[]string{"localhost", "broker.test"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	)
}

// issueClientLeaf mints a client-only leaf with no SANs (the broker
// verifies the chain, not the hostname, on the agent's incoming
// connection).
func (b *pkiBundle) issueClientLeaf(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	return b.issueLeaf(t, "agent-client", nil, nil)
}

func (b *pkiBundle) issueLeaf(
	t *testing.T, cn string, dnsNames []string, ipSANs []net.IP,
) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		IPAddresses:  ipSANs,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, b.caCert, &key.PublicKey, b.caKey,
	)
	if err != nil {
		t.Fatalf("leaf sign: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("leaf marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

// startBroker spins up an httptest TLS server with the supplied
// handler, returns the wss:// URL and a Config the agent can use.
// The broker requires (but does not verify) the agent's client cert
// — we trust whatever ours generates.
func startBroker(t *testing.T, handler *brokerHandler) (cfg Config, server *httptest.Server) {
	t.Helper()

	// One CA mints both ends — keeps the test setup tight. Real
	// deployment uses two CAs (agent-ca, broker-ca); the tunnel
	// only cares about RootCAs for outbound verification, so pool
	// vs single CA is irrelevant here.
	ca := newCA(t)
	serverCert, serverKey := ca.issueServerLeaf(t)
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(ca.caPEM)

	server = httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	// Mint the agent's identity off the same CA so client-cert
	// verification against ClientCAs passes.
	agentCertPEM, agentKeyPEM := ca.issueClientLeaf(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	caPath := filepath.Join(dir, "broker-ca.crt")
	if err := os.WriteFile(certPath, agentCertPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, agentKeyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(caPath, ca.caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	wssURL := convertHTTPSToWSS(t, server.URL)
	cfg = Config{
		BrokerURL:    wssURL,
		CertFile:     certPath,
		KeyFile:      keyPath,
		BrokerCAFile: caPath,
		AgentVersion: "test-0.1",
		SystemID:     42,
	}
	return cfg, server
}

func convertHTTPSToWSS(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	u.Scheme = "wss"
	u.Path = ""
	return u.String()
}

// captureLogger collects log lines so tests can assert on what got
// printed (e.g. "unsupported in this build").
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *captureLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]string, len(l.lines))
	copy(cp, l.lines)
	return cp
}

func (l *captureLogger) contains(substr string) bool {
	for _, line := range l.snapshot() {
		if containsString(line, substr) {
			return true
		}
	}
	return false
}

func containsString(haystack, needle string) bool {
	return len(needle) == 0 ||
		(len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestBackoffSchedule(t *testing.T) {
	got := []time.Duration{}
	cur := time.Second
	for i := 0; i < 8; i++ {
		got = append(got, cur)
		cur = nextBackoff(cur, 60*time.Second)
	}
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	for i, d := range want {
		if got[i] != d {
			t.Fatalf("step %d: got %s want %s", i, got[i], d)
		}
	}
}

func TestJitterStaysWithinEqualJitterBounds(t *testing.T) {
	// jitter(d) must return a value in [d/2, d) for any randFloat in
	// [0,1). Pin randFloat at the extremes and a midpoint to check the
	// bounds without relying on real randomness.
	orig := randFloat
	t.Cleanup(func() { randFloat = orig })

	base := 60 * time.Second
	cases := map[string]struct {
		r    float64
		want time.Duration
	}{
		"low edge":  {0.0, base / 2},                 // exactly d/2
		"midpoint":  {0.5, base/2 + base/4},          // d/2 + 0.5*(d/2)
		"high edge": {0.9999, base/2 + (base/2 - 1)}, // just under d (approx)
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			randFloat = func() float64 { return tc.r }
			got := jitter(base)
			if got < base/2 || got >= base {
				t.Fatalf("%s: jitter(%s)=%s out of [d/2, d)", name, base, got)
			}
			if tc.r == 0.0 && got != tc.want {
				t.Fatalf("low edge: got %s want %s", got, tc.want)
			}
		})
	}
}

func TestJitterSpreadsAcrossAgents(t *testing.T) {
	// Two agents with the SAME backoff must (almost always) wait
	// different amounts — that's the whole anti-thundering-herd point.
	orig := randFloat
	t.Cleanup(func() { randFloat = orig })

	randFloat = func() float64 { return 0.1 }
	a := jitter(BackoffMax)
	randFloat = func() float64 { return 0.8 }
	b := jitter(BackoffMax)
	if a == b {
		t.Fatalf("expected jittered waits to differ, both = %s", a)
	}
}

func TestJitterZeroDurationIsNoop(t *testing.T) {
	if jitter(0) != 0 {
		t.Fatalf("jitter(0) should be 0, got %s", jitter(0))
	}
}

func TestExitAfterWelcomeReturnsCleanly(t *testing.T) {
	handler := &brokerHandler{t: t}
	cfg, _ := startBroker(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := Run(ctx, cfg, RunOptions{ExitAfterWelcome: true, Logger: &captureLogger{}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := handler.connections.Load(); got != 1 {
		t.Fatalf("expected exactly 1 connection, got %d", got)
	}
	if got := handler.hellos.Load(); got != 1 {
		t.Fatalf("expected exactly 1 hello, got %d", got)
	}
}

func TestHelloPayloadShape(t *testing.T) {
	captured := make(chan map[string]any, 1)
	// Custom http.Handler — easier than threading a hello-capture
	// callback into brokerHandler since this test cares only about
	// the agent's outbound payload shape.
	wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		defer c.CloseNow() //nolint:errcheck
		mt, raw, err := c.Read(r.Context())
		if err != nil || mt != websocket.MessageText {
			return
		}
		var msg map[string]any
		if err := json.Unmarshal(raw, &msg); err != nil {
			return
		}
		captured <- msg
		welcome, _ := json.Marshal(map[string]any{
			"type":              "welcome",
			"system_id":         1,
			"tunnel_session_id": "abc",
		})
		_ = c.Write(r.Context(), websocket.MessageText, welcome)
	})

	ca := newCA(t)
	serverCert, serverKey := ca.issueServerLeaf(t)
	pair, _ := tls.X509KeyPair(serverCert, serverKey)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.caPEM)
	server := httptest.NewUnstartedServer(wrap)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool, MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	agentCertPEM, agentKeyPEM := ca.issueClientLeaf(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(certPath, agentCertPEM, 0o600)
	_ = os.WriteFile(keyPath, agentKeyPEM, 0o600)
	_ = os.WriteFile(caPath, ca.caPEM, 0o600)

	cfg := Config{
		BrokerURL:    convertHTTPSToWSS(t, server.URL),
		CertFile:     certPath,
		KeyFile:      keyPath,
		BrokerCAFile: caPath,
		AgentVersion: "test-1.2.3",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = Run(ctx, cfg, RunOptions{ExitAfterWelcome: true, Logger: &captureLogger{}})

	hello := <-captured
	if hello["type"] != "hello" {
		t.Fatalf("type=%v", hello["type"])
	}
	if hello["protocol_version"] != float64(1) {
		t.Fatalf("protocol_version=%v", hello["protocol_version"])
	}
	if hello["agent_version"] != "test-1.2.3" {
		t.Fatalf("agent_version=%v", hello["agent_version"])
	}
	caps, _ := hello["capabilities"].([]any)
	// Capabilities should mirror DefaultCapabilities exactly. As
	// op handlers grow this list (heartbeat → exec → file.* → pty →
	// facts), the assertion follows the constant rather than pinning
	// a frozen snapshot of one slice's worth of advertisements.
	gotCaps := make([]string, 0, len(caps))
	for _, c := range caps {
		s, _ := c.(string)
		gotCaps = append(gotCaps, s)
	}
	if len(gotCaps) != len(DefaultCapabilities) {
		t.Fatalf("capabilities len=%d want %d (%v vs %v)",
			len(gotCaps), len(DefaultCapabilities), gotCaps, DefaultCapabilities)
	}
	for i, want := range DefaultCapabilities {
		if gotCaps[i] != want {
			t.Fatalf("capabilities[%d]=%q want %q", i, gotCaps[i], want)
		}
	}
	fp, _ := hello["cert_fingerprint"].(string)
	if !containsString(fp, "sha256:") || len(fp) != 71 {
		t.Fatalf("cert_fingerprint=%q (want sha256:<64hex>)", fp)
	}
}

func TestHeartbeatLifecycle(t *testing.T) {
	heartbeats := make(chan map[string]any, 8)
	handler := &brokerHandler{
		t: t,
		// Broker omits heartbeat tunables so the fast (trusted, unclamped)
		// RunOptions cadence below drives the loop. PRA-260 clamps broker
		// values to a >=5s floor, which a 3s test can't observe.
		suppressHeartbeatTunables: true,
		script: func(t *testing.T, ctx context.Context, c *websocket.Conn) {
			// Send a heartbeat right away so the agent's recv loop sees one.
			payload, _ := json.Marshal(map[string]any{
				"type": "heartbeat", "ts": time.Now().UTC().Format(time.RFC3339Nano),
			})
			_ = c.Write(ctx, websocket.MessageText, payload)
			// Then read whatever the agent sends until the connection ends.
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
				if t, _ := msg["type"].(string); t == "heartbeat" {
					select {
					case heartbeats <- msg:
					default:
					}
				}
			}
		},
	}
	cfg, _ := startBroker(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		// The broker suppresses heartbeat tunables, so these fast RunOptions
		// values (trusted config, not clamped) drive the send loop.
		_ = Run(ctx, cfg, RunOptions{
			HeartbeatInterval: 80 * time.Millisecond,
			HeartbeatDead:     5 * time.Second,
			Logger:            &captureLogger{},
		})
	}()

	got := false
	for i := 0; i < 30 && !got; i++ {
		select {
		case <-time.After(100 * time.Millisecond):
		case msg := <-heartbeats:
			if _, ok := msg["ts"].(string); ok {
				got = true
			}
		}
	}
	if !got {
		t.Fatal("never received an agent heartbeat with a ts field")
	}
}

func TestByeTriggersReconnect(t *testing.T) {
	first := true
	handler := &brokerHandler{
		t: t,
		script: func(t *testing.T, ctx context.Context, c *websocket.Conn) {
			if first {
				first = false
				bye, _ := json.Marshal(map[string]any{"type": "bye", "reason": "test"})
				_ = c.Write(ctx, websocket.MessageText, bye)
				_ = c.Close(websocket.StatusNormalClosure, "test")
				return
			}
			// Second connection: stay open.
			<-ctx.Done()
		},
	}
	cfg, _ := startBroker(t, handler)

	logger := &captureLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = Run(ctx, cfg, RunOptions{
			BackoffInitial: 50 * time.Millisecond,
			BackoffMax:     200 * time.Millisecond,
			Logger:         logger,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if handler.connections.Load() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := handler.connections.Load(); got < 2 {
		t.Fatalf("expected reconnect after bye; connections=%d", got)
	}
	if !logger.contains("broker bye") {
		t.Fatalf("missing 'broker bye' log; lines=%v", logger.snapshot())
	}
	sessions := handler.sessionsSnapshot()
	if len(sessions) < 2 || sessions[0] == sessions[1] {
		t.Fatalf("expected distinct sessions across reconnect; got %v", sessions)
	}
}

func TestUnknownControlTypeIgnored(t *testing.T) {
	handler := &brokerHandler{
		t: t,
		script: func(t *testing.T, ctx context.Context, c *websocket.Conn) {
			payload, _ := json.Marshal(map[string]any{"type": "future_thing"})
			_ = c.Write(ctx, websocket.MessageText, payload)
			<-ctx.Done()
		},
	}
	cfg, _ := startBroker(t, handler)

	logger := &captureLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, RunOptions{
			HeartbeatInterval: time.Second,
			HeartbeatDead:     5 * time.Second,
			Logger:            logger,
		})
	}()

	select {
	case <-time.After(800 * time.Millisecond):
	case err := <-done:
		t.Fatalf("Run returned early on unknown type: err=%v", err)
	}
	if !logger.contains(`unknown control type "future_thing"`) {
		t.Fatalf("missing unknown-type log; lines=%v", logger.snapshot())
	}
	if handler.connections.Load() != 1 {
		t.Fatalf("expected tunnel to stay up on unknown type; connections=%d",
			handler.connections.Load())
	}
}

func TestHeartbeatDeadCausesReconnect(t *testing.T) {
	// Broker accepts + welcomes, then goes silent. The agent watchdog
	// should declare it dead and reconnect with a fresh attempt.
	handler := &brokerHandler{
		t: t,
		// Broker omits heartbeat tunables (PRA-260 would clamp a 0.2s dead
		// window up to the 15s floor); the tight dead window comes from the
		// trusted RunOptions below instead.
		suppressHeartbeatTunables: true,
		script: func(t *testing.T, ctx context.Context, c *websocket.Conn) {
			<-ctx.Done()
		},
	}
	cfg, _ := startBroker(t, handler)

	logger := &captureLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		// interval < dead so normalizeHeartbeat's dead>interval invariant
		// doesn't bump the tight dead window. The broker stays silent, so the
		// watchdog fires ~200ms after welcome and forces a reconnect.
		_ = Run(ctx, cfg, RunOptions{
			HeartbeatInterval: 50 * time.Millisecond,
			HeartbeatDead:     200 * time.Millisecond,
			BackoffInitial:    50 * time.Millisecond,
			BackoffMax:        200 * time.Millisecond,
			Logger:            logger,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if handler.connections.Load() >= 2 {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if got := handler.connections.Load(); got < 2 {
		t.Fatalf("expected reconnect after heartbeat_dead; connections=%d", got)
	}
}

// brokerWithCustomWelcome lets a test inject any welcome payload it
// wants — used to exercise the welcome-validation paths
// (fingerprint mismatch, wrong system_id, broker-tuned heartbeat).
type brokerWithCustomWelcome struct {
	t       *testing.T
	welcome func(hello map[string]any) map[string]any
	script  func(t *testing.T, ctx context.Context, c *websocket.Conn)
	conns   atomic.Int32
}

func (b *brokerWithCustomWelcome) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer c.CloseNow() //nolint:errcheck
	b.conns.Add(1)
	mt, raw, err := c.Read(r.Context())
	if err != nil || mt != websocket.MessageText {
		return
	}
	var hello map[string]any
	_ = json.Unmarshal(raw, &hello)
	wm := b.welcome(hello)
	wj, _ := json.Marshal(wm)
	if err := c.Write(r.Context(), websocket.MessageText, wj); err != nil {
		return
	}
	if b.script != nil {
		b.script(b.t, r.Context(), c)
	} else {
		<-r.Context().Done()
	}
}

func startCustomBroker(t *testing.T, h *brokerWithCustomWelcome) Config {
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

func TestWelcomeRejectedOnFingerprintMismatch(t *testing.T) {
	h := &brokerWithCustomWelcome{
		t: t,
		welcome: func(hello map[string]any) map[string]any {
			// Deliberately echo a different fingerprint than the
			// agent sent in hello.
			return map[string]any{
				"type":              "welcome",
				"system_id":         1,
				"tunnel_session_id": "x",
				"cert_fingerprint":  "sha256:" + strings.Repeat("0", 64),
			}
		},
	}
	cfg := startCustomBroker(t, h)
	logger := &captureLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		_ = Run(ctx, cfg, RunOptions{
			BackoffInitial: 50 * time.Millisecond,
			BackoffMax:     200 * time.Millisecond,
			Logger:         logger,
		})
	}()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if logger.contains("cert_fingerprint mismatch") {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("missing fingerprint mismatch log; lines=%v", logger.snapshot())
}

func TestWelcomeRejectedOnSystemIDMismatch(t *testing.T) {
	h := &brokerWithCustomWelcome{
		t: t,
		welcome: func(hello map[string]any) map[string]any {
			return map[string]any{
				"type":              "welcome",
				"system_id":         99, // different from cfg.SystemID below
				"tunnel_session_id": "x",
				"cert_fingerprint":  hello["cert_fingerprint"],
			}
		},
	}
	cfg := startCustomBroker(t, h)
	cfg.SystemID = 42 // pin agent's expectation
	logger := &captureLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		_ = Run(ctx, cfg, RunOptions{
			BackoffInitial: 50 * time.Millisecond,
			BackoffMax:     200 * time.Millisecond,
			Logger:         logger,
		})
	}()
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if logger.contains("system_id 99 differs from configured 42") {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("missing system_id mismatch log; lines=%v", logger.snapshot())
}

func TestBrokerHeartbeatTunablesAreApplied(t *testing.T) {
	// A valid, in-bounds broker override is adopted by validateWelcome,
	// overriding the agent defaults. Asserted directly at the parse point —
	// no lifecycle timing needed (PRA-260 clamps sub-second cadences, so the
	// old 50ms-via-welcome approach is no longer observable). The clamping
	// itself is covered exhaustively by TestNormalizeHeartbeat below.
	hello := map[string]any{"cert_fingerprint": "fp"}
	welcome := map[string]any{
		"type":                       "welcome",
		"cert_fingerprint":           "fp",
		"heartbeat_interval_seconds": 45.0,
		"heartbeat_dead_seconds":     120.0,
	}
	opts := RunOptions{
		HeartbeatInterval: HeartbeatInterval,
		HeartbeatDead:     HeartbeatDead,
	}
	if err := validateWelcome(welcome, hello, Config{}, &opts); err != nil {
		t.Fatalf("validateWelcome: %v", err)
	}
	if opts.HeartbeatInterval != 45*time.Second {
		t.Fatalf("interval: got %s, want 45s", opts.HeartbeatInterval)
	}
	if opts.HeartbeatDead != 120*time.Second {
		t.Fatalf("dead: got %s, want 120s", opts.HeartbeatDead)
	}
}

func TestCleanByeStillSleepsBeforeReconnect(t *testing.T) {
	// Broker sends bye on every connection. Without the
	// sleep-before-redial fix the agent would hammer it tight-loop;
	// measure the reconnect cadence and assert it respects
	// BackoffInitial.
	h := &brokerWithCustomWelcome{
		t: t,
		welcome: func(hello map[string]any) map[string]any {
			return map[string]any{
				"type":              "welcome",
				"system_id":         1,
				"tunnel_session_id": fmt.Sprintf("s-%d", time.Now().UnixNano()),
				"cert_fingerprint":  hello["cert_fingerprint"],
			}
		},
		script: func(t *testing.T, ctx context.Context, c *websocket.Conn) {
			bye, _ := json.Marshal(map[string]any{
				"type": "bye", "reason": "drain",
			})
			_ = c.Write(ctx, websocket.MessageText, bye)
			_ = c.Close(websocket.StatusNormalClosure, "drain")
		},
	}
	cfg := startCustomBroker(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_ = Run(ctx, cfg, RunOptions{
			BackoffInitial: 200 * time.Millisecond,
			BackoffMax:     1 * time.Second,
			Logger:         &captureLogger{},
		})
	}()
	// Wait ~700ms; with 200ms initial backoff between clean reconnects
	// we should see roughly 3 connections (t=0, ~200ms, ~400ms, ~600ms).
	// Crucially we should NOT see dozens — that's what the bug looked
	// like.
	time.Sleep(700 * time.Millisecond)
	got := h.conns.Load()
	if got > 6 {
		t.Fatalf("too many reconnects in 700ms (got %d) — sleep-before-redial regression?", got)
	}
	if got < 2 {
		t.Fatalf("expected at least 2 reconnects, got %d", got)
	}
}

func TestBuildTLSConfigRejectsBadBrokerCA(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	cert, key := ca.issueClientLeaf(t)
	_ = os.WriteFile(filepath.Join(dir, "agent.crt"), cert, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "agent.key"), key, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "broker-ca.crt"), []byte("not a cert"), 0o600)
	cfg := Config{
		CertFile:     filepath.Join(dir, "agent.crt"),
		KeyFile:      filepath.Join(dir, "agent.key"),
		BrokerCAFile: filepath.Join(dir, "broker-ca.crt"),
	}
	if _, _, err := buildTLSConfig(cfg); err == nil {
		t.Fatal("expected error on bad broker CA, got nil")
	}
}

func TestBuildTLSConfigFingerprintMatchesCert(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	certPEM, keyPEM := ca.issueClientLeaf(t)
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	caPath := filepath.Join(dir, "broker-ca.crt")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(caPath, ca.caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	cfg := Config{
		CertFile: certPath, KeyFile: keyPath, BrokerCAFile: caPath,
	}
	_, fp, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint len=%d want 64", len(fp))
	}
}

// Sanity: agent should refuse to start if the broker-ca file is
// missing entirely (config integrity guard).
func TestRunSurfacesMissingBrokerCA(t *testing.T) {
	cfg := Config{
		BrokerURL:    "wss://localhost:1",
		CertFile:     "/does/not/exist.crt",
		KeyFile:      "/does/not/exist.key",
		BrokerCAFile: "/does/not/exist.ca",
		AgentVersion: "test",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := Run(ctx, cfg, RunOptions{Logger: &captureLogger{}})
	if err == nil {
		t.Fatal("expected error from missing cert/key/ca, got nil")
	}
}

// ---------------------------------------------------------------------------
// PRA-260: broker heartbeat tunable normalization
// ---------------------------------------------------------------------------

// overflowSeconds is a finite float far larger than any real duration — big
// enough that seconds*1e9 would overflow int64 nanoseconds if multiplied
// directly. Normalization must clamp to the max bound instead of overflowing.
const overflowSeconds = 1e300

func TestSecondsToBoundedDuration(t *testing.T) {
	const (
		minD = 5 * time.Second
		maxD = 5 * time.Minute
	)
	cases := []struct {
		name    string
		seconds float64
		wantOK  bool
		want    time.Duration
	}{
		{"normal", 30, true, 30 * time.Second},
		{"min-boundary", 5, true, minD},
		{"max-boundary", 300, true, maxD},
		{"below-min-fractional", 0.000000001, true, minD},
		{"below-min-small", 1, true, minD},
		{"above-max", 600, true, maxD},
		{"overflow-sized", overflowSeconds, true, maxD},
		{"nan", math.NaN(), false, 0},
		{"pos-inf", math.Inf(1), false, 0},
		{"neg-inf", math.Inf(-1), false, 0},
		{"zero", 0, false, 0},
		{"negative", -10, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := secondsToBoundedDuration(tc.seconds, minD, maxD)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("duration: got %s, want %s", got, tc.want)
			}
			// A returned duration must always be within bounds and never
			// negative — the property that keeps time.NewTicker safe.
			if ok && (got < minD || got > maxD) {
				t.Fatalf("out-of-bounds duration %s (min=%s max=%s)", got, minD, maxD)
			}
		})
	}
}

func TestNormalizeHeartbeat(t *testing.T) {
	// Each case starts from the production defaults and applies broker values.
	cases := []struct {
		name         string
		haveInterval bool
		haveDead     bool
		interval     float64
		dead         float64
		wantInterval time.Duration
		wantDead     time.Duration
	}{
		{
			name:         "missing-fields-keep-defaults",
			wantInterval: HeartbeatInterval,
			wantDead:     HeartbeatDead,
		},
		{
			name:         "normal-override",
			haveInterval: true, haveDead: true,
			interval: 30, dead: 90,
			wantInterval: 30 * time.Second, wantDead: 90 * time.Second,
		},
		{
			name:         "min-boundary",
			haveInterval: true, haveDead: true,
			interval: 5, dead: 15,
			wantInterval: minBrokerHeartbeatInterval, wantDead: minBrokerHeartbeatDead,
		},
		{
			name:         "max-boundary",
			haveInterval: true, haveDead: true,
			interval: 300, dead: 1800,
			wantInterval: maxBrokerHeartbeatInterval, wantDead: maxBrokerHeartbeatDead,
		},
		{
			name:         "below-min-fractional-clamps-up",
			haveInterval: true, haveDead: true,
			interval: 0.000000001, dead: 0.5,
			wantInterval: minBrokerHeartbeatInterval, wantDead: minBrokerHeartbeatDead,
		},
		{
			name:         "nan-ignored-keeps-defaults",
			haveInterval: true, haveDead: true,
			interval: math.NaN(), dead: math.NaN(),
			wantInterval: HeartbeatInterval, wantDead: HeartbeatDead,
		},
		{
			name:         "pos-inf-ignored",
			haveInterval: true, haveDead: true,
			interval: math.Inf(1), dead: math.Inf(1),
			wantInterval: HeartbeatInterval, wantDead: HeartbeatDead,
		},
		{
			name:         "neg-inf-ignored",
			haveInterval: true, haveDead: true,
			interval: math.Inf(-1), dead: math.Inf(-1),
			wantInterval: HeartbeatInterval, wantDead: HeartbeatDead,
		},
		{
			name:         "overflow-clamps-to-max",
			haveInterval: true, haveDead: true,
			interval: overflowSeconds, dead: overflowSeconds,
			wantInterval: maxBrokerHeartbeatInterval, wantDead: maxBrokerHeartbeatDead,
		},
		{
			// dead < interval after clamping: dead must be bumped above interval.
			name:         "dead-less-than-interval-bumped",
			haveInterval: true, haveDead: true,
			interval: 120, dead: 20,
			wantInterval: 120 * time.Second,
			wantDead:     120*time.Second + minBrokerHeartbeatInterval,
		},
		{
			// dead == interval must also be bumped strictly above interval.
			name:         "dead-equal-interval-bumped",
			haveInterval: true, haveDead: true,
			interval: 60, dead: 60,
			wantInterval: 60 * time.Second,
			wantDead:     60*time.Second + minBrokerHeartbeatInterval,
		},
		{
			// interval-only override; dead default (90s) already exceeds it.
			name:         "interval-only",
			haveInterval: true,
			interval:     45,
			wantInterval: 45 * time.Second,
			wantDead:     HeartbeatDead,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := RunOptions{
				HeartbeatInterval: HeartbeatInterval,
				HeartbeatDead:     HeartbeatDead,
			}
			normalizeHeartbeat(
				&opts, tc.interval, tc.dead, tc.haveInterval, tc.haveDead, nil,
			)
			if opts.HeartbeatInterval != tc.wantInterval {
				t.Errorf(
					"interval: got %s, want %s", opts.HeartbeatInterval, tc.wantInterval,
				)
			}
			if opts.HeartbeatDead != tc.wantDead {
				t.Errorf("dead: got %s, want %s", opts.HeartbeatDead, tc.wantDead)
			}
			// The invariant that protects the watchdog: dead strictly exceeds
			// interval for every input, valid or hostile.
			if opts.HeartbeatDead <= opts.HeartbeatInterval {
				t.Errorf(
					"invariant violated: dead %s <= interval %s",
					opts.HeartbeatDead, opts.HeartbeatInterval,
				)
			}
		})
	}
}

// TestNormalizeHeartbeatNeverPanicsOrProducesUnsafeTicker feeds a wide sweep of
// hostile values and asserts the results are always safe to hand to
// time.NewTicker (strictly positive, and dead/5 > 0).
func TestNormalizeHeartbeatNeverPanicsOrProducesUnsafeTicker(t *testing.T) {
	hostile := []float64{
		math.NaN(), math.Inf(1), math.Inf(-1), 0, -1, -1e300,
		overflowSeconds, 1e-18, 0.0000001, 1, 5, 300, 1e9,
	}
	for _, iv := range hostile {
		for _, dv := range hostile {
			opts := RunOptions{
				HeartbeatInterval: HeartbeatInterval,
				HeartbeatDead:     HeartbeatDead,
			}
			normalizeHeartbeat(&opts, iv, dv, true, true, nil)
			if opts.HeartbeatInterval <= 0 {
				t.Fatalf("interval non-positive for (%v,%v): %s", iv, dv, opts.HeartbeatInterval)
			}
			if opts.HeartbeatDead <= 0 || opts.HeartbeatDead/5 <= 0 {
				t.Fatalf("dead unsafe for (%v,%v): %s", iv, dv, opts.HeartbeatDead)
			}
			if opts.HeartbeatDead <= opts.HeartbeatInterval {
				t.Fatalf("dead<=interval for (%v,%v): %s <= %s", iv, dv, opts.HeartbeatDead, opts.HeartbeatInterval)
			}
		}
	}
}
