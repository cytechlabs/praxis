// Package tunnel is the agent-side counterpart to the broker's
// /agent/tunnel control WebSocket (PRA-151).
//
// Scope here is intentionally narrow per the PRA-152 task #3 design
// lock: dial mTLS WSS, complete the hello/welcome handshake, run the
// heartbeat lifecycle (send every interval; declare the broker dead
// after the silence window), reconnect on disconnect with exponential
// backoff (1s, 2s, 4s, ..., 60s cap; reset on welcome). Op handling
// (op_request / op_nonce / op_attach) explicitly stays out — when
// such a message arrives we log "unsupported in this build" and keep
// the tunnel up.
//
// Backed by github.com/coder/websocket so the wire shape matches the
// broker side exactly (same library on both ends).
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Defaults match the locked spec — protocol_version 1, send heartbeat
// every 30s, declare broker dead after 90s silence, agent reconnect
// backoff 1s -> 2s -> 4s -> ... cap 60s, reset on welcome.
const (
	ProtocolVersion = 1

	HeartbeatInterval = 30 * time.Second
	HeartbeatDead     = 90 * time.Second

	BackoffInitial = 1 * time.Second
	BackoffMax     = 60 * time.Second

	// Read deadline for the welcome — the broker should send it
	// immediately after the agent's hello. If it stalls something is
	// wrong; bail and let the reconnect loop try again.
	HelloTimeout = 10 * time.Second
)

// PRA-260: safe bounds for broker-supplied heartbeat tunables. The broker may
// tune the cadence via the welcome frame, but the values arrive as untrusted
// JSON floats (interpreted as SECONDS) and feed straight into time.NewTicker.
// Without bounds a malformed or hostile welcome could panic the agent (NaN/Inf/
// overflow) or force a pathological ticker cadence (sub-nanosecond truncating to
// zero, or a few-millisecond interval flooding CPU/network). Every broker value
// is clamped to these ranges before any Duration conversion or ticker creation.
const (
	minBrokerHeartbeatInterval = 5 * time.Second
	maxBrokerHeartbeatInterval = 5 * time.Minute
	minBrokerHeartbeatDead     = 15 * time.Second
	maxBrokerHeartbeatDead     = 30 * time.Minute
)

// Capabilities advertised in the agent's hello. The broker
// intersects this with its own SERVER_CAPABILITIES at handshake;
// the result drives op-type gating downstream (e.g. PRA-155 #2b-b's
// transport selector skips the agent path when the facts capability
// is absent from the negotiated set).
//
// Order:
//   - heartbeat: PRA-151. Tunnel liveness; not an op_type.
//   - exec / file.read / file.write / file.list / file.checksum:
//     PRA-152 / PRA-153 op handlers.
//   - pty: PRA-153 (deferred at backend until effective_login lands,
//     but the wire capability is honest about what the agent serves).
//   - facts: PRA-155 #2b-a — runFacts is a real op handler now.
var DefaultCapabilities = []string{
	"heartbeat",
	"exec",
	"file.read",
	"file.write",
	"file.list",
	"file.checksum",
	"pty",
	"facts",
}

// Config carries everything Run needs to dial the broker. All paths
// are absolute and refer to files written by install-cert
// (/etc/praxis-agent/{agent.key,agent.crt,broker-ca.crt} by default).
type Config struct {
	BrokerURL    string // wss://host:port — connect appends /agent/tunnel
	CertFile     string // PEM cert (the Vault-signed agent identity)
	KeyFile      string // PEM PKCS#8 private key matching CertFile
	BrokerCAFile string // PEM CA bundle to verify the broker's server cert
	AgentVersion string // build-time Version, sent in hello
	SystemID     int    // informational — not on the wire, used for logging
}

// Logger is the minimum the tunnel needs from the host process. The
// CLI passes log.Default(); tests pass a no-op or capturing impl.
type Logger interface {
	Printf(format string, args ...any)
}

type stdLogger struct{}

func (stdLogger) Printf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "praxis-agent tunnel: "+format+"\n", args...)
}

// RunOptions tunes Run for tests + the --exit-after-welcome smoke
// mode. Default values match the spec (heartbeat 30s, dead after 90s).
type RunOptions struct {
	HeartbeatInterval time.Duration
	HeartbeatDead     time.Duration
	BackoffInitial    time.Duration
	BackoffMax        time.Duration
	Capabilities      []string
	Logger            Logger
	// ExitAfterWelcome makes Run return nil immediately after the
	// first successful welcome. Used by the CLI smoke flag and by
	// tests that don't need the heartbeat lifecycle.
	ExitAfterWelcome bool
	// OpPairTimeout overrides the op_request/op_nonce pairing window
	// in tests. Zero -> DefaultOpPairTimeout (5s).
	OpPairTimeout time.Duration
}

func (o *RunOptions) applyDefaults() {
	if o.HeartbeatInterval == 0 {
		o.HeartbeatInterval = HeartbeatInterval
	}
	if o.HeartbeatDead == 0 {
		o.HeartbeatDead = HeartbeatDead
	}
	if o.BackoffInitial == 0 {
		o.BackoffInitial = BackoffInitial
	}
	if o.BackoffMax == 0 {
		o.BackoffMax = BackoffMax
	}
	if o.Capabilities == nil {
		o.Capabilities = DefaultCapabilities
	}
	if o.Logger == nil {
		o.Logger = stdLogger{}
	}
}

// Run dials the broker, runs the connect / handshake / heartbeat
// loop, and reconnects on failure with exponential backoff. Returns
// nil when the context is cancelled (normal shutdown signal) or when
// ExitAfterWelcome triggers an early return.
func Run(ctx context.Context, cfg Config, opts RunOptions) error {
	opts.applyDefaults()

	tlsCfg, fingerprint, err := buildTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	hello := helloPayload(cfg, opts.Capabilities, fingerprint)

	backoff := opts.BackoffInitial
	url := cfg.BrokerURL + "/agent/tunnel"

	for {
		if ctx.Err() != nil {
			return nil
		}
		opts.Logger.Printf("connecting system_id=%d url=%s", cfg.SystemID, url)
		welcomedEarly, err := connectOnce(ctx, url, tlsCfg, hello, cfg, opts)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil
		case welcomedEarly:
			// ExitAfterWelcome short-circuit — caller wanted a smoke
			// run; respect it.
			return nil
		case err != nil:
			wait := jitter(backoff)
			opts.Logger.Printf("tunnel error: %v; reconnect in %s", err, wait)
			if !sleepWithCancel(ctx, wait) {
				return nil
			}
			backoff = nextBackoff(backoff, opts.BackoffMax)
			continue
		}
		// Clean disconnect (broker bye, EOF) AFTER welcome. Reset
		// backoff because the previous attempt was healthy, but still
		// sleep before redialing — without this the agent would hammer
		// the broker in a tight loop during graceful drain /
		// replacement / cert-expired flows. Jitter the redial so a
		// fleet draining off one broker doesn't reconnect in lockstep.
		backoff = opts.BackoffInitial
		wait := jitter(backoff)
		opts.Logger.Printf("tunnel closed cleanly; reconnect in %s", wait)
		if !sleepWithCancel(ctx, wait) {
			return nil
		}
	}
}

// connectOnce dials, handshakes, and runs the lifecycle until the
// connection ends. Returns (welcomedEarly, err):
//
//   - welcomedEarly=true means ExitAfterWelcome fired and the caller
//     should NOT reconnect — used by the smoke flag.
//   - err non-nil means a transient failure (connect, handshake, or
//     in-flight read) and the caller should back off and retry.
//   - err nil means the broker closed cleanly (e.g. bye); caller
//     sleeps backoff and reconnects on next iteration.
func connectOnce(
	ctx context.Context,
	url string,
	tlsCfg *tls.Config,
	hello map[string]any,
	cfg Config,
	opts RunOptions,
) (welcomedEarly bool, err error) {
	dialOpts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}
	conn, _, err := websocket.Dial(ctx, url, dialOpts)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	// coder/websocket defaults to a 32 KiB per-message read limit; our
	// frame cap is 1 MiB and file/exec primitives can hit it. Bump.
	conn.SetReadLimit(int64(DefaultMaxFramePayload + FrameHeaderSize + 1024))
	defer conn.CloseNow() //nolint:errcheck // best-effort on shutdown

	helloRaw, _ := json.Marshal(hello)
	if err := conn.Write(ctx, websocket.MessageText, helloRaw); err != nil {
		return false, fmt.Errorf("send hello: %w", err)
	}

	welcomeCtx, cancel := context.WithTimeout(ctx, HelloTimeout)
	defer cancel()
	mt, raw, err := conn.Read(welcomeCtx)
	if err != nil {
		return false, fmt.Errorf("await welcome: %w", err)
	}
	if mt != websocket.MessageText {
		return false, fmt.Errorf("welcome: expected text frame, got %v", mt)
	}
	var welcome map[string]any
	if err := json.Unmarshal(raw, &welcome); err != nil {
		return false, fmt.Errorf("welcome parse: %w", err)
	}
	if err := validateWelcome(welcome, hello, cfg, &opts); err != nil {
		return false, err
	}
	opts.Logger.Printf(
		"welcome system_id=%v session=%v hb_interval=%s hb_dead=%s",
		welcome["system_id"], welcome["tunnel_session_id"],
		opts.HeartbeatInterval, opts.HeartbeatDead,
	)

	if opts.ExitAfterWelcome {
		_ = conn.Close(websocket.StatusNormalClosure, "exit_after_welcome")
		return true, nil
	}

	return false, runLifecycle(ctx, conn, cfg, tlsCfg, opts)
}

// controlWriter serialises writes to the control WSS so the
// heartbeat loop and the op pump (op_complete posts) don't race —
// websockets requires single-writer semantics on a connection.
type controlWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (cw *controlWriter) sendJSON(ctx context.Context, msg map[string]any) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.conn.Write(ctx, websocket.MessageText, raw)
}

// validateWelcome enforces the cross-side identity + lifecycle
// confirmation the spec requires. Mutates “opts“ to apply the
// broker's heartbeat tunables — without that override the agent
// would always run on its compile-time defaults regardless of what
// the broker advertises.
func validateWelcome(
	welcome, hello map[string]any, cfg Config, opts *RunOptions,
) error {
	if t, _ := welcome["type"].(string); t != "welcome" {
		return fmt.Errorf("welcome: unexpected type %q", t)
	}

	// cert_fingerprint defense in depth: broker echoes what we sent,
	// so a mismatch means the cert the broker authenticated us with
	// is somehow not the cert we're holding. Treat as protocol
	// failure and let the reconnect loop handle it.
	wantFP, _ := hello["cert_fingerprint"].(string)
	gotFP, _ := welcome["cert_fingerprint"].(string)
	if wantFP != "" && gotFP != "" && wantFP != gotFP {
		return errors.New("welcome cert_fingerprint mismatch")
	}

	// system_id check (only when caller pinned one — config.SystemID
	// is 0 in test setups that don't care).
	if cfg.SystemID > 0 {
		welcomeID, ok := welcome["system_id"].(float64) // JSON numbers
		if !ok {
			return fmt.Errorf("welcome system_id missing or wrong type: %v", welcome["system_id"])
		}
		if int(welcomeID) != cfg.SystemID {
			return fmt.Errorf(
				"welcome system_id %d differs from configured %d",
				int(welcomeID), cfg.SystemID,
			)
		}
	}

	// Honour broker-supplied heartbeat tunables. Agent defaults are
	// just fallbacks for tests / disconnected demos; in production
	// the broker dictates the cadence. The values are untrusted JSON
	// floats in SECONDS — normalizeHeartbeat validates and clamps them
	// before they can reach a ticker (PRA-260).
	hbi, haveHbi := welcome["heartbeat_interval_seconds"].(float64)
	hbd, haveHbd := welcome["heartbeat_dead_seconds"].(float64)
	normalizeHeartbeat(opts, hbi, hbd, haveHbi, haveHbd, opts.Logger)
	return nil
}

// secondsToBoundedDuration converts a broker-provided heartbeat value —
// interpreted as SECONDS — into a time.Duration clamped to [minD, maxD].
//
// It returns ok=false (and the caller keeps its current value) when the input
// is unusable: NaN, ±Inf, or non-positive. Overflow is impossible by
// construction: a value larger than maxD is clamped to maxD *before* any
// multiplication into nanoseconds, so an astronomically large "seconds" float
// can never overflow the int64 Duration. A tiny positive value below minD is
// raised to minD rather than truncating toward a zero / pathological cadence.
func secondsToBoundedDuration(seconds float64, minD, maxD time.Duration) (time.Duration, bool) {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return 0, false
	}
	if seconds >= maxD.Seconds() {
		return maxD, true
	}
	if seconds <= minD.Seconds() {
		return minD, true
	}
	return time.Duration(seconds * float64(time.Second)), true
}

// normalizeHeartbeat applies broker-provided heartbeat tunables (in SECONDS) on
// top of the current opts, clamping each to its safe bound and guaranteeing
// HeartbeatDead > HeartbeatInterval afterwards. Malformed values (NaN, ±Inf,
// overflow-sized, non-positive) are ignored, leaving the current value — the
// agent default or a prior valid setting — untouched. haveInterval/haveDead say
// whether the broker actually supplied each field, so an absent field never
// disturbs the current value. Passing a nil logger is safe.
func normalizeHeartbeat(
	opts *RunOptions,
	intervalSeconds, deadSeconds float64,
	haveInterval, haveDead bool,
	logger Logger,
) {
	if haveInterval {
		if d, ok := secondsToBoundedDuration(
			intervalSeconds, minBrokerHeartbeatInterval, maxBrokerHeartbeatInterval,
		); ok {
			opts.HeartbeatInterval = d
		} else if logger != nil {
			logger.Printf(
				"ignoring invalid broker heartbeat_interval_seconds=%v", intervalSeconds,
			)
		}
	}
	if haveDead {
		if d, ok := secondsToBoundedDuration(
			deadSeconds, minBrokerHeartbeatDead, maxBrokerHeartbeatDead,
		); ok {
			opts.HeartbeatDead = d
		} else if logger != nil {
			logger.Printf(
				"ignoring invalid broker heartbeat_dead_seconds=%v", deadSeconds,
			)
		}
	}
	// The dead window must strictly exceed the interval so the watchdog can see
	// at least one heartbeat before declaring the broker dead. Independent
	// clamping (or a broker sending dead <= interval) can violate that, so bump
	// dead to one minimum-interval above the interval, capped at its max.
	if opts.HeartbeatDead <= opts.HeartbeatInterval {
		bumped := opts.HeartbeatInterval + minBrokerHeartbeatInterval
		if bumped > maxBrokerHeartbeatDead {
			bumped = maxBrokerHeartbeatDead
		}
		if logger != nil {
			logger.Printf(
				"bumped heartbeat_dead %s -> %s to exceed interval %s",
				opts.HeartbeatDead, bumped, opts.HeartbeatInterval,
			)
		}
		opts.HeartbeatDead = bumped
	}
}

// runLifecycle owns the post-welcome conversation: outbound
// heartbeats every “HeartbeatInterval“ and a recv loop that bumps
// liveness on every frame. Closes when the peer closes, when the
// liveness watchdog fires, or when ctx is cancelled.
func runLifecycle(
	ctx context.Context,
	conn *websocket.Conn,
	cfg Config,
	tlsCfg *tls.Config,
	opts RunOptions,
) error {
	lifeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// last is shared between recv loop and watchdog; we own it via
	// a small channel-backed clock so writes/reads don't race.
	resetCh := make(chan struct{}, 1)

	cw := &controlWriter{conn: conn}
	pump := newOpPump(cfg, tlsCfg, cw.sendJSON, opts.Logger, opts.OpPairTimeout)
	defer pump.shutdown()

	errCh := make(chan error, 3)

	go func() { errCh <- recvLoop(lifeCtx, conn, opts, resetCh, pump) }()
	go func() { errCh <- sendHeartbeatLoop(lifeCtx, cw, opts) }()
	go func() { errCh <- watchdog(lifeCtx, opts, resetCh) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		// First goroutine to finish wins; cancel siblings.
		cancel()
		// Drain the other two so we don't leak.
		go func() { <-errCh; <-errCh }()
		if errors.Is(err, errBrokerClosed) {
			return nil
		}
		return err
	}
}

var errBrokerClosed = errors.New("broker closed connection")

// recvLoop reads frames from the broker. Heartbeats reset liveness
// silently; bye triggers a clean reconnect; op_request / op_nonce /
// op_cancel are forwarded to the op pump (PRA-152 task #4); unknown
// types are logged and ignored (forward-compat).
func recvLoop(
	ctx context.Context,
	conn *websocket.Conn,
	opts RunOptions,
	resetCh chan<- struct{},
	pump *opPump,
) error {
	for {
		mt, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Treat any read error after handshake as a transient
			// disconnect — the reconnect loop handles backoff.
			return fmt.Errorf("recv: %w", err)
		}
		select {
		case resetCh <- struct{}{}:
		default:
		}
		if mt != websocket.MessageText {
			opts.Logger.Printf("ignoring non-text frame (type=%v len=%d)", mt, len(raw))
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal(raw, &msg); err != nil {
			opts.Logger.Printf("ignoring non-JSON control frame: %v", err)
			continue
		}
		switch t, _ := msg["type"].(string); t {
		case "heartbeat":
			// liveness already bumped above
		case "bye":
			opts.Logger.Printf("broker bye: reason=%v", msg["reason"])
			return errBrokerClosed
		case "op_request", "op_nonce", "op_cancel":
			pump.handleControl(ctx, msg)
		default:
			opts.Logger.Printf("ignoring unknown control type %q", t)
		}
	}
}

func sendHeartbeatLoop(
	ctx context.Context, cw *controlWriter, opts RunOptions,
) error {
	tk := time.NewTicker(opts.HeartbeatInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
			err := cw.sendJSON(ctx, map[string]any{
				"type": "heartbeat",
				"ts":   time.Now().UTC().Format(time.RFC3339Nano),
			})
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

// watchdog declares the broker dead after “HeartbeatDead“ of recv
// silence. The recv loop nudges resetCh on every frame; we restart
// the timer each time we see one. Uses time.Since(monotonic-now) so
// wall-clock skew can't lie to us.
func watchdog(
	ctx context.Context, opts RunOptions, resetCh <-chan struct{},
) error {
	last := time.Now()
	tk := time.NewTicker(opts.HeartbeatDead / 5)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-resetCh:
			last = time.Now()
		case <-tk.C:
			if time.Since(last) >= opts.HeartbeatDead {
				return fmt.Errorf("heartbeat_dead: idle %s", time.Since(last))
			}
		}
	}
}

func helloPayload(cfg Config, capabilities []string, fingerprint string) map[string]any {
	return map[string]any{
		"type":             "hello",
		"protocol_version": ProtocolVersion,
		"agent_version":    cfg.AgentVersion,
		"capabilities":     capabilities,
		"cert_fingerprint": "sha256:" + fingerprint,
	}
}

// buildTLSConfig loads the agent cert/key as the client identity and
// the broker CA as the only RootCAs entry — agent-ca.crt is NOT used
// here (the broker uses it to verify us; we don't use it to verify
// the broker).
func buildTLSConfig(cfg Config) (*tls.Config, string, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("load agent cert/key: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, "", errors.New("agent cert chain is empty")
	}
	leafDER := cert.Certificate[0]
	fp := sha256.Sum256(leafDER)
	fingerprint := hex.EncodeToString(fp[:])

	caRaw, err := os.ReadFile(cfg.BrokerCAFile)
	if err != nil {
		return nil, "", fmt.Errorf("read broker ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caRaw) {
		return nil, "", fmt.Errorf("broker ca: no PEM certs in %s", cfg.BrokerCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, fingerprint, nil
}

// nextBackoff doubles the current backoff with a hard cap. Pure
// helper so tests can verify the schedule without spinning a real
// connect loop.
func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		return max
	}
	return n
}

// randFloat is the source of jitter randomness, isolated as a package
// var so tests can pin it. Returns a value in [0.0, 1.0).
var randFloat = rand.Float64

// jitter applies "equal jitter" to a backoff duration: it returns a
// value in [d/2, d). Every agent that redials after a broker
// outage/graceful-drain therefore waits a *different* amount instead of
// reconnecting in lockstep on the same 1/2/4/…/60s schedule, which would
// otherwise stampede the broker the instant it comes back (thundering
// herd). Pure given randFloat so the bounds are testable.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	half := d / 2
	return half + time.Duration(randFloat()*float64(half))
}

// sleepWithCancel returns false if the context cancels mid-sleep.
func sleepWithCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
