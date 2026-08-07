package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cytechlabs/praxis/agent/internal/config"
	"github.com/cytechlabs/praxis/agent/internal/tunnel"
)

// AgentVersion is set by main at process start (mirrors main.Version)
// so the connect subcommand can stamp the right value into the
// hello payload without an awkward import cycle.
var AgentVersion = "dev"

// Connect dials the broker, runs hello/welcome + heartbeat lifecycle,
// and reconnects on disconnect with exponential backoff. Cancels
// cleanly on SIGINT/SIGTERM.
//
// --exit-after-welcome turns on a bounded smoke run: the subcommand
// returns 0 immediately after the first successful welcome. Used by
// CI + operator sanity checks to prove mTLS + handshake without
// running forever.
func Connect(args []string) int {
	fs := newFlagSet("connect", os.Stderr)
	configDir := fs.String("config-dir", "", "override config dir (default /etc/praxis-agent or $PRAXIS_AGENT_CONFIG_DIR)")
	exitAfterWelcome := fs.Bool("exit-after-welcome", false, "exit 0 immediately after the first successful welcome (smoke mode)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	dir := config.Resolve(*configDir)
	cfg, err := config.Load(dir)
	if err != nil {
		return fatalf("%v", err)
	}
	if cfg.BrokerURL == "" {
		return fatalf("config %s has empty broker_url", config.Path(dir, config.ConfigFile))
	}

	tcfg := tunnel.Config{
		BrokerURL:    cfg.BrokerURL,
		CertFile:     config.Path(dir, config.CertFile),
		KeyFile:      config.Path(dir, config.KeyFile),
		BrokerCAFile: config.Path(dir, config.BrokerCAFile),
		AgentVersion: AgentVersion,
		SystemID:     cfg.SystemID,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	opts := tunnel.RunOptions{ExitAfterWelcome: *exitAfterWelcome}
	if err := tunnel.Run(ctx, tcfg, opts); err != nil {
		// ctx cancellation is normal shutdown — don't error-exit.
		if errors.Is(err, context.Canceled) {
			return ExitOK
		}
		return fatalf("%v", err)
	}
	if !*exitAfterWelcome {
		fmt.Fprintln(os.Stderr, "praxis-agent: tunnel shut down cleanly")
	}
	return ExitOK
}
