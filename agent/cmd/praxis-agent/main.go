// Package main is the Praxis thin agent entrypoint (PRA-152).
//
// Subcommand dispatcher only. Subcommand implementations live in
// agent/internal/cli; identity + config primitives live in
// agent/internal/{identity,config}.
//
// Subcommands wired in PRA-152 task #2 (local primitives only — no
// network calls; backend orchestrates over SSH):
//
//	gen-keypair      generate EC P-256 key, write <dir>/agent.key
//	gen-csr          load key, print PKCS#10 CSR PEM to stdout
//	install-cert     write Vault-signed cert + CA bundle + config.json
//	show-config      dump current install state for debugging
//
// Tunnel client / op handler / exec primitives land in subsequent
// PRA-152 commits.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/cytechlabs/praxis/agent/internal/cli"
)

// Version + Commit are overridden at build time via -ldflags; see
// agent/Makefile.
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	// The connect subcommand stamps Version into the hello payload;
	// keep the cli package's mirror in sync with whatever -ldflags
	// supplied us at build time.
	cli.AgentVersion = Version
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printHelp()
		return cli.ExitUsage
	}
	switch args[0] {
	case "gen-keypair":
		return cli.GenKeypair(args[1:])
	case "gen-csr":
		return cli.GenCSR(args[1:])
	case "install-cert":
		return cli.InstallCert(args[1:])
	case "show-config":
		return cli.ShowConfig(args[1:])
	case "connect":
		return cli.Connect(args[1:])
	case "version", "--version", "-v":
		printVersion()
		return cli.ExitOK
	case "help", "--help", "-h":
		printHelp()
		return cli.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "praxis-agent: unknown subcommand %q\n", args[0])
		printHelp()
		return cli.ExitUsage
	}
}

func printVersion() {
	fmt.Printf("praxis-agent %s (commit %s, %s/%s, %s)\n",
		Version, Commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func printHelp() {
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), `praxis-agent %s

usage: praxis-agent <subcommand> [flags]

subcommands:
  gen-keypair    generate the agent's EC P-256 private key
  gen-csr        print a PKCS#10 CSR for the local key (placeholder
                 CN/SAN; backend rewrites at sign time)
  install-cert   install a Vault-signed cert + CA bundle + config
  show-config    print current install state (config + cert metadata)
  connect        dial the broker (mTLS WSS), maintain hello/welcome +
                 heartbeat; reconnects forever until SIGINT/SIGTERM.
                 --exit-after-welcome runs a one-shot smoke check.
  version        print version and exit
  help           this message

run "praxis-agent <subcommand> -h" for per-subcommand flags.

config dir resolution: --config-dir flag wins, else
PRAXIS_AGENT_CONFIG_DIR env, else /etc/praxis-agent.
`, Version)
}
