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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/cytechlabs/praxis/agent/internal/cli"
)

// Version + Commit are overridden at build time via -ldflags; see
// agent/Makefile. The release value of Version comes from agent/VERSION,
// which is the single source of truth for the agent's released version.
// Commit is the full 40-character source commit SHA: a git short hash is
// only as long as the local object database requires, so it is not a
// stable identifier for the source a binary was built from.
var (
	Version = "dev"
	Commit  = "unknown"
)

// commitDisplayLen is how much of the commit SHA the human-readable line
// shows. The full value stays available in the JSON output.
const commitDisplayLen = 12

// shortCommit abbreviates a commit SHA for display. Values shorter than the
// display length, such as the "unknown" placeholder in an unstamped build,
// are returned unchanged.
func shortCommit(commit string) string {
	if len(commit) <= commitDisplayLen {
		return commit
	}
	return commit[:commitDisplayLen]
}

// buildInfo is the inspectable release identity of this binary.
//
// Every field is determined by the build inputs alone: the released
// version, the source commit, the Go toolchain, and the target platform.
// No wall-clock build time is recorded, so rebuilding the same commit
// with the same toolchain reproduces an identical binary. Reproducibility
// is checked by comparing artifact checksums, not by reading a timestamp
// out of the binary.
//
// Commit is reported in full so the binary can be traced back to an exact
// source revision without depending on how a particular checkout
// abbreviates hashes.
type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	// Stamped reports whether release metadata was injected at link
	// time. A false value means this is a local build, not a published
	// release artifact.
	Stamped bool `json:"stamped"`
}

func currentBuildInfo() buildInfo {
	return buildInfo{
		Version:   Version,
		Commit:    Commit,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Stamped:   Version != "dev" && Commit != "unknown",
	}
}

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
		return versionCmd(args[1:])
	case "help", "--help", "-h":
		printHelp()
		return cli.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "praxis-agent: unknown subcommand %q\n", args[0])
		printHelp()
		return cli.ExitUsage
	}
}

// versionCmd prints the binary's build identity. The default output is
// a single human-readable line; --json emits the same fields in a stable
// machine-readable shape so tooling can record exactly which artifact is
// installed on a host.
func versionCmd(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print build metadata as JSON")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "praxis-agent: version takes no positional arguments\n")
		return cli.ExitUsage
	}

	info := currentBuildInfo()
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(info); err != nil {
			fmt.Fprintf(os.Stderr, "praxis-agent: %v\n", err)
			return cli.ExitRuntimeError
		}
		return cli.ExitOK
	}
	fmt.Printf("praxis-agent %s (commit %s, %s/%s, %s)\n",
		info.Version, shortCommit(info.Commit), info.OS, info.Arch, info.GoVersion)
	return cli.ExitOK
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
  version        print build identity (--json for machine-readable
                 version, commit, toolchain, and target platform)
  help           this message

run "praxis-agent <subcommand> -h" for per-subcommand flags.

config dir resolution: --config-dir flag wins, else
PRAXIS_AGENT_CONFIG_DIR env, else /etc/praxis-agent.
`, Version)
}
