// Package cli holds the agent's subcommand implementations. Each
// subcommand is a single exported function taking “args
// []string“ (the args after the subcommand name) and returning an
// “int“ exit code so main can “os.Exit“ cleanly.
//
// Stylistically each subcommand owns its own “flag.FlagSet“ so the
// dispatcher stays a dumb switch and each command can document its
// own flags via “-h“.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Result is the exit code a subcommand wants the process to surface.
const (
	ExitOK           = 0
	ExitUsage        = 2
	ExitRuntimeError = 1
)

// newFlagSet returns a flag.FlagSet whose Usage prints to “out“ so
// tests can capture help text without intercepting os.Stderr.
func newFlagSet(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

// fatalf is a small wrapper that prints to stderr and returns
// ExitRuntimeError so callers can “return cli.fatalf(...)“.
func fatalf(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "praxis-agent: "+format+"\n", args...)
	return ExitRuntimeError
}
