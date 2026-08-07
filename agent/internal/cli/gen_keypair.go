package cli

import (
	"fmt"
	"os"

	"github.com/cytechlabs/praxis/agent/internal/config"
	"github.com/cytechlabs/praxis/agent/internal/identity"
)

// GenKeypair generates a fresh EC P-256 keypair and writes the
// PKCS#8-encoded private key to <config-dir>/agent.key with mode
// 0600. Refuses to overwrite an existing key unless --force is set.
func GenKeypair(args []string) int {
	fs := newFlagSet("gen-keypair", os.Stderr)
	configDir := fs.String("config-dir", "", "override config dir (default /etc/praxis-agent or $PRAXIS_AGENT_CONFIG_DIR)")
	force := fs.Bool("force", false, "overwrite an existing agent.key")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	dir := config.Resolve(*configDir)
	if _, err := config.EnsureDir(dir); err != nil {
		return fatalf("%v", err)
	}

	keyPath := config.Path(dir, config.KeyFile)
	if _, err := os.Stat(keyPath); err == nil && !*force {
		return fatalf("%s already exists; pass --force to overwrite", keyPath)
	}

	pemBytes, _, err := identity.GenerateKeypair()
	if err != nil {
		return fatalf("%v", err)
	}
	// PRA-262: WriteFileAtomic (temp + explicit chmod 0600 + atomic rename) so a
	// forced overwrite of an existing permissive agent.key still ends at 0600 —
	// os.WriteFile would have preserved the old file's mode.
	if err := config.WriteFileAtomic(keyPath, pemBytes, config.ModeKey); err != nil {
		return fatalf("write %s: %v", keyPath, err)
	}
	fmt.Printf("wrote %s (mode %o)\n", keyPath, config.ModeKey)
	return ExitOK
}
