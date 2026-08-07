package cli

import (
	"fmt"
	"os"

	"github.com/cytechlabs/praxis/agent/internal/config"
	"github.com/cytechlabs/praxis/agent/internal/identity"
)

// GenCSR loads <config-dir>/agent.key and prints a PKCS#10 CSR PEM
// to stdout. The CSR carries placeholder CN + URI SAN (see
// identity.CSRPlaceholder*); backend rewrites these at sign time.
//
// Designed for piping straight into curl:
//
//	praxis-agent gen-csr | curl -X POST .../agent/bootstrap/<id> \
//	     -H "Content-Type: application/x-pem-file" --data-binary @-
func GenCSR(args []string) int {
	fs := newFlagSet("gen-csr", os.Stderr)
	configDir := fs.String("config-dir", "", "override config dir (default /etc/praxis-agent or $PRAXIS_AGENT_CONFIG_DIR)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	dir := config.Resolve(*configDir)
	keyPath := config.Path(dir, config.KeyFile)
	key, err := identity.LoadKey(keyPath)
	if err != nil {
		return fatalf("%v", err)
	}
	csr, err := identity.BuildCSR(key)
	if err != nil {
		return fatalf("%v", err)
	}
	if _, err := fmt.Fprint(os.Stdout, string(csr)); err != nil {
		return fatalf("write csr: %v", err)
	}
	return ExitOK
}
