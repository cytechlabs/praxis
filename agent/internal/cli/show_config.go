package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/cytechlabs/praxis/agent/internal/config"
	"github.com/cytechlabs/praxis/agent/internal/identity"
)

// ShowConfig prints a human-readable summary of the agent's current
// install state: which config dir is in use, which files exist, what
// system_id + URLs are configured, and the cert's
// subject / fingerprint / NotAfter when present.
//
// Useful as the success-condition check after install-cert and as a
// diagnostic when something is misconfigured.
func ShowConfig(args []string) int {
	fs := newFlagSet("show-config", os.Stderr)
	configDir := fs.String("config-dir", "", "override config dir (default /etc/praxis-agent or $PRAXIS_AGENT_CONFIG_DIR)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	dir := config.Resolve(*configDir)
	fmt.Printf("config_dir: %s\n", dir)

	cfg, err := config.Load(dir)
	switch {
	case err == nil:
		fmt.Printf("backend_url: %s\n", cfg.BackendURL)
		fmt.Printf("broker_url:  %s\n", cfg.BrokerURL)
		fmt.Printf("system_id:   %d\n", cfg.SystemID)
	case errors.Is(err, os.ErrNotExist):
		fmt.Println("config:      <not installed>")
	default:
		return fatalf("%v", err)
	}

	certPath := config.Path(dir, config.CertFile)
	cert, err := identity.ParseCert(certPath)
	switch {
	case err == nil:
		fp := sha256.Sum256(cert.Raw)
		fmt.Printf("cert_subject:     %s\n", cert.Subject.String())
		fmt.Printf("cert_serial:      %x\n", cert.SerialNumber)
		fmt.Printf("cert_fingerprint: sha256:%s\n", hex.EncodeToString(fp[:]))
		fmt.Printf("cert_not_before:  %s\n", cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
		fmt.Printf("cert_not_after:   %s\n", cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
		uris := make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			uris = append(uris, u.String())
		}
		fmt.Printf("cert_uri_sans:    %v\n", uris)
	case errors.Is(err, os.ErrNotExist):
		fmt.Println("cert:        <not installed>")
	default:
		return fatalf("%v", err)
	}
	return ExitOK
}
