package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cytechlabs/praxis/agent/internal/config"
	"github.com/cytechlabs/praxis/agent/internal/identity"
)

// CABundle mirrors the JSON shape that backend's
// “GET /agent/ca-bundle“ returns. Field names match the wire
// format exactly so the file the operator/installer hands us can be
// the literal HTTP response body.
type CABundle struct {
	AgentCA  string `json:"agent_ca"`
	BrokerCA string `json:"broker_ca"`
}

// InstallCert validates that a Vault-signed cert matches the local
// agent.key, then writes the cert + both CA roots + a config.json
// into the config dir. Refuses to install when the cert pubkey
// doesn't match the local key (saves the operator from a confusing
// failure on first tunnel dial).
func InstallCert(args []string) int {
	fs := newFlagSet("install-cert", os.Stderr)
	configDir := fs.String("config-dir", "", "override config dir (default /etc/praxis-agent or $PRAXIS_AGENT_CONFIG_DIR)")
	certPath := fs.String("cert", "", "path to PEM-encoded signed agent cert (required)")
	bundlePath := fs.String("bundle", "", "path to /agent/ca-bundle JSON: {\"agent_ca\":..., \"broker_ca\":...} (required)")
	backendURL := fs.String("backend-url", "", "main backend URL — written to config.json (required)")
	brokerURL := fs.String("broker-url", "", "broker WSS URL — written to config.json (required)")
	systemID := fs.Int("system-id", 0, "system_id assigned by backend — written to config.json (required, > 0)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	missing := []string{}
	if *certPath == "" {
		missing = append(missing, "--cert")
	}
	if *bundlePath == "" {
		missing = append(missing, "--bundle")
	}
	if *backendURL == "" {
		missing = append(missing, "--backend-url")
	}
	if *brokerURL == "" {
		missing = append(missing, "--broker-url")
	}
	if *systemID <= 0 {
		missing = append(missing, "--system-id")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "praxis-agent: missing required flag(s): %v\n", missing)
		return ExitUsage
	}

	dir := config.Resolve(*configDir)
	if _, err := config.EnsureDir(dir); err != nil {
		return fatalf("%v", err)
	}

	// Pubkey-mismatch check happens BEFORE any file is written so a
	// bad pairing leaves no partial install.
	keyPath := config.Path(dir, config.KeyFile)
	key, err := identity.LoadKey(keyPath)
	if err != nil {
		return fatalf("%v", err)
	}
	cert, err := identity.ParseCert(*certPath)
	if err != nil {
		return fatalf("%v", err)
	}
	if err := identity.PublicKeysMatch(cert, key); err != nil {
		return fatalf("cert/key pair invalid: %v", err)
	}

	bundleRaw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fatalf("read %s: %v", *bundlePath, err)
	}
	var bundle CABundle
	if err := json.Unmarshal(bundleRaw, &bundle); err != nil {
		return fatalf("parse %s: %v", *bundlePath, err)
	}
	if bundle.AgentCA == "" || bundle.BrokerCA == "" {
		return fatalf("bundle missing agent_ca or broker_ca")
	}
	// Validate both CA values parse as real x509 CERTIFICATE PEMs
	// BEFORE writing anything. Without this, a malformed bundle
	// installs cleanly and the failure surfaces much later as a
	// confusing TLS error during broker dial.
	if _, err := identity.ParseCertPEM([]byte(bundle.AgentCA)); err != nil {
		return fatalf("bundle agent_ca: %v", err)
	}
	if _, err := identity.ParseCertPEM([]byte(bundle.BrokerCA)); err != nil {
		return fatalf("bundle broker_ca: %v", err)
	}

	certRaw, err := os.ReadFile(*certPath)
	if err != nil {
		return fatalf("re-read %s: %v", *certPath, err)
	}

	// Marshal config.json up front so a marshal failure is caught before any
	// live file is touched — it's part of the same transactional set.
	cfg := &config.Config{
		BackendURL: *backendURL,
		BrokerURL:  *brokerURL,
		SystemID:   *systemID,
	}
	cfgRaw, err := config.MarshalConfig(cfg)
	if err != nil {
		return fatalf("%v", err)
	}

	// PRA-261: publish the whole identity set transactionally. Every file is
	// staged + fsync'd first, then published with atomic renames and
	// backup/rollback, so a failure leaves the previous coherent set intact
	// rather than a mixed old/new install that could brick reconnect. agent.key
	// is never part of the set and is left untouched.
	set := []config.FileSpec{
		{Name: config.CertFile, Data: certRaw, Mode: config.ModeCert},
		{Name: config.AgentCAFile, Data: []byte(bundle.AgentCA), Mode: config.ModeCert},
		{Name: config.BrokerCAFile, Data: []byte(bundle.BrokerCA), Mode: config.ModeCert},
		{Name: config.ConfigFile, Data: cfgRaw, Mode: config.ModeConfig},
	}
	if err := config.PublishSet(dir, set); err != nil {
		return fatalf("%v", err)
	}

	fmt.Printf("installed agent identity into %s (system_id=%d, NotAfter=%s)\n",
		dir, *systemID, cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	return ExitOK
}
