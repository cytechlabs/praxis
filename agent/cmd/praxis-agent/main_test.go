package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cytechlabs/praxis/agent/internal/cli"
	"github.com/cytechlabs/praxis/agent/internal/identity"
)

// captureStdout swaps os.Stdout for a pipe and returns whatever the
// inner func wrote. Lets us assert subcommand output without touching
// the real stdout of `go test`.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("pipe close: %v", err)
	}
	os.Stdout = orig
	return <-done
}

// signCSRForTest runs the gen-csr output through a throwaway CA so
// install-cert sees a cert that genuinely belongs to the agent's
// key. Mirrors what the real Vault praxis-agent-ca path does at sign
// time (replaces CN + SANs with backend-controlled values).
func signCSRForTest(t *testing.T, csrPEM []byte, systemID int) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr pem decode")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	// Mint a throwaway CA whose key we hold so we can sign leaf certs
	// that genuinely belong to ``csr.PublicKey``.
	caKeyPEM, _, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("ca keypair: %v", err)
	}
	caKey, err := identity.LoadKey(writeTempPEM(t, caKeyPEM))
	if err != nil {
		t.Fatalf("ca load: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self sign ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(1000 + systemID)),
		Subject: pkix.Name{
			CommonName: "system-" + itoa(systemID) + ".agent.praxis.internal",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// makeStandaloneSelfSignedCertPEM returns a freshly-minted self-
// signed CA-shaped cert PEM with the supplied CN. Used by the
// end-to-end test to fabricate realistic agent_ca / broker_ca bundle
// entries that pass install-cert's x509 validation.
func makeStandaloneSelfSignedCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	keyPEM, _, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	key, err := identity.LoadKey(writeTempPEM(t, keyPEM))
	if err != nil {
		t.Fatalf("ca load: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self sign ca cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeTempPEM(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write tmp pem: %v", err)
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestEndToEndSuccessCondition exercises the full PRA-152 task #2
// flow: gen-keypair -> gen-csr -> (sign with throwaway CA) ->
// install-cert -> show-config -> assert cert metadata is correctly
// reported.
//
// This is the success condition from the task #2 design lock.
func TestEndToEndSuccessCondition(t *testing.T) {
	dir := t.TempDir()

	// 1. gen-keypair
	if rc := run([]string{"gen-keypair", "--config-dir", dir}); rc != 0 {
		t.Fatalf("gen-keypair exit=%d", rc)
	}
	keyPath := filepath.Join(dir, "agent.key")
	if st, err := os.Stat(keyPath); err != nil {
		t.Fatalf("stat key: %v", err)
	} else if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode=%o want 0600", st.Mode().Perm())
	}

	// 2. gen-csr (capture PEM from stdout)
	var csrPEM []byte
	out := captureStdout(t, func() {
		if rc := run([]string{"gen-csr", "--config-dir", dir}); rc != 0 {
			t.Fatalf("gen-csr exit=%d", rc)
		}
	})
	csrPEM = []byte(out)
	if !strings.Contains(out, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("csr stdout missing PEM header:\n%s", out)
	}

	// 3. throwaway-CA signs the CSR — stands in for Vault PRA-150 in
	// pure-Go test land
	leafPEM := signCSRForTest(t, csrPEM, 42)
	leafPath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(leafPath, leafPEM, 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}

	// 4. fabricate the /agent/ca-bundle JSON shape with REAL self-
	// signed certs — install-cert validates both as x509 PEMs before
	// writing trust anchors to disk.
	bundle := map[string]string{
		"agent_ca":  string(makeStandaloneSelfSignedCertPEM(t, "fake-agent-ca")),
		"broker_ca": string(makeStandaloneSelfSignedCertPEM(t, "fake-broker-ca")),
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	bb, _ := json.Marshal(bundle)
	if err := os.WriteFile(bundlePath, bb, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	// 5. install-cert
	rc := run([]string{
		"install-cert",
		"--config-dir", dir,
		"--cert", leafPath,
		"--bundle", bundlePath,
		"--backend-url", "https://praxis.example.com",
		"--broker-url", "wss://agent-broker.example.com:8443",
		"--system-id", "42",
	})
	if rc != 0 {
		t.Fatalf("install-cert exit=%d", rc)
	}
	for _, name := range []string{"agent.crt", "agent-ca.crt", "broker-ca.crt", "config.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	// 6. show-config — assert the success condition from the design
	// lock: prints fingerprint, NotAfter, and config fields.
	out = captureStdout(t, func() {
		if rc := run([]string{"show-config", "--config-dir", dir}); rc != 0 {
			t.Fatalf("show-config exit=%d", rc)
		}
	})
	for _, want := range []string{
		"backend_url: https://praxis.example.com",
		"broker_url:  wss://agent-broker.example.com:8443",
		"system_id:   42",
		"cert_subject:     CN=system-42.agent.praxis.internal",
		"cert_fingerprint: sha256:",
		"cert_not_after:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show-config output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestInstallCertRejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	if rc := run([]string{"gen-keypair", "--config-dir", dir}); rc != 0 {
		t.Fatalf("gen-keypair: %d", rc)
	}

	// Build a cert that belongs to a DIFFERENT key than the one
	// install-cert will load.
	_, otherKey, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wrong"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("self sign: %v", err)
	}
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	wrongPath := filepath.Join(t.TempDir(), "wrong.pem")
	if err := os.WriteFile(wrongPath, wrongPEM, 0o644); err != nil {
		t.Fatalf("write wrong cert: %v", err)
	}

	// Real CA PEMs so this test reaches the pubkey-mismatch check
	// (the bundle validator now rejects non-cert strings earlier).
	bundlePath := filepath.Join(t.TempDir(), "b.json")
	bb, _ := json.Marshal(map[string]string{
		"agent_ca":  string(makeStandaloneSelfSignedCertPEM(t, "fake-agent-ca")),
		"broker_ca": string(makeStandaloneSelfSignedCertPEM(t, "fake-broker-ca")),
	})
	if err := os.WriteFile(bundlePath, bb, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	rc := run([]string{
		"install-cert",
		"--config-dir", dir,
		"--cert", wrongPath,
		"--bundle", bundlePath,
		"--backend-url", "https://x",
		"--broker-url", "wss://x",
		"--system-id", "1",
	})
	if rc == 0 {
		t.Fatal("expected non-zero exit on cert/key mismatch")
	}
	// Cert file must NOT have been written when the validation fails.
	if _, err := os.Stat(filepath.Join(dir, "agent.crt")); !os.IsNotExist(err) {
		t.Fatalf("agent.crt should not exist after rejected install: %v", err)
	}
}

// TestInstallCertRejectsInvalidCABundleEntries proves install-cert
// validates both CA values as parseable x509 CERTIFICATE PEMs before
// touching the filesystem. Without this guard a malformed
// /agent/ca-bundle response would install successfully and surface
// later as a confusing TLS error during broker dial.
func TestInstallCertRejectsInvalidCABundleEntries(t *testing.T) {
	cases := []struct {
		name     string
		agentCA  string
		brokerCA string
	}{
		{
			name:     "agent_ca is not PEM",
			agentCA:  "this is not a cert",
			brokerCA: "", // populated per-case below
		},
		{
			name:     "broker_ca is not PEM",
			agentCA:  "", // populated per-case below
			brokerCA: "this is not a cert",
		},
		{
			name: "agent_ca PEM block is wrong type",
			agentCA: string(pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3},
			})),
			brokerCA: "", // populated per-case below
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if rc := run([]string{"gen-keypair", "--config-dir", dir}); rc != 0 {
				t.Fatalf("gen-keypair: %d", rc)
			}

			// Mint a real cert that genuinely matches the local key
			// so the bundle check is what fails (not the pubkey check).
			keyBytes, err := os.ReadFile(filepath.Join(dir, "agent.key"))
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			localKey, err := identity.LoadKey(writeTempPEM(t, keyBytes))
			if err != nil {
				t.Fatalf("load key: %v", err)
			}
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "valid-cert"},
				NotBefore:    time.Now().Add(-time.Minute),
				NotAfter:     time.Now().Add(time.Hour),
			}
			der, err := x509.CreateCertificate(
				rand.Reader, tmpl, tmpl, &localKey.PublicKey, localKey,
			)
			if err != nil {
				t.Fatalf("self sign: %v", err)
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			certPath := filepath.Join(t.TempDir(), "cert.pem")
			if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
				t.Fatalf("write cert: %v", err)
			}

			// Fill in the "real" half of the bundle so we isolate the
			// failure to the corrupted side.
			realCA := string(makeStandaloneSelfSignedCertPEM(t, "real-ca"))
			agentCA := tc.agentCA
			brokerCA := tc.brokerCA
			if agentCA == "" {
				agentCA = realCA
			}
			if brokerCA == "" {
				brokerCA = realCA
			}
			bundlePath := filepath.Join(t.TempDir(), "bundle.json")
			bb, _ := json.Marshal(map[string]string{
				"agent_ca": agentCA, "broker_ca": brokerCA,
			})
			if err := os.WriteFile(bundlePath, bb, 0o644); err != nil {
				t.Fatalf("write bundle: %v", err)
			}

			rc := run([]string{
				"install-cert",
				"--config-dir", dir,
				"--cert", certPath,
				"--bundle", bundlePath,
				"--backend-url", "https://x",
				"--broker-url", "wss://x",
				"--system-id", "1",
			})
			if rc == 0 {
				t.Fatal("expected non-zero exit on bad CA bundle")
			}
			// No partial install: agent.crt + the CA files must not
			// exist when the bundle was rejected.
			for _, name := range []string{"agent.crt", "agent-ca.crt", "broker-ca.crt", "config.json"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
					t.Fatalf("%s should not exist after rejected install: %v", name, err)
				}
			}
		})
	}
}

func TestUnknownSubcommandReturnsUsage(t *testing.T) {
	rc := run([]string{"not-a-command"})
	if rc != 2 {
		t.Fatalf("expected exit 2, got %d", rc)
	}
}

func TestNoArgsPrintsHelp(t *testing.T) {
	rc := run(nil)
	if rc != 2 {
		t.Fatalf("expected exit 2, got %d", rc)
	}
}

// Sanity: the embedded ECDSA-only assumption. If a future Go change
// makes ParsePKCS8PrivateKey return *ecdsa.PrivateKey for non-EC keys
// (it won't, but defense in depth), this test catches it.
func TestLoadKeyRefusesNonECKey(t *testing.T) {
	pemBytes, err := pemEncodeBogusKey()
	if err != nil {
		t.Fatalf("bogus key: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.key"), pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := identity.LoadKey(filepath.Join(dir, "agent.key")); err == nil {
		t.Fatal("expected error loading bogus key")
	}
}

// pemEncodeBogusKey writes a PEM "PRIVATE KEY" block with payload
// that isn't a valid PKCS#8 EC key.
func pemEncodeBogusKey() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3, 4}}), nil
}

// Ensure the version printer doesn't panic and contains the version
// var (defaults to "dev" until -ldflags overrides it).
func TestVersionSubcommand(t *testing.T) {
	out := captureStdout(t, func() {
		if rc := run([]string{"version"}); rc != 0 {
			t.Fatalf("version exit=%d", rc)
		}
	})
	if !strings.Contains(out, "praxis-agent") {
		t.Fatalf("missing praxis-agent in version output: %s", out)
	}
}

// The human-readable line has to carry everything that identifies the
// build, because it is what an operator pastes into a bug report.
func TestVersionLineReportsBuildIdentity(t *testing.T) {
	out := captureStdout(t, func() {
		if rc := run([]string{"version"}); rc != 0 {
			t.Fatalf("version exit=%d", rc)
		}
	})
	info := currentBuildInfo()
	for _, want := range []string{
		info.Version,
		shortCommit(info.Commit),
		info.GoVersion,
		info.OS + "/" + info.Arch,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("version output missing %q: %s", want, out)
		}
	}
}

// The commit must be stamped in full. A git short hash is only as long as
// the local object database needs it to be, so it is not a stable way to
// name the source a binary came from.
func TestStampedCommitIsAFullSHA(t *testing.T) {
	const stamped = "0123456789abcdef0123456789abcdef01234567"
	original := Commit
	t.Cleanup(func() { Commit = original })
	Commit = stamped

	out := captureStdout(t, func() {
		if rc := run([]string{"version", "--json"}); rc != 0 {
			t.Fatalf("version --json exit=%d", rc)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, out)
	}
	if got["commit"] != stamped {
		t.Fatalf("json commit = %v, want the full 40-character SHA %s", got["commit"], stamped)
	}

	line := captureStdout(t, func() {
		if rc := run([]string{"version"}); rc != 0 {
			t.Fatalf("version exit=%d", rc)
		}
	})
	if !strings.Contains(line, stamped[:commitDisplayLen]) {
		t.Fatalf("human output missing the abbreviated commit: %s", line)
	}
	if strings.Contains(line, stamped) {
		t.Fatalf("human output should abbreviate the commit, got: %s", line)
	}
}

// shortCommit must not slice past the end of a value that is not a SHA.
func TestShortCommitHandlesNonSHAValues(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"unknown", "unknown"},
		{"", ""},
		{"0123456789ab", "0123456789ab"},
		{"0123456789abc", "0123456789ab"},
	} {
		if got := shortCommit(tc.in); got != tc.want {
			t.Fatalf("shortCommit(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Tooling records which artifact is installed on a host by parsing this
// output, so the field names are a contract.
func TestVersionJSONReportsBuildIdentity(t *testing.T) {
	for _, args := range [][]string{
		{"version", "--json"},
		{"--version", "--json"},
	} {
		out := captureStdout(t, func() {
			if rc := run(args); rc != 0 {
				t.Fatalf("%v exit=%d", args, rc)
			}
		})
		var got map[string]any
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%v produced invalid JSON: %v (%s)", args, err, out)
		}
		info := currentBuildInfo()
		want := map[string]any{
			"version":    info.Version,
			"commit":     info.Commit,
			"go_version": info.GoVersion,
			"os":         info.OS,
			"arch":       info.Arch,
			"stamped":    info.Stamped,
		}
		if len(got) != len(want) {
			t.Fatalf("%v field set changed: got %v want %v", args, got, want)
		}
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("%v field %q = %v, want %v", args, key, got[key], value)
			}
		}
	}
}

// An unstamped binary must say so rather than looking like a release.
func TestVersionReportsUnstampedLocalBuilds(t *testing.T) {
	if currentBuildInfo().Stamped {
		t.Fatalf("test binary is built without -ldflags, expected stamped=false")
	}
}

// A typo must not silently print the default output and exit 0.
func TestVersionRejectsUnknownArguments(t *testing.T) {
	for _, args := range [][]string{
		{"version", "--nope"},
		{"version", "extra"},
	} {
		if rc := run(args); rc != cli.ExitUsage {
			t.Fatalf("%v exit=%d want %d", args, rc, cli.ExitUsage)
		}
	}
}

// TestGenKeypairForceCorrectsPermissiveMode is the PRA-262 key regression:
// `gen-keypair --force` over an existing world-readable agent.key must leave the
// final key at 0600 and regenerate a valid key with no temp-file leak.
func TestGenKeypairForceCorrectsPermissiveMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o666} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "agent.key")
			// Seed a pre-existing permissive key file.
			if err := os.WriteFile(keyPath, []byte("stale-key\n"), 0o600); err != nil {
				t.Fatalf("seed key: %v", err)
			}
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatalf("chmod seed: %v", err)
			}
			if rc := run([]string{"gen-keypair", "--config-dir", dir, "--force"}); rc != 0 {
				t.Fatalf("gen-keypair --force exit=%d", rc)
			}
			st, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("key mode=%o want 0600 (seeded %o)", st.Mode().Perm(), mode)
			}
			// A real EC key was written, not the seeded stub.
			if _, err := identity.LoadKey(keyPath); err != nil {
				t.Fatalf("regenerated key invalid: %v", err)
			}
			if leaks, _ := filepath.Glob(filepath.Join(dir, ".agent.key.tmp-*")); len(leaks) != 0 {
				t.Fatalf("temp files lingered: %v", leaks)
			}
		})
	}
}
