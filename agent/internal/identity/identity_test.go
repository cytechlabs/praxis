package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateKeypairProducesParsablePKCS8(t *testing.T) {
	pemBytes, key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if key == nil {
		t.Fatal("nil key")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY pem, got %#v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pkcs8: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ECDSA, got %T", parsed)
	}
}

func TestLoadKeyRoundTrip(t *testing.T) {
	pemBytes, want, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadKey(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// PKIX-DER round trip avoids touching the deprecated
	// big.Int X/Y fields (Go 1.26 SA1019).
	wantDER, err := x509.MarshalPKIXPublicKey(&want.PublicKey)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	gotDER, err := x509.MarshalPKIXPublicKey(&got.PublicKey)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	if !bytes.Equal(wantDER, gotDER) {
		t.Fatal("loaded key does not match generated key")
	}
}

func TestBuildCSRCarriesPlaceholderURISAN(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	csrPEM, err := BuildCSR(key)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected CSR pem, got %#v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature: %v", err)
	}
	if csr.Subject.CommonName != CSRPlaceholderCN {
		t.Fatalf("CN=%q want %q", csr.Subject.CommonName, CSRPlaceholderCN)
	}
	if len(csr.URIs) != 1 {
		t.Fatalf("expected 1 URI SAN, got %d", len(csr.URIs))
	}
	if csr.URIs[0].String() != CSRPlaceholderURI {
		t.Fatalf("URI=%q want %q", csr.URIs[0].String(), CSRPlaceholderURI)
	}
}

// makeSelfSignedCertFor produces a throwaway cert that legitimately
// belongs to “key“ so install-cert validation can be exercised
// without a real Vault round trip.
func makeSelfSignedCertFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self sign: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPublicKeysMatchAcceptsValidPair(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := makeSelfSignedCertFor(t, key)
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := PublicKeysMatch(cert, key); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestPublicKeysMatchRejectsMismatchedKey(t *testing.T) {
	_, certKey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	_, otherKey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	certPEM := makeSelfSignedCertFor(t, certKey)
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := PublicKeysMatch(cert, otherKey); err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

func TestPublicKeysMatchRejectsNonECDSACert(t *testing.T) {
	// Build a valid certificate with an RSA-shaped public key field by
	// hand-crafting the parsed struct — easier than minting a real RSA
	// cert.
	cert := &x509.Certificate{
		PublicKey: &struct{ X, Y *big.Int }{X: big.NewInt(1), Y: big.NewInt(2)},
	}
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := PublicKeysMatch(cert, key); err == nil {
		t.Fatal("expected non-ECDSA error, got nil")
	}
}

func TestParseCertRejectsNonCertPEM(t *testing.T) {
	keyPEM, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := ParseCertPEM(keyPEM); err == nil {
		t.Fatal("expected error parsing key PEM as cert, got nil")
	}
}

// Ensure curve mismatch is detected — defensive: the agent only ever
// generates P-256 keys, but a future bug could mint a P-384 key while
// the cert is P-256 (or vice versa).
func TestPublicKeysMatchRejectsCurveMismatch(t *testing.T) {
	_, p256, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384: %v", err)
	}
	certPEM := makeSelfSignedCertFor(t, p256)
	cert, _ := ParseCertPEM(certPEM)
	if err := PublicKeysMatch(cert, p384); err == nil {
		t.Fatal("expected curve mismatch, got nil")
	}
}
