// Package identity owns the agent's local crypto material:
// EC P-256 keypair generation, PKCS#10 CSR construction with the
// required URI SAN placeholder, and cert/key pubkey-match validation
// during install.
//
// The agent is deliberately quiet about cert subject and SAN values
// — Vault's praxis-agent-ca role discards CSR-supplied values and
// substitutes backend-controlled identity (system-<id>.agent.praxis
// .internal CN, praxis://system/<id> URI SAN). The CSR placeholder
// here exists so server-side parsers don't choke on a SAN-less
// CSR, and so the test expectation ("exercises CSR SAN parsing expectations
// later without giving it authority") is satisfied.
package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
)

// CSRPlaceholderURI is the URI SAN we put on every gen-csr output.
// Backend rewrites this to praxis://system/<id> at sign time
// (PRA-150 sets use_csr_sans=false on the Vault role).
const CSRPlaceholderURI = "praxis://bootstrap/pending"

// CSRPlaceholderCN is the CN we put on every gen-csr output. Same
// rationale: discarded by backend; only present so parsers don't
// reject a CN-less CSR.
const CSRPlaceholderCN = "praxis-agent-bootstrap"

// PEM block types we read/write.
const (
	pemBlockKey  = "PRIVATE KEY"
	pemBlockCert = "CERTIFICATE"
	pemBlockCSR  = "CERTIFICATE REQUEST"
)

// GenerateKeypair produces a fresh EC P-256 keypair and returns the
// PKCS#8 PEM encoding of the private key. EC P-256 matches what the
// Vault praxis-agent-ca role expects (key_type=ec, key_bits=256).
func GenerateKeypair() (keyPEM []byte, key *ecdsa.PrivateKey, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa generate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemBlockKey, Bytes: der}), k, nil
}

// LoadKey reads a PKCS#8 PEM-encoded EC P-256 private key from disk.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM file", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an EC private key", path)
	}
	return ec, nil
}

// BuildCSR constructs a PKCS#10 CSR for the supplied private key
// using the documented placeholder CN and URI SAN. Returns the PEM
// encoding ready to ship to /agent/bootstrap.
func BuildCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	uri, err := url.Parse(CSRPlaceholderURI)
	if err != nil {
		return nil, fmt.Errorf("parse placeholder uri: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: CSRPlaceholderCN},
		URIs:    []*url.URL{uri},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemBlockCSR, Bytes: der}), nil
}

// ParseCert reads a PEM-encoded x509 cert from disk.
func ParseCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCertPEM(raw)
}

// ParseCertPEM parses a PEM-encoded x509 cert from a byte slice.
// The first CERTIFICATE block wins (chains may follow).
func ParseCertPEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block in cert input")
	}
	if block.Type != pemBlockCert {
		return nil, fmt.Errorf("expected %q PEM block, got %q", pemBlockCert, block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// PublicKeysMatch returns nil iff the cert's public key is the same
// EC point as the supplied private key's public part. Used by
// install-cert to refuse mismatched (cert, key) pairs.
//
// Comparison goes through MarshalPKIXPublicKey rather than touching
// the deprecated ecdsa.PublicKey.X / Y fields directly (Go 1.26
// SA1019); the PKIX DER encoding is stable and side-channel-safe.
func PublicKeysMatch(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("cert public key is not ECDSA")
	}
	if certPub.Curve != key.Curve {
		return errors.New("cert/key curve mismatch")
	}
	certDER, err := x509.MarshalPKIXPublicKey(certPub)
	if err != nil {
		return fmt.Errorf("encode cert pubkey: %w", err)
	}
	keyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("encode key pubkey: %w", err)
	}
	if !bytes.Equal(certDER, keyDER) {
		return errors.New("cert public key does not match private key")
	}
	return nil
}
