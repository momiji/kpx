package cert_test

import (
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/momiji/kpx/cert"
)

// sharedCA is created once per test binary run (1024-bit for speed).
var (
	sharedCA     *cert.Cert
	sharedCAOnce sync.Once
)

func getCA(t *testing.T) *cert.Cert {
	t.Helper()
	sharedCAOnce.Do(func() {
		var err error
		sharedCA, err = cert.NewCert(cert.NewBasicCACertConfig("test-ca", 1), 1024, nil)
		if err != nil {
			panic("getCA: " + err.Error())
		}
	})
	return sharedCA
}

// ── NewBasicCACertConfig ──────────────────────────────────────────────────────

func TestNewBasicCACertConfig_IsCA(t *testing.T) {
	cfg := cert.NewBasicCACertConfig("my-ca", 42)
	if !cfg.IsCA {
		t.Error("IsCA should be true")
	}
	if !cfg.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be true")
	}
}

func TestNewBasicCACertConfig_CommonNameAndSerial(t *testing.T) {
	cfg := cert.NewBasicCACertConfig("my-ca", 99)
	if cfg.Subject.CommonName != "my-ca" {
		t.Errorf("CommonName = %q, want %q", cfg.Subject.CommonName, "my-ca")
	}
	if cfg.SerialNumber.Int64() != 99 {
		t.Errorf("SerialNumber = %d, want 99", cfg.SerialNumber.Int64())
	}
}

func TestNewBasicCACertConfig_KeyUsageIncludesCertSign(t *testing.T) {
	cfg := cert.NewBasicCACertConfig("ca", 1)
	if cfg.KeyUsage&0x20 == 0 { // x509.KeyUsageCertSign
		t.Error("KeyUsage should include CertSign")
	}
}

func TestNewBasicCACertConfig_ValidityApprox100Years(t *testing.T) {
	cfg := cert.NewBasicCACertConfig("ca", 1)
	if time.Until(cfg.NotAfter) < 99*365*24*time.Hour {
		t.Errorf("NotAfter too soon: %v", cfg.NotAfter)
	}
}

// ── NewBasicHttpsCertConfig ───────────────────────────────────────────────────

func TestNewBasicHttpsCertConfig_DNSNames(t *testing.T) {
	cfg := cert.NewBasicHttpsCertConfig("cn", []string{"example.com", "www.example.com"}, 1)
	if len(cfg.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %d", len(cfg.DNSNames))
	}
}

func TestNewBasicHttpsCertConfig_IPAddress(t *testing.T) {
	cfg := cert.NewBasicHttpsCertConfig("cn", []string{"1.2.3.4"}, 1)
	// always contains 127.0.0.1 + provided IP
	found := false
	for _, ip := range cfg.IPAddresses {
		if ip.Equal(net.ParseIP("1.2.3.4")) {
			found = true
		}
	}
	if !found {
		t.Errorf("1.2.3.4 not found in IPAddresses: %v", cfg.IPAddresses)
	}
}

func TestNewBasicHttpsCertConfig_MixedSANs(t *testing.T) {
	cfg := cert.NewBasicHttpsCertConfig("cn", []string{"example.com", "192.168.1.1"}, 1)
	if len(cfg.DNSNames) != 1 || cfg.DNSNames[0] != "example.com" {
		t.Errorf("unexpected DNSNames: %v", cfg.DNSNames)
	}
	found := false
	for _, ip := range cfg.IPAddresses {
		if ip.Equal(net.ParseIP("192.168.1.1")) {
			found = true
		}
	}
	if !found {
		t.Errorf("192.168.1.1 not in IPAddresses: %v", cfg.IPAddresses)
	}
}

func TestNewBasicHttpsCertConfig_NilNames(t *testing.T) {
	cfg := cert.NewBasicHttpsCertConfig("cn", nil, 1)
	if len(cfg.DNSNames) != 0 {
		t.Errorf("expected no DNS names, got %v", cfg.DNSNames)
	}
	// always contains 127.0.0.1
	if len(cfg.IPAddresses) != 1 {
		t.Errorf("expected only 127.0.0.1, got %v", cfg.IPAddresses)
	}
}

func TestNewBasicHttpsCertConfig_ValidityApprox10Years(t *testing.T) {
	cfg := cert.NewBasicHttpsCertConfig("cn", nil, 1)
	if time.Until(cfg.NotAfter) < 9*365*24*time.Hour {
		t.Errorf("NotAfter too soon: %v", cfg.NotAfter)
	}
}

// ── NewCert ───────────────────────────────────────────────────────────────────

func TestNewCert_SelfSigned(t *testing.T) {
	cfg := cert.NewBasicCACertConfig("self", 2)
	c, err := cert.NewCert(cfg, 1024, nil)
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	if c.Pub.Issuer.CommonName != "self" {
		t.Errorf("issuer CN = %q, want %q", c.Pub.Issuer.CommonName, "self")
	}
	// self-signed: signature verifiable by itself
	if err := c.Pub.CheckSignatureFrom(c.Pub); err != nil {
		t.Errorf("self-signature invalid: %v", err)
	}
}

func TestNewCert_SignedByCA(t *testing.T) {
	ca := getCA(t)
	cfg := cert.NewBasicHttpsCertConfig("leaf", []string{"leaf.example.com"}, 3)
	leaf, err := cert.NewCert(cfg, 1024, ca)
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	if leaf.Pub.Issuer.CommonName != ca.Pub.Subject.CommonName {
		t.Errorf("leaf issuer = %q, want %q", leaf.Pub.Issuer.CommonName, ca.Pub.Subject.CommonName)
	}
	if err := leaf.Pub.CheckSignatureFrom(ca.Pub); err != nil {
		t.Errorf("CA signature invalid: %v", err)
	}
}

func TestNewCert_PrivateKeyMatchesPublic(t *testing.T) {
	ca := getCA(t)
	cfg := cert.NewBasicHttpsCertConfig("leaf2", []string{"leaf2.example.com"}, 4)
	c, err := cert.NewCert(cfg, 1024, ca)
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	rsaPub, ok := c.Pub.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("certificate public key is not RSA")
	}
	if rsaPub.N.Cmp(c.Priv.N) != 0 {
		t.Error("certificate public key N does not match private key N")
	}
}

// ── ToPEM / NewCertFromPEM round-trip ─────────────────────────────────────────

func TestToPEM_ProducesValidPEMBlocks(t *testing.T) {
	ca := getCA(t)
	pub, priv, err := ca.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM: %v", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		t.Error("ToPEM returned empty strings")
	}
}

func TestNewCertFromPEM_RoundTrip(t *testing.T) {
	ca := getCA(t)
	cfg := cert.NewBasicHttpsCertConfig("rt", []string{"rt.example.com"}, 5)
	original, err := cert.NewCert(cfg, 1024, ca)
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	pub, priv, err := original.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM: %v", err)
	}
	restored, err := cert.NewCertFromPEM(pub, priv)
	if err != nil {
		t.Fatalf("NewCertFromPEM: %v", err)
	}
	if restored.Pub.SerialNumber.Cmp(original.Pub.SerialNumber) != 0 {
		t.Error("serial numbers differ after PEM round-trip")
	}
	if restored.Priv.N.Cmp(original.Priv.N) != 0 {
		t.Error("private key N differs after PEM round-trip")
	}
}

func TestNewCertFromPEM_MalformedPublic(t *testing.T) {
	_, err := cert.NewCertFromPEM("not-valid-pem", "")
	if err == nil {
		t.Fatal("expected error for malformed public PEM, got nil")
	}
}

func TestNewCertFromPEM_MalformedPrivate(t *testing.T) {
	ca := getCA(t)
	pub, _, err := ca.ToPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cert.NewCertFromPEM(pub, "not-valid-pem")
	if err == nil {
		t.Fatal("expected error for malformed private PEM, got nil")
	}
}

// ── SaveToFiles / NewCertFromFiles ────────────────────────────────────────────

func TestSaveToFiles_NewCertFromFiles_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "cert.pem")
	privPath := filepath.Join(dir, "key.pem")

	ca := getCA(t)
	if err := ca.SaveToFiles(pubPath, privPath); err != nil {
		t.Fatalf("SaveToFiles: %v", err)
	}
	restored, err := cert.NewCertFromFiles(pubPath, privPath)
	if err != nil {
		t.Fatalf("NewCertFromFiles: %v", err)
	}
	if restored.Pub.SerialNumber.Cmp(ca.Pub.SerialNumber) != 0 {
		t.Error("serial numbers differ after file round-trip")
	}
	if restored.Priv.N.Cmp(ca.Priv.N) != 0 {
		t.Error("private key N differs after file round-trip")
	}
}

func TestSaveToFiles_PrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "cert.pem")
	privPath := filepath.Join(dir, "key.pem")

	ca := getCA(t)
	if err := ca.SaveToFiles(pubPath, privPath); err != nil {
		t.Fatalf("SaveToFiles: %v", err)
	}
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key permissions = %04o, want 0600", perm)
	}
}

func TestSaveToFiles_PublicKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "cert.pem")
	privPath := filepath.Join(dir, "key.pem")

	ca := getCA(t)
	if err := ca.SaveToFiles(pubPath, privPath); err != nil {
		t.Fatalf("SaveToFiles: %v", err)
	}
	info, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("public cert permissions = %04o, want 0644", perm)
	}
}

func TestNewCertFromFiles_MissingFile(t *testing.T) {
	_, err := cert.NewCertFromFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ── NewPbkdfCert ──────────────────────────────────────────────────────────────

func TestNewPbkdfCert_Deterministic(t *testing.T) {
	ca := getCA(t)
	cfg := cert.NewBasicHttpsCertConfig("pbkdf", []string{"pbkdf.example.com"}, 10)
	password := []byte("secret-password")
	salt := []byte("fixed-salt-value")
	iter := 100

	c1, err := cert.NewPbkdfCert(cfg, 1024, ca, password, salt, iter)
	if err != nil {
		t.Fatalf("first NewPbkdfCert: %v", err)
	}
	c2, err := cert.NewPbkdfCert(cfg, 1024, ca, password, salt, iter)
	if err != nil {
		t.Fatalf("second NewPbkdfCert: %v", err)
	}
	if c1.Priv.N.Cmp(c2.Priv.N) != 0 || c1.Priv.D.Cmp(c2.Priv.D) != 0 {
		t.Error("same inputs should yield the same private key")
	}
}

func TestNewPbkdfCert_DifferentPasswordYieldsDifferentKey(t *testing.T) {
	ca := getCA(t)
	salt := []byte("fixed-salt")
	iter := 100

	cfg1 := cert.NewBasicHttpsCertConfig("pbkdf2a", []string{"pbkdf2a.example.com"}, 11)
	c1, err := cert.NewPbkdfCert(cfg1, 1024, ca, []byte("password-A"), salt, iter)
	if err != nil {
		t.Fatalf("c1: %v", err)
	}

	cfg2 := cert.NewBasicHttpsCertConfig("pbkdf2b", []string{"pbkdf2b.example.com"}, 12)
	c2, err := cert.NewPbkdfCert(cfg2, 1024, ca, []byte("password-B"), salt, iter)
	if err != nil {
		t.Fatalf("c2: %v", err)
	}

	if c1.Priv.N.Cmp(c2.Priv.N) == 0 {
		t.Error("different passwords should yield different private keys")
	}
}

func TestNewPbkdfCert_SignedByCA(t *testing.T) {
	ca := getCA(t)
	cfg := cert.NewBasicHttpsCertConfig("pbkdf3", []string{"pbkdf3.example.com"}, 12)
	c, err := cert.NewPbkdfCert(cfg, 1024, ca, []byte("pw"), []byte("salt"), 100)
	if err != nil {
		t.Fatalf("NewPbkdfCert: %v", err)
	}
	if err := c.Pub.CheckSignatureFrom(ca.Pub); err != nil {
		t.Errorf("CA signature on PbkdfCert invalid: %v", err)
	}
}
