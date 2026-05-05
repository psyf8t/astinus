package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadClientCertificateBothEmpty(t *testing.T) {
	c, err := loadClientCertificate("", "")
	if err != nil {
		t.Fatalf("loadClientCertificate(empty): %v", err)
	}
	if hasClientCert(c) {
		t.Error("empty paths should yield empty cert")
	}
}

func TestLoadClientCertificateHalfEmptyErrors(t *testing.T) {
	_, err := loadClientCertificate("/tmp/x.crt", "")
	if err == nil {
		t.Error("expected error when only cert path set")
	}
	_, err = loadClientCertificate("", "/tmp/x.key")
	if err == nil {
		t.Error("expected error when only key path set")
	}
}

func TestLoadClientCertificateBadFile(t *testing.T) {
	_, err := loadClientCertificate("/no/such.crt", "/no/such.key")
	if err == nil {
		t.Error("expected error for missing files")
	}
}

func TestMTLSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")

	// Build a CA + client cert. Server uses the CA both for its
	// own serving cert AND to verify the client cert.
	caCert, caKey := mustGenerateCA(t)
	clientCert, clientKey := mustGenerateClientCert(t, caCert, caKey)

	mustWritePEM(t, caCertPath, "CERTIFICATE", caCert.Raw)
	mustWritePEM(t, clientCertPath, "CERTIFICATE", clientCert.Raw)
	mustWritePEMECKey(t, clientKeyPath, clientKey)

	// Server config that requires + verifies the client cert.
	serverPool := x509.NewCertPool()
	serverPool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  serverPool,
		Certificates: []tls.Certificate{
			mustServerCertificate(t, caCert, caKey),
		},
	}
	srv.StartTLS()
	defer srv.Close()

	rt, err := New(Options{
		CABundle:   caCertPath,
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
		MaxRetries: -1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := doGet(t, rt, srv.URL); err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func mustGenerateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustGenerateClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustServerCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}
}

func mustWritePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustWritePEMECKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
