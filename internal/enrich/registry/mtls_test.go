package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psyf8t/astinus/internal/config"
)

// TestRegistryMirror_mTLS — the corporate-environment regression
// gate: the registry fetch path MUST present a client certificate
// when the per-mirror TLS config asks for it. We stand up an
// in-process HTTPS server that requires + verifies the client cert,
// then drive a FetchJSON through it via a MirrorEntry whose TLS
// block points at the test cert pair.
func TestRegistryMirror_mTLS(t *testing.T) {
	caCert, caKey := generateCA(t)
	serverCert, serverKey := signCert(t, caCert, caKey, "test-mirror", true)
	clientCert, clientKey := signCert(t, caCert, caKey, "client", false)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Errorf("server did not see a client certificate")
		}
		_, _ = w.Write([]byte(`{"name":"foo","version":"1"}`))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{makeServerTLSCert(t, serverCert, serverKey)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Persist client cert / key + CA for the MirrorEntry config.
	dir := t.TempDir()
	caPath := writePEMCert(t, dir, "ca.pem", caCert)
	clientCertPath := writePEMCert(t, dir, "client.pem", clientCert)
	clientKeyPath := writePEMKey(t, dir, "client.key", clientKey)

	mirror := config.MirrorEntry{
		URL:  server.URL,
		Mode: config.MirrorModeReplace,
		TLS: &config.MirrorTLSConfig{
			CACert:     caPath,
			ClientCert: clientCertPath,
			ClientKey:  clientKeyPath,
		},
	}
	chain := MirrorChain{Mirrors: []config.MirrorEntry{mirror}}

	// Default client doesn't have the test CA — buildMirrorClient
	// (called inside FetchJSON) must build a per-mirror transport
	// that does.
	err := FetchJSON(context.Background(), DefaultClient(), chain, "/x", "test",
		func(io.Reader) error { return nil }, nil)
	if err != nil {
		t.Fatalf("FetchJSON over mTLS mirror: %v", err)
	}
}

// ─── tiny in-tree x509 helpers ────────────────────────────────────

func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "astinus-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("ca create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	return cert, priv
}

func signCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isServer bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if isServer {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf parse: %v", err)
	}
	return cert, priv
}

func writePEMCert(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func writePEMKey(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func makeServerTLSCert(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}
