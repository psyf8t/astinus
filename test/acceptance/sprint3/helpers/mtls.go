//go:build acceptance

package helpers

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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// MTLSBundle is the on-disk artefacts the registry's MirrorTLSConfig
// expects: a CA bundle, a client certificate, and the matching
// client key. Plus the parsed structs the in-process server needs to
// validate the chain.
//
// Tests get the bundle, hand the file paths to MirrorTLSConfig, and
// hand the *tls.Config to httptest.Server.
type MTLSBundle struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string

	CAPool       *x509.CertPool
	ServerTLSCfg *tls.Config
}

// NewMTLSBundle builds a self-signed CA, signs a server cert
// (DNS=localhost, IP=127.0.0.1) + a client cert from it, writes the
// PEM artefacts to dir, and returns paths + a server tls.Config that
// requires + verifies the client cert.
//
// Cert validity is 1 hour — well beyond any reasonable test runtime.
func NewMTLSBundle(tb testing.TB, dir string) *MTLSBundle {
	tb.Helper()
	caCert, caKey := mtlsGenerateCA(tb)
	serverCert, serverKey := mtlsSignCert(tb, caCert, caKey, "test-server", true)
	clientCert, clientKey := mtlsSignCert(tb, caCert, caKey, "test-client", false)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	caPath := mtlsWriteCert(tb, dir, "ca.pem", caCert)
	clientCertPath := mtlsWriteCert(tb, dir, "client.pem", clientCert)
	clientKeyPath := mtlsWriteKey(tb, dir, "client.key", clientKey)

	return &MTLSBundle{
		CACertPath:     caPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		CAPool:         pool,
		ServerTLSCfg: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
				Leaf:        serverCert,
			}},
			ClientCAs:  pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS12,
		},
	}
}

// ServerTLSCfgNoClientAuth returns the server's tls.Config but with
// ClientAuth dialled down to NoClientCert — the cert-failure test
// uses this to drive "TLS handshake fails because client cert is
// missing" via a server that DOES require the cert (the default),
// and the auth-success test would use this knob to permit a request
// without a client cert.
func (b *MTLSBundle) ServerTLSCfgNoClientAuth() *tls.Config {
	cfg := b.ServerTLSCfg.Clone()
	cfg.ClientAuth = tls.NoClientCert
	cfg.ClientCAs = nil
	return cfg
}

func mtlsGenerateCA(tb testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "astinus-acceptance-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("ca create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("ca parse: %v", err)
	}
	return cert, priv
}

func mtlsSignCert(tb testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isServer bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("leaf key: %v", err)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if isServer {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("leaf create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("leaf parse: %v", err)
	}
	return cert, priv
}

func mtlsWriteCert(tb testing.TB, dir, name string, cert *x509.Certificate) string {
	tb.Helper()
	path := filepath.Join(dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		tb.Fatalf("write cert: %v", err)
	}
	return path
}

func mtlsWriteKey(tb testing.TB, dir, name string, key *ecdsa.PrivateKey) string {
	tb.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		tb.Fatalf("write key: %v", err)
	}
	return path
}
