package registry

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/psyf8t/astinus/internal/config"
)

// buildMirrorClient returns the *http.Client used for one mirror.
// When the mirror has no TLS overrides, it returns the shared
// `defaultClient` so most mirrors share a single connection pool.
//
// When TLS overrides are present (per-mirror CA bundle, mTLS client
// cert, or insecure-skip-verify), a dedicated transport is built so
// the mirror's TLS settings don't bleed into the rest of the
// process.
//
// proxy support is inherited from the base transport (we Clone
// http.DefaultTransport, which honours `http.ProxyFromEnvironment`
// already).
func buildMirrorClient(defaultClient *http.Client, mirror *config.MirrorEntry) (*http.Client, error) {
	if mirror == nil || mirror.TLS == nil {
		return defaultClient, nil
	}
	tlsConfig, hasOverride, err := buildMirrorTLSConfig(mirror.TLS)
	if err != nil {
		return nil, fmt.Errorf("registry mirror %q: tls: %w", mirror.URL, err)
	}
	if !hasOverride {
		return defaultClient, nil
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tlsConfig
	timeout := defaultRegistryTimeout
	if defaultClient != nil && defaultClient.Timeout > 0 {
		timeout = defaultClient.Timeout
	}
	return &http.Client{Transport: base, Timeout: timeout}, nil
}

// defaultRegistryTimeout caps a single request when the operator
// passes no client. Generous because some upstream registries
// (search.maven.org) routinely take 5+ seconds.
const defaultRegistryTimeout = 30 * time.Second

// DefaultClient returns a shared *http.Client suitable for sources
// that don't need per-mirror TLS. Honors `http.ProxyFromEnvironment`
// via the cloned default transport.
func DefaultClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: t, Timeout: defaultRegistryTimeout}
}

// buildMirrorTLSConfig translates the per-mirror TLS YAML into a
// *tls.Config. The bool result is true when at least one override
// was applied (callers short-circuit to the shared client when
// false). Errors on bad files / parse failures — air-gapped CI must
// fail loudly when a misconfigured mirror would otherwise silently
// degrade.
func buildMirrorTLSConfig(t *config.MirrorTLSConfig) (*tls.Config, bool, error) {
	if t == nil {
		return nil, false, nil
	}
	if t.CACert == "" && t.ClientCert == "" && t.ClientKey == "" && !t.SkipVerify {
		return nil, false, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.CACert != "" {
		pool, err := loadCABundle(t.CACert)
		if err != nil {
			return nil, false, err
		}
		cfg.RootCAs = pool
	}
	if t.ClientCert != "" || t.ClientKey != "" {
		if t.ClientCert == "" || t.ClientKey == "" {
			return nil, false, errors.New("client_cert and client_key must both be set")
		}
		cert, err := tls.LoadX509KeyPair(t.ClientCert, t.ClientKey)
		if err != nil {
			return nil, false, fmt.Errorf("load mTLS client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if t.SkipVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // explicit operator opt-in
	}
	return cfg, true, nil
}

// loadCABundle reads a PEM bundle from path and returns a CertPool
// that contains the system pool plus the bundle's certs. Errors when
// the file is missing or contains no parseable certs.
func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %q: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %q: no certificates parsed", path)
	}
	return pool, nil
}
