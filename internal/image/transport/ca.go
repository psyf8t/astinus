package transport

import (
	"crypto/x509"
	"fmt"
	"os"
)

// loadCAPool returns a *x509.CertPool consisting of the system pool
// PLUS the certificates in path (if non-empty). The system pool is
// loaded once via x509.SystemCertPool; on platforms where that's not
// available (e.g. Windows pre-Go 1.18 — not us, but defensive) we
// fall back to a fresh empty pool.
func loadCAPool(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Defensive: fall back to a fresh pool so the corporate CA
		// is at least loaded.
		pool = x509.NewCertPool()
	}
	if path == "" {
		return pool, nil
	}

	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca bundle %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca bundle %q: no PEM certificates loaded", path)
	}
	return pool, nil
}
