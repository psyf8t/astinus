package transport

import (
	"crypto/tls"
	"fmt"
)

// loadClientCertificate reads a PEM-encoded certificate + private
// key pair into a tls.Certificate suitable for tls.Config.Certificates.
//
// Returns an empty tls.Certificate (zero value) plus nil error when
// both paths are empty — the caller can use that to mean "no client
// cert configured for this host".
func loadClientCertificate(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" && keyPath == "" {
		return tls.Certificate{}, nil
	}
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("transport: client cert + key must both be set (cert=%q key=%q)",
			certPath, keyPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transport: load client cert (%s, %s): %w",
			certPath, keyPath, err)
	}
	return cert, nil
}

// hasClientCert reports whether c carries any cert/key material.
func hasClientCert(c tls.Certificate) bool {
	return len(c.Certificate) > 0 || c.PrivateKey != nil
}
