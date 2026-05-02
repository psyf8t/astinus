// Package fingerprint identifies untracked files in a container image.
//
// The package combines three concerns:
//
//   - Hashing — multi-algorithm digests of arbitrary byte streams
//     (hasher.go).
//   - Format detection — recognising what KIND of file something is
//     (elf.go for executables, archive.go for jars, etc.).
//   - Embedded metadata extraction — Go binaries (golang.go),
//     Java archives (archive.go), and similar formats expose enough
//     information to identify the constituents without going to
//     external catalogues.
//
// Online catalogues (ClearlyDefined / Software Heritage) and
// PE/Windows binaries land in later stages.
package fingerprint

import (
	"crypto/sha1" //nolint:gosec // SHA-1 surfaces for legacy SBOM compat, not auth
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// MaxHashBytes caps how many bytes a single Hash invocation reads
// before bailing out. Set generously — fingerprinting a 500 MB
// vendored binary is reasonable; fingerprinting a 50 GB tarball is
// not.
const MaxHashBytes = 1 << 30 // 1 GiB

// Hasher computes SHA-256 (always) plus optional SHA-1 / SHA-512
// digests of an io.Reader in one streaming pass.
type Hasher struct {
	WithSHA1   bool
	WithSHA512 bool
}

// Hash reads r and returns the requested digests as model.Hash.
//
// Returns an error if the input exceeds MaxHashBytes.
func (h Hasher) Hash(r io.Reader) ([]model.Hash, int64, error) {
	hashes := []namedHasher{
		{name: model.HashAlgorithmSHA256, h: sha256.New()},
	}
	if h.WithSHA1 {
		hashes = append(hashes, namedHasher{name: model.HashAlgorithmSHA1, h: sha1.New()}) //nolint:gosec // SHA-1 is for legacy SBOM compatibility, not authentication
	}
	if h.WithSHA512 {
		hashes = append(hashes, namedHasher{name: model.HashAlgorithmSHA512, h: sha512.New()})
	}

	writers := make([]io.Writer, len(hashes))
	for i := range hashes {
		writers[i] = hashes[i].h
	}
	mw := io.MultiWriter(writers...)

	limited := io.LimitReader(r, MaxHashBytes+1)
	n, err := io.Copy(mw, limited)
	if err != nil {
		return nil, 0, fmt.Errorf("fingerprint: hash: %w", err)
	}
	if n > MaxHashBytes {
		return nil, n, fmt.Errorf("fingerprint: input exceeds MaxHashBytes (%d)", MaxHashBytes)
	}

	out := make([]model.Hash, len(hashes))
	for i, h := range hashes {
		out[i] = model.Hash{Algorithm: h.name, Value: hex.EncodeToString(h.h.Sum(nil))}
	}
	return out, n, nil
}

// HashSHA256 is the common-case shorthand for callers that only need
// the SHA-256.
func HashSHA256(r io.Reader) (string, int64, error) {
	out, n, err := Hasher{}.Hash(r)
	if err != nil {
		return "", 0, err
	}
	return out[0].Value, n, nil
}

type namedHasher struct {
	name string
	h    hash.Hash
}
