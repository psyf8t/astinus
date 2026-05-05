package model

import "strings"

// Hash is one cryptographic digest of a component artifact.
//
// Algorithm uses lowercase canonical names ("sha256", "sha1", "sha512",
// "md5", "swhid"). Readers normalize incoming variants ("SHA-256",
// "SHA_256") via NormalizeHashAlgorithm so equality comparisons are safe.
type Hash struct {
	Algorithm string
	Value     string
}

// Canonical hash algorithm names. Add new entries when an input demands it.
const (
	HashAlgorithmMD5        = "md5"
	HashAlgorithmSHA1       = "sha1"
	HashAlgorithmSHA256     = "sha256"
	HashAlgorithmSHA384     = "sha384"
	HashAlgorithmSHA512     = "sha512"
	HashAlgorithmSWHID      = "swhid"
	HashAlgorithmBlake2b256 = "blake2b-256"
	HashAlgorithmBlake2b512 = "blake2b-512"
	HashAlgorithmBlake3     = "blake3"
)

// NormalizeHashAlgorithm collapses the various wire-format spellings
// ("SHA-256", "SHA_512", "sha256") to the canonical lowercase form.
// Unknown algorithms pass through lowercased so we don't silently drop
// data — the value is still retrievable by the downstream consumer.
func NormalizeHashAlgorithm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	switch s {
	case "sha-1":
		return HashAlgorithmSHA1
	case "sha-256":
		return HashAlgorithmSHA256
	case "sha-384":
		return HashAlgorithmSHA384
	case "sha-512":
		return HashAlgorithmSHA512
	case "blake2b-256", "blake2b256":
		return HashAlgorithmBlake2b256
	case "blake2b-512", "blake2b512":
		return HashAlgorithmBlake2b512
	default:
		// Already canonical or genuinely unknown — preserve.
		return strings.ReplaceAll(s, "-", "")
	}
}
