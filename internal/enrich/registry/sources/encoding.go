package sources

import (
	"encoding/base64"
	"encoding/hex"
)

// decodeBase64ToHex decodes a standard-base64 string and returns
// its hex-encoded value. Returns empty string on parse failure so
// callers can branch on it without an error.
//
// Used by sources that store hashes in Subresource-Integrity
// format (npm `dist.integrity`, future PyPI `digests.sha256`) and
// the canonical model wants hex.
func decodeBase64ToHex(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}
