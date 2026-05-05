package matcher

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DefaultClearlyDefinedBaseURL is the public ClearlyDefined v1 API base.
const DefaultClearlyDefinedBaseURL = "https://api.clearlydefined.io"

// ClearlyDefinedMatcher resolves cryptographic digests against the
// ClearlyDefined service
// (https://docs.clearlydefined.io/docs/integrations/api).
//
// # IMPORTANT — design caveat
//
// ClearlyDefined is **coordinate-indexed**, not hash-indexed. Its
// definitions / curations are keyed by
// `(type/provider/namespace/name/revision)`, not by SHA digests.
// There is no hash-to-coordinate index in the public API (as of the
// time of writing).
//
// This matcher exists today as a registration anchor + diagnostic
// breadcrumb so:
//
//  1. The resolver chain has the slot the spec section §15 Stage 13
//     enumerates.
//  2. A future PURL-based extension (Resolver, not Matcher) can
//     plug into the cpe pipeline alongside cpe.LocalDictionaryResolver.
//  3. Operators see a clear "no hash lookup available; use offline-db"
//     message instead of silent ignoring.
//
// Lookup() always returns ErrNoMatch with the diagnostic message
// embedded. The matcher honours the http.Client / baseURL fields so
// a future implementation can flip to a real API call without
// touching the chain construction.
type ClearlyDefinedMatcher struct {
	baseURL string
	client  *http.Client
}

// NewClearlyDefinedMatcher returns a ClearlyDefined matcher. Pass
// baseURL == "" for the public default.
func NewClearlyDefinedMatcher(baseURL string, client *http.Client) *ClearlyDefinedMatcher {
	if baseURL == "" {
		baseURL = DefaultClearlyDefinedBaseURL
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &ClearlyDefinedMatcher{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

// Name implements Matcher.
func (c *ClearlyDefinedMatcher) Name() string { return "clearlydefined" }

// Lookup implements Matcher.
//
// Always ErrNoMatch in Stage 13 (see the type doc for why). The
// error message points operators at the offline-db / PURL-based
// integrations.
func (c *ClearlyDefinedMatcher) Lookup(_ context.Context, alg, digest string) (Match, error) {
	return Match{}, fmt.Errorf(
		"clearlydefined: no hash-to-coordinate index in public API "+
			"(alg=%s digest=%s); use --offline-db with curated entries: %w",
		alg, digest, ErrNoMatch)
}
