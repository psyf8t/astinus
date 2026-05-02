// Package matcher resolves a file's hash digest to an identified
// component (typically a vendored / downloaded binary that escaped
// the package manager).
//
// Stage 4 ships two implementations:
//
//   - NullMatcher — always reports "no match" (the safe default for
//     air-gapped environments and the unit suite).
//   - LocalMatcher — looks the digest up in an offline catalogue
//     loaded from disk. Stage 12 (Air-gapped Mode + Offline DB
//     Builder) populates the catalogue; until then this matcher
//     accepts a hand-crafted map for tests.
//
// Online matchers (ClearlyDefined, Software Heritage) land in
// Stage 13 and slot in via the same interface.
package matcher

import (
	"context"
	"errors"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Match is what a successful lookup yields.
//
// All fields optional except Name — a matcher that returns a Match
// must at least name the artefact, so the SBOM consumer sees
// something useful instead of just a hash.
type Match struct {
	// Name is the canonical name of the identified artefact (e.g.
	// "jq", "log4j-core").
	Name string
	// Version, when known.
	Version string
	// PURL, when the matcher can construct one.
	PURL string
	// CPEs the catalogue records for this artefact.
	CPEs []string
	// Licenses, when the catalogue carries them.
	Licenses []model.License
	// Source identifies the catalogue ("local-offline-db", "swh", …).
	Source string
}

// Matcher resolves a hash digest to a Match. Implementations MUST be
// safe for concurrent use.
type Matcher interface {
	// Name identifies the matcher in logs.
	Name() string

	// Lookup returns the Match for digest. Returns ErrNoMatch
	// (wrapped) when this matcher has no entry. Other errors are
	// real failures (network, malformed catalogue, etc.) and the
	// caller decides whether to fall through.
	Lookup(ctx context.Context, alg string, digest string) (Match, error)
}

// ErrNoMatch is the sentinel a matcher returns to indicate "I have
// no entry for this digest". Distinct from a real error so the
// caller can `errors.Is` it.
var ErrNoMatch = errors.New("matcher: no match")

// Chain queries multiple matchers in order, returning the first
// non-error/non-ErrNoMatch result.
type Chain struct {
	matchers []Matcher
}

// NewChain returns a Chain over the given matchers (order matters).
func NewChain(matchers ...Matcher) *Chain {
	return &Chain{matchers: append([]Matcher(nil), matchers...)}
}

// Name implements Matcher.
func (c *Chain) Name() string { return "chain" }

// Lookup implements Matcher.
func (c *Chain) Lookup(ctx context.Context, alg, digest string) (Match, error) {
	for _, m := range c.matchers {
		out, err := m.Lookup(ctx, alg, digest)
		if err == nil {
			return out, nil
		}
		if errors.Is(err, ErrNoMatch) {
			continue
		}
		return Match{}, err
	}
	return Match{}, ErrNoMatch
}
