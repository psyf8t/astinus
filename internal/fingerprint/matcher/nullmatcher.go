package matcher

import "context"

// NullMatcher always reports ErrNoMatch. It is the safe default in
// air-gapped environments and in tests that don't want to depend on
// an offline catalogue.
type NullMatcher struct{}

// Null is the canonical instance — there's no per-call state.
var Null Matcher = NullMatcher{}

// Name implements Matcher.
func (NullMatcher) Name() string { return "null" }

// Lookup implements Matcher.
func (NullMatcher) Lookup(_ context.Context, _, _ string) (Match, error) {
	return Match{}, ErrNoMatch
}
