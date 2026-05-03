package sources

import (
	"context"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// LocalDictSource wraps the Stage-12 offline-db
// `cpe.LocalDictionaryResolver` so it slots into the new
// Source-driven orchestrator. Operators populate the offline-db via
// `astinus offline-db build` (the existing CLI command); this Source
// then queries it without network.
//
// Created with NewLocalDict; pass nil to disable (the orchestrator
// drops nil Sources at registration time).
type LocalDictSource struct {
	resolver *cpe.LocalDictionaryResolver
}

// NewLocalDict returns a LocalDictSource backed by an
// already-loaded resolver. Pass `cpe.NewLocalDictionaryResolver()`
// + `LoadFromDir(path)` then hand the resolver in.
//
// Returns nil when resolver is nil — the orchestrator silently
// skips nil Sources at registration time, so callers can pass
// the zero value without a special-case.
func NewLocalDict(r *cpe.LocalDictionaryResolver) *LocalDictSource {
	if r == nil {
		return nil
	}
	return &LocalDictSource{resolver: r}
}

// Name implements Source.
func (*LocalDictSource) Name() string { return "local-dictionary" }

// Match implements Source.
func (l *LocalDictSource) Match(_ context.Context, purl cpe.PURL) ([]cpe.Match, error) {
	if l == nil || l.resolver == nil {
		return nil, nil
	}
	return l.resolver.Resolve(purl), nil
}

// RequiresNetwork implements Source.
func (*LocalDictSource) RequiresNetwork() bool { return false }

// Priority implements Source — slots between bundled (100) and
// online sources (80/70). Operators who curate a local-dict expect
// it to outrank online queries.
func (*LocalDictSource) Priority() int { return 90 }
