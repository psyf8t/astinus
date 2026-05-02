package matcher

import (
	"context"
	"strings"
	"sync"
)

// LocalMatcher resolves digests from an in-memory catalogue.
//
// Today the catalogue is populated programmatically (mostly by tests
// and by the upcoming Stage 12 builder, which will hand the matcher a
// fully-loaded map). The disk format / loader will live alongside
// the offline-db CLI command in Stage 12.
type LocalMatcher struct {
	mu      sync.RWMutex
	entries map[string]Match
}

// NewLocalMatcher returns an empty LocalMatcher.
func NewLocalMatcher() *LocalMatcher { return &LocalMatcher{entries: map[string]Match{}} }

// Name implements Matcher.
func (l *LocalMatcher) Name() string { return "local" }

// Add registers a Match under the (alg, digest) pair. Algorithm and
// digest are normalised to lowercase. Safe for concurrent use.
func (l *LocalMatcher) Add(alg, digest string, m Match) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[localKey(alg, digest)] = m
}

// Lookup implements Matcher.
func (l *LocalMatcher) Lookup(_ context.Context, alg, digest string) (Match, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if m, ok := l.entries[localKey(alg, digest)]; ok {
		return m, nil
	}
	return Match{}, ErrNoMatch
}

// Len reports how many entries the matcher holds.
func (l *LocalMatcher) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

func localKey(alg, digest string) string {
	return strings.ToLower(strings.TrimSpace(alg)) + ":" + strings.ToLower(strings.TrimSpace(digest))
}
