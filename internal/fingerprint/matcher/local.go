package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// LoadFromDir populates the matcher from an offline-db directory
// produced by `astinus offline-db build`. Layout:
//
//	<root>/fingerprint/<alg>/<digest>.json   (one Match per file)
//
// The function is additive: existing entries (e.g. seeded by tests)
// are not removed. Missing root path is NOT an error — air-gapped
// callers might point at a directory that has not been built yet
// and that's fine; the matcher just stays empty for unknown digests.
//
// Per-file errors are accumulated and returned as one wrapped error
// so a single malformed entry doesn't make the whole load silent.
func (l *LocalMatcher) LoadFromDir(root string) error {
	fpRoot := filepath.Join(root, "fingerprint")
	info, err := os.Stat(fpRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("local matcher: stat %s: %w", fpRoot, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("local matcher: %s is not a directory", fpRoot)
	}

	var loadErrs []string
	walkErr := filepath.WalkDir(fpRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("walk %s: %v", path, walkErr))
			return nil
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		alg, digest, ok := splitFingerprintPath(fpRoot, path)
		if !ok {
			loadErrs = append(loadErrs, fmt.Sprintf("unexpected file layout: %s", path))
			return nil
		}
		body, err := os.ReadFile(path) //nolint:gosec // path comes from filepath.WalkDir under a caller-supplied root
		if err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("read %s: %v", path, err))
			return nil
		}
		var m Match
		if err := json.Unmarshal(body, &m); err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("parse %s: %v", path, err))
			return nil
		}
		l.Add(alg, digest, m)
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("local matcher: walk %s: %w", fpRoot, walkErr)
	}
	if len(loadErrs) > 0 {
		return fmt.Errorf("local matcher: %d error(s) loading entries: %s",
			len(loadErrs), strings.Join(loadErrs, "; "))
	}
	return nil
}

// splitFingerprintPath parses "<root>/<alg>/<digest>.json" into
// (alg, digest). Anything not matching that two-segment shape is
// reported as a layout error by the caller.
func splitFingerprintPath(root, full string) (alg, digest string, ok bool) {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return "", "", false
	}
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	digest = strings.TrimSuffix(parts[1], ".json")
	if digest == "" {
		return "", "", false
	}
	return parts[0], digest, true
}
