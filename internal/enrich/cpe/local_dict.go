package cpe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// LocalDictionaryResolver looks PURLs up in an offline-db directory
// produced by `astinus offline-db build`.
//
// Layout:
//
//	<root>/cpe/by-purl/<urlencoded-purl>.json   (one localCPEEntry per file)
//	<root>/cpe/by-name/<type>/<lower(name)>.json
//
// `by-purl` matches when the entire PURL string matches; `by-name`
// is the broader fallback when the operator's catalogue only
// records a (type, name) → CPE mapping. Either lookup yields a
// high-confidence match (the operator pre-curated the catalogue).
type LocalDictionaryResolver struct {
	mu     sync.RWMutex
	byPurl map[string]localCPEEntry
	byName map[string]localCPEEntry

	// logger receives per-file warn records on skip and one info
	// record summarising the load. nil → slog.Default(). Set via
	// SetLogger before LoadFromDir for non-default behaviour.
	// post-stage-13 review F-010.
	logger *slog.Logger

	// skipped counts files dropped by the loader (read fail, JSON
	// parse fail, name decode fail). Reported in the summary.
	skipped int
}

// localCPEEntry is the on-disk record. Same shape as a bundled
// entry, but with vendor + product spelled out so the resolver can
// build a CPE for any version.
type localCPEEntry struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Source  string `json:"source,omitempty"` // "nvd-cpe", "clearlydefined", etc.
}

// NewLocalDictionaryResolver returns an empty resolver. Logger
// defaults to slog.Default(); override via SetLogger.
func NewLocalDictionaryResolver() *LocalDictionaryResolver {
	return &LocalDictionaryResolver{
		byPurl: map[string]localCPEEntry{},
		byName: map[string]localCPEEntry{},
	}
}

// SetLogger overrides the slog.Logger the resolver writes warn /
// info records to during LoadFromDir. Pass nil to revert to
// slog.Default().
func (l *LocalDictionaryResolver) SetLogger(logger *slog.Logger) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger = logger
}

// log returns the effective logger (configured one or slog.Default).
func (l *LocalDictionaryResolver) log() *slog.Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.logger != nil {
		return l.logger
	}
	return slog.Default()
}

// LoadFromDir reads every JSON entry under <root>/cpe/. Missing
// directory is NOT an error (air-gapped operators may pass a path
// that has not been built yet).
//
// Per-file failures (unreadable, malformed JSON, undecodable file
// name) are skipped with a WARN log — air-gapped CI must be able
// to tell when entries are silently lost. A summary INFO record
// is emitted at the end with the final entry count and skip count.
// post-stage-13 review F-010.
func (l *LocalDictionaryResolver) LoadFromDir(root string) error {
	l.mu.Lock()
	l.skipped = 0
	l.mu.Unlock()

	cpeRoot := filepath.Join(root, "cpe")
	info, err := os.Stat(cpeRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("local cpe: stat %s: %w", cpeRoot, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("local cpe: %s is not a directory", cpeRoot)
	}

	if err := l.loadByPurl(filepath.Join(cpeRoot, "by-purl")); err != nil {
		return err
	}
	if err := l.loadByName(filepath.Join(cpeRoot, "by-name")); err != nil {
		return err
	}

	l.log().Info("cpe.local.loaded",
		"entries", l.Len(),
		"skipped", l.skipped,
		"root", cpeRoot,
	)
	return nil
}

func (l *LocalDictionaryResolver) loadByPurl(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("local cpe: stat %s: %w", dir, err)
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return walkErr
		}
		body, err := os.ReadFile(path) //nolint:gosec // path comes from filepath.WalkDir under a caller-supplied root
		if err != nil {
			l.recordSkip(path, "read", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		var entry localCPEEntry
		if err := json.Unmarshal(body, &entry); err != nil {
			l.recordSkip(path, "parse", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		// Filename is the URL-encoded PURL (operator's choice). Use
		// the file name minus extension as the lookup key after
		// canonicalising via PURL parser.
		base := strings.TrimSuffix(filepath.Base(path), ".json")
		decoded, err := purlFromFileBase(base)
		if err != nil {
			l.recordSkip(path, "decode-name", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		l.mu.Lock()
		l.byPurl[decoded] = entry
		l.mu.Unlock()
		return nil
	})
}

func (l *LocalDictionaryResolver) loadByName(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("local cpe: stat %s: %w", dir, err)
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return walkErr
		}
		body, err := os.ReadFile(path) //nolint:gosec // path comes from filepath.WalkDir under a caller-supplied root
		if err != nil {
			l.recordSkip(path, "read", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		var entry localCPEEntry
		if err := json.Unmarshal(body, &entry); err != nil {
			l.recordSkip(path, "parse", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		// Layout: <dir>/<type>/<name>.json — relative path gives the
		// (type, name) pair we key on.
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			l.recordSkip(path, "rel-path", err)
			return nil //nolint:nilerr // single-file failure shouldn't kill the whole load
		}
		rel = filepath.ToSlash(rel)
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 {
			l.recordSkip(path, "layout", fmt.Errorf("expected <type>/<name>.json under by-name root"))
			return nil
		}
		typ := strings.ToLower(parts[0])
		name := strings.ToLower(strings.TrimSuffix(parts[1], ".json"))
		l.mu.Lock()
		l.byName[typ+"|"+name] = entry
		l.mu.Unlock()
		return nil
	})
}

// Resolve implements Resolver.
//
// Confidence is ConfidenceHigh for both index hits — the operator
// pre-curated the catalogue. Sprint 3 Task 0 routes the answer
// through the new Candidate type so the orchestrator can attribute
// per-candidate confidence rather than blanket-stamping the
// component.
func (l *LocalDictionaryResolver) Resolve(p PURL) []Candidate {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if e, ok := l.byPurl[p.String()]; ok {
		return []Candidate{{
			CPE:        Build(e.Vendor, e.Product, p.Version),
			Source:     SourceLocalDict,
			Confidence: ConfidenceHigh,
			Evidence:   "local-dictionary by-purl exact",
			MatchDetails: MatchDetails{
				VendorMatch:  "known-mapping",
				ProductMatch: "known-mapping",
				VersionMatch: versionMatchKind(p.Version),
				SearchMethod: "purl-direct",
			},
		}}
	}
	if e, ok := l.byName[strings.ToLower(p.Type)+"|"+strings.ToLower(p.Name)]; ok {
		return []Candidate{{
			CPE:        Build(e.Vendor, e.Product, p.Version),
			Source:     SourceLocalDict,
			Confidence: ConfidenceHigh,
			Evidence:   "local-dictionary by-name fallback",
			MatchDetails: MatchDetails{
				VendorMatch:  "known-mapping",
				ProductMatch: "known-mapping",
				VersionMatch: versionMatchKind(p.Version),
				SearchMethod: "dictionary-lookup",
			},
		}}
	}
	return nil
}

// Len reports how many entries the resolver holds (across both
// indexes). Useful for log lines.
func (l *LocalDictionaryResolver) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.byPurl) + len(l.byName)
}

// purlFromFileBase normalises an operator-provided file name back
// into a canonical PURL string. File names MUST be percent-encoded
// (PURLs contain `:` and `/`, neither of which are portable in
// file names); the loader percent-decodes here.
func purlFromFileBase(base string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("empty file base")
	}
	decoded, err := percentDecode(base)
	if err != nil {
		return "", fmt.Errorf("decode %q: %w", base, err)
	}
	return decoded, nil
}

// percentDecode is a minimal URL-style decoder. Operators emit file
// names like `pkg%3Anpm%2Fexpress%404.18.2.json`; the loader
// reverses to the canonical PURL string.
func percentDecode(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, err1 := unhex(s[i+1])
			lo, err2 := unhex(s[i+2])
			if err1 != nil || err2 != nil {
				return "", fmt.Errorf("invalid percent-escape at offset %d", i)
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

func unhex(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("not a hex digit: %q", c)
}

// recordSkip increments the skipped counter and emits a WARN
// log record so the operator sees lossy file-level failures.
// post-stage-13 review F-010.
func (l *LocalDictionaryResolver) recordSkip(path, op string, err error) {
	l.mu.Lock()
	l.skipped++
	l.mu.Unlock()
	l.log().Warn("cpe.local.skip", "path", path, "op", op, "err", err.Error())
}

// ChainWithLocal returns the canonical chain plus a LocalDictionary
// resolver loaded from offlineDBRoot. Slot order is bundled →
// local → heuristic so that:
//
//   - the curated bundled mapping wins when it has an entry,
//   - the operator's offline catalogue beats the heuristic,
//   - the heuristic stays the last-resort fallback.
//
// When offlineDBRoot is empty the function returns DefaultChain
// unchanged + nil error. Genuine load failures (corrupt directory
// layout, IO error stat'ing the root) are now propagated — air-
// gapped CI must be able to refuse a broken catalogue rather than
// silently fall through to bundled+heuristic only.
// post-stage-13 review F-011.
func ChainWithLocal(offlineDBRoot string) (*Chain, error) {
	return ChainWithLocalAndLogger(offlineDBRoot, nil)
}

// ChainWithLocalAndLogger is ChainWithLocal with an explicit logger
// for the resolver's load-time records. nil logger → slog.Default.
func ChainWithLocalAndLogger(offlineDBRoot string, logger *slog.Logger) (*Chain, error) {
	if offlineDBRoot == "" {
		return DefaultChain(), nil
	}
	local := NewLocalDictionaryResolver()
	if logger != nil {
		local.SetLogger(logger)
	}
	if err := local.LoadFromDir(offlineDBRoot); err != nil {
		return nil, err
	}
	return NewChain(NewBundledResolver(), local, NewHeuristicResolver()), nil
}
