// Package untracked discovers components that no upstream SBOM
// generator knew about — vendored binaries, downloaded archives,
// embedded JARs, statically linked Go binaries, scripts dropped in
// via curl|sh.
//
// Algorithm (per spec section 8.8):
//
//  1. Build the set of paths the input SBOM already mentions
//     (Component.Evidence.Locations across the whole tree).
//  2. Walk the image's filesystem in layered order (whiteout-aware,
//     via internal/image/layer.WalkFiles).
//  3. For each file NOT in the set:
//     - skip noise (pyc, locales, doc, …) — see classifier.go
//     - classify (executable / archive / library / script / config / …)
//     - hash + extract embedded metadata (Go buildinfo, JAR manifest)
//     - look the digest up via fingerprint/matcher
//  4. Append a Component to the SBOM with Evidence.Method
//     ("fingerprint" when the matcher answered, "untracked-scan"
//     otherwise).
//
// Limits:
//
//   - MaxComponents (default 10000) stops the scan once the SBOM
//     would otherwise blow up.
//   - MaxFileBytes (default 256 MiB) is the per-file cap on bytes
//     we hash / parse.
package untracked

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/psyf8t/astinus/internal/fingerprint"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable untracked`).
const Name = "untracked"

// Defaults — overridable via Options.
const (
	DefaultMaxComponents = 10000
	DefaultMaxFileBytes  = 256 << 20 // 256 MiB
	defaultMagicWindow   = 16
)

// Options controls the enricher.
type Options struct {
	// Matcher is queried for each hashed file. Nil → matcher.Null.
	Matcher matcher.Matcher
	// MaxComponents caps how many untracked components get added.
	// Zero → DefaultMaxComponents. Set to -1 to disable.
	MaxComponents int
	// MaxFileBytes caps how many bytes we hash per file.
	// Zero → DefaultMaxFileBytes.
	MaxFileBytes int64
	// Include selects which categories to record. Default mask
	// excludes Redundant + Noise. post-Stage-13 hardening Task 1.
	Include IncludeMask
	// MatcherIncludeUnknown enables Matcher.Lookup for files
	// classified as CategoryUnknown (zero value = false = SKIP
	// matcher for unknowns, the production default). Unknowns are
	// overwhelmingly /etc/* config / data files that no public
	// catalogue (SWH, ClearlyDefined) will ever match; skipping
	// them cuts ~70 % of matcher lookups on a typical Debian
	// image. Set to true to opt back in for debug.
	// post-Stage-13 hardening Task 4.
	MatcherIncludeUnknown bool
	// MatcherIncludeScripts enables Matcher.Lookup for files
	// classified as CategoryScript (default false = skip). Shell /
	// python entry-point scripts almost never appear in
	// content-hash catalogues like Software Heritage; skipping
	// them removes another ~250 lookups on a typical Debian image.
	// Set to true to opt back in for debug.
	MatcherIncludeScripts bool
	// MatcherIncludeArchives enables Matcher.Lookup for files
	// classified as CategoryArchive (default false = skip). JAR
	// archives already get embedded-manifest extraction
	// (vendor / version), and SWH does not reliably index .jar
	// content. Set to true to opt back in for debug.
	MatcherIncludeArchives bool
	// MatcherMinFileBytes drops Matcher.Lookup for files smaller
	// than this many bytes — too small to be a vendored binary
	// worth fingerprinting. Default 4 KiB (real vendored binaries
	// start in the tens of KiB).
	MatcherMinFileBytes int64
	// MatcherTimeout caps how long a single Matcher.Lookup is
	// allowed to block. The matcher chain itself has a 30 s HTTP
	// timeout; this is a tighter cap so a single slow request
	// can't dominate wall-clock. Zero → 5 s.
	MatcherTimeout time.Duration
	// MatcherWorkers controls the size of the worker pool used to
	// run matcher.Lookup calls in parallel after the layer walk
	// finishes. The matcher chain itself rate-limits requests
	// (Stage 13's RateLimitedMatcher) so the workers serialise
	// through that bucket; the parallelism gain is in overlapping
	// HTTP RTT (each Lookup takes ~1–2 s on Software Heritage),
	// not in raising the issue rate. Zero → 16.
	// post-Stage-13 hardening Task 4.
	MatcherWorkers int
}

// Enricher implements enrich.Enricher.
type Enricher struct {
	opts Options
}

// New returns a fresh Enricher with default options.
func New() *Enricher { return NewWithOptions(Options{}) }

// NewWithOptions returns an Enricher with custom options.
func NewWithOptions(o Options) *Enricher {
	if o.Matcher == nil {
		o.Matcher = matcher.Null
	}
	if o.MaxComponents == 0 {
		o.MaxComponents = DefaultMaxComponents
	}
	if o.MaxFileBytes == 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
	if o.MatcherMinFileBytes == 0 {
		o.MatcherMinFileBytes = 4 * 1024 // 4 KiB
	}
	if o.MatcherTimeout == 0 {
		o.MatcherTimeout = 5 * time.Second
	}
	if o.MatcherWorkers == 0 {
		o.MatcherWorkers = 16
	}
	return &Enricher{opts: o}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Enrich implements enrich.Enricher.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("untracked: missing sbom/bundle/image")
	}

	idx := buildKnownIndex(sbom)
	stats := scanStats{start: time.Now(), byCategory: map[string]int{}}

	// Matcher tasks are queued by the visitor and processed in
	// parallel AFTER the layer walk completes (so sbom.Components
	// is stable and worker writes by index are safe).
	// post-Stage-13 hardening Task 4.
	var tasks []matchTask

	visitor := func(ctx context.Context, fe layer.FileEntry, body io.Reader) error {
		return e.visit(ctx, sbom, idx, &stats, &tasks, fe, body)
	}

	err := layer.WalkFiles(ctx, bundle.Image, visitor)
	if err != nil && !errors.Is(err, errLimitHit) {
		logScanStats(stats, 0)
		return fmt.Errorf("untracked: walk: %w", err)
	}

	matcherHits := e.runMatcherWorkers(ctx, sbom, tasks)
	logScanStats(stats, matcherHits)
	return nil
}

// matchTask is one queued matcher.Lookup deferred until after the
// layer walk completes.
type matchTask struct {
	componentIdx int
	sha256       string
}

// runMatcherWorkers fans the queued matcher tasks out across a
// bounded worker pool. Each worker calls matcher.Lookup with a
// per-call ctx timeout (default 5 s) so a single slow upstream can
// not dominate wall-clock. Returns the number of matcher hits.
func (e *Enricher) runMatcherWorkers(ctx context.Context, sbom *model.SBOM, tasks []matchTask) int {
	if len(tasks) == 0 {
		return 0
	}
	workers := e.opts.MatcherWorkers
	if workers > len(tasks) {
		workers = len(tasks)
	}

	taskCh := make(chan matchTask, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskCh {
				lookupCtx, cancel := context.WithTimeout(ctx, e.opts.MatcherTimeout)
				m, lerr := e.opts.Matcher.Lookup(lookupCtx, model.HashAlgorithmSHA256, t.sha256)
				cancel()
				if lerr != nil {
					continue
				}
				mu.Lock()
				applyMatch(&sbom.Components[t.componentIdx], m)
				sbom.Components[t.componentIdx].Evidence.Method = "fingerprint"
				hits++
				mu.Unlock()
			}
		}()
	}
	for _, t := range tasks {
		taskCh <- t
	}
	close(taskCh)
	wg.Wait()
	return hits
}

// visit runs the per-file pipeline (pre-pass filters → processFile →
// append + queue matcher task). Extracted from Enrich so the closure
// stays simple and the linter is happy with cognitive complexity.
func (e *Enricher) visit(_ context.Context, sbom *model.SBOM, idx *knownIndex, stats *scanStats, tasks *[]matchTask, fe layer.FileEntry, body io.Reader) error {
	if e.opts.MaxComponents > 0 && stats.added >= e.opts.MaxComponents {
		return errLimitHit
	}
	stats.scanned++

	preReason, skip := e.preFilter(fe.Path, idx, stats)
	if skip {
		return nil
	}

	r, err := e.processFile(fe, body)
	if err != nil {
		return err
	}
	if !r.ok {
		stats.skippedClassifier++
		return nil
	}
	if preReason != "" {
		r.comp.Properties["astinus:untracked:filter-bypass"] = preReason
	}
	sbom.Components = append(sbom.Components, r.comp)
	stats.added++
	if catStr := r.comp.Properties["astinus:untracked:category"]; catStr != "" {
		stats.byCategory[catStr]++
	}
	if e.shouldMatcherLookup(r.category, r.size) {
		*tasks = append(*tasks, matchTask{
			componentIdx: len(sbom.Components) - 1,
			sha256:       r.sha256,
		})
	}
	return nil
}

// processResult bundles everything visit needs to know about a file:
// the assembled Component, its SHA-256 (for the matcher worker pool),
// its category + body size (for shouldMatcherLookup), and whether
// the file should be recorded at all.
type processResult struct {
	comp     model.Component
	sha256   string
	category Category
	size     int64
	ok       bool
}

// preFilter runs the redundancy + docs/metadata cheap pre-passes and
// returns whether the visitor should skip this file. When the file is
// kept under --include-redundant / --include-noise, returns the
// reason string so the resulting Component can be stamped.
func (e *Enricher) preFilter(filePath string, idx *knownIndex, stats *scanStats) (reason string, skip bool) {
	if isRedundantAgainstIndex(filePath, idx) {
		stats.redundant++
		if !e.opts.Include.allow(CategoryRedundant) {
			return "", true
		}
		reason = "redundant"
	}
	if isDocsOrMetadata(filePath) {
		stats.noise++
		if !e.opts.Include.allow(CategoryNoise) {
			return "", true
		}
		if reason == "" {
			reason = "noise"
		}
	}
	return reason, false
}

// scanStats is the per-Enrich-call set of counters that drive the
// `untracked.stats` log line. post-Stage-13 hardening Task 1 + Task 4.
type scanStats struct {
	start             time.Time
	scanned           int
	added             int
	redundant         int
	noise             int
	skippedClassifier int
	byCategory        map[string]int
}

func logScanStats(s scanStats, matcherHits int) {
	dur := time.Since(s.start)
	throughput := 0.0
	if dur > 0 {
		throughput = float64(s.scanned) / dur.Seconds()
	}
	slog.Default().Info("untracked.stats",
		"files_scanned", s.scanned,
		"files_added", s.added,
		"files_skipped_redundant", s.redundant,
		"files_skipped_noise", s.noise,
		"files_skipped_classifier", s.skippedClassifier,
		"by_category", s.byCategory,
		"matcher_hits", matcherHits,
		"duration_ms", dur.Milliseconds(),
		"throughput_files_per_sec", int(throughput),
	)
}

// processFile runs one file through "slurp → classify → hash →
// extract" and returns the assembled Component PLUS the metadata the
// caller needs (sha256, category, size) to decide whether to queue a
// matcher task. ok=false for noise / config / static-archive
// (skipped); err is for true I/O errors. Matcher.Lookup is no longer
// called here — see runMatcherWorkers.
func (e *Enricher) processFile(fe layer.FileEntry, body io.Reader) (processResult, error) {
	buf, err := readCapped(body, e.opts.MaxFileBytes)
	if err != nil {
		return processResult{}, err
	}

	magic := buf
	if len(magic) > defaultMagicWindow {
		magic = magic[:defaultMagicWindow]
	}
	cls := Classify(fe.Path, magic)

	switch cls.Category {
	case CategoryNoise, CategoryStaticArchive, CategoryConfig, CategoryRedundant:
		return processResult{}, nil
	case CategoryExecutable, CategoryArchive, CategoryScript,
		CategoryLibrary, CategoryUnknown:
		// continue
	}

	hashes, _, hashErr := fingerprint.Hasher{}.Hash(bytes.NewReader(buf))
	if hashErr != nil {
		return processResult{}, nil //nolint:nilerr // single-file hash failure must not abort the scan
	}
	sha := hashes[0].Value

	comp := buildBaseComponent(fe, cls, sha, hashes)
	enrichEmbedded(&comp, cls.Category, buf)
	return processResult{
		comp:     comp,
		sha256:   sha,
		category: cls.Category,
		size:     int64(len(buf)),
		ok:       true,
	}, nil
}

// shouldMatcherLookup reports whether the matcher chain is worth
// querying for a file of the given (category, size). Default policy:
// run matcher only for Executable + Library — those are the
// categories where Software Heritage actually carries content. Other
// categories (Script, Archive — which has its own embedded-metadata
// extraction; Unknown — overwhelmingly /etc/* configs Syft missed)
// almost never produce a hit and dominate wall-clock when the
// matcher is rate-limited against a public API.
// post-Stage-13 hardening Task 4.
func (e *Enricher) shouldMatcherLookup(cat Category, size int64) bool {
	if size < e.opts.MatcherMinFileBytes {
		return false
	}
	switch cat {
	case CategoryExecutable, CategoryLibrary:
		return true
	case CategoryUnknown:
		return e.opts.MatcherIncludeUnknown
	case CategoryScript:
		return e.opts.MatcherIncludeScripts
	case CategoryArchive:
		return e.opts.MatcherIncludeArchives
	default:
		return false
	}
}

// enrichEmbedded looks for in-file metadata (Go buildinfo, JAR
// MANIFEST) and folds it onto comp.
func enrichEmbedded(comp *model.Component, cat Category, body []byte) {
	switch cat {
	case CategoryExecutable:
		if gobi, err := fingerprint.ReadGoBuildInfo(bytes.NewReader(body)); err == nil {
			attachGoBuildInfo(comp, gobi)
		}
	case CategoryArchive:
		if md, err := fingerprint.ReadJARMetadata(body); err == nil && md != nil {
			attachJARMetadata(comp, md)
		}
	case CategoryNoise, CategoryStaticArchive, CategoryScript,
		CategoryLibrary, CategoryConfig, CategoryUnknown, CategoryRedundant:
		// no embedded-metadata extraction for these categories
	}
}

// errLimitHit is the internal sentinel that aborts WalkFiles when
// MaxComponents is reached.
var errLimitHit = errors.New("untracked: max components reached")

func normalize(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

// buildBaseComponent fills in the fields every untracked Component
// gets regardless of category.
func buildBaseComponent(fe layer.FileEntry, cls Result, sha256Short string, hashes []model.Hash) model.Component {
	comp := model.Component{
		BOMRef: "untracked-" + sha256Short[:min(12, len(sha256Short))],
		Type:   componentTypeFor(cls.Category),
		Name:   path.Base(fe.Path),
		Hashes: hashes,
		Evidence: &model.Evidence{
			Method:    "untracked-scan",
			Locations: []model.EvidenceLocation{{Path: fe.Path}},
		},
		LayerInfo: &model.LayerInfo{
			LayerDigest: fe.Layer.Digest,
			LayerIndex:  fe.Layer.Index,
			AddedBy:     fe.Layer.CreatedBy,
		},
		Properties: map[string]string{
			"astinus:untracked:category": categoryString(cls.Category),
		},
	}
	return comp
}

// componentTypeFor maps a Category to the SBOM ComponentType it
// makes sense to record.
func componentTypeFor(c Category) model.ComponentType {
	switch c {
	case CategoryExecutable, CategoryScript:
		return model.ComponentTypeApplication
	case CategoryLibrary:
		return model.ComponentTypeLibrary
	case CategoryArchive:
		return model.ComponentTypeFile
	default:
		return model.ComponentTypeFile
	}
}

func categoryString(c Category) string {
	switch c {
	case CategoryExecutable:
		return "executable"
	case CategoryArchive:
		return "archive"
	case CategoryLibrary:
		return "library"
	case CategoryScript:
		return "script"
	case CategoryConfig:
		return "config"
	case CategoryStaticArchive:
		return "static-archive"
	case CategoryNoise:
		return "noise"
	case CategoryRedundant:
		return "redundant"
	default:
		return "unknown"
	}
}

// attachGoBuildInfo adds Go module info as SubComponents and wires
// the parent component's PURL when the main module is identifiable.
func attachGoBuildInfo(c *model.Component, bi *fingerprint.GoBuildInfo) {
	c.Properties["astinus:untracked:go-version"] = bi.GoVersion
	if bi.Main.Path != "" && bi.Main.Path != "command-line-arguments" {
		c.PURL = "pkg:golang/" + bi.Main.Path + "@" + nonEmpty(bi.Main.Version, "(devel)")
	}
	for _, dep := range bi.Deps {
		if dep.Path == "" {
			continue
		}
		c.SubComponents = append(c.SubComponents, model.Component{
			Type:    model.ComponentTypeLibrary,
			Name:    dep.Path,
			Version: dep.Version,
			PURL:    "pkg:golang/" + dep.Path + "@" + nonEmpty(dep.Version, ""),
		})
	}
}

// attachJARMetadata fills in name / version / vendor from the JAR
// manifest when those keys were populated.
func attachJARMetadata(c *model.Component, md *fingerprint.JARMetadata) {
	if md.BundleSymbolicName != "" {
		c.Name = md.BundleSymbolicName
	} else if md.ImplementationTitle != "" {
		c.Name = md.ImplementationTitle
	}
	if md.BundleVersion != "" {
		c.Version = md.BundleVersion
	} else if md.ImplementationVersion != "" {
		c.Version = md.ImplementationVersion
	}
	if md.ImplementationVendor != "" {
		c.Supplier = md.ImplementationVendor
	}
	c.Type = model.ComponentTypeLibrary
}

func applyMatch(c *model.Component, m matcher.Match) {
	if m.Name != "" {
		c.Name = m.Name
	}
	if m.Version != "" {
		c.Version = m.Version
	}
	if m.PURL != "" {
		c.PURL = m.PURL
	}
	if len(m.CPEs) > 0 {
		c.CPEs = append(c.CPEs, m.CPEs...)
	}
	if len(m.Licenses) > 0 {
		c.Licenses = append(c.Licenses, m.Licenses...)
	}
	if m.Source != "" {
		c.Properties["astinus:untracked:matcher"] = m.Source
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// readCapped reads up to limit+1 bytes; if the input is longer it
// returns an error (so the caller knows the file was over the cap).
// limit < 0 means unlimited.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return io.ReadAll(r)
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("untracked: file exceeds MaxFileBytes (%d)", limit)
	}
	return body, nil
}
