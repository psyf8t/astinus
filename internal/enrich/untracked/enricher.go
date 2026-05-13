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
//   - MaxFileBytes (default 2 GiB, S4 Task 5) is the per-file cap
//     on bytes we hash / parse. Files over the cap are emitted as
//     observed-only Components rather than aborting the walk.
package untracked

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/psyf8t/astinus/internal/enrich/untracked/cluster"
	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/fingerprint"
	"github.com/psyf8t/astinus/internal/fingerprint/extractor"
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
	// DefaultMaxFileBytes is the per-file cap on bytes hashed +
	// classified by the untracked enricher. S4 Task 5 raised the
	// default from 256 MiB → 2 GiB after the 256 MiB ceiling
	// aborted the walk on real production Go binaries (Grafana's
	// 435 MB single-binary distribution) that arrive without a
	// matching Syft `Evidence.Locations` entry to skip them via
	// the redundancy filter. 2 GiB covers every Go / JVM / native
	// app binary observed on public images and leaves a generous
	// margin before pathological multi-GB blobs hit the cap.
	DefaultMaxFileBytes = 2 << 30 // 2 GiB
	defaultMagicWindow  = 16
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

	// PathClassifier is the declarative-rules classifier consulted
	// in preFilter before the magic-byte classification path. Nil →
	// the bundled default rules from pathclassifier.LoadDefault.
	// Pass an explicitly-constructed *pathclassifier.Classifier to
	// merge a `--rules-file` override on top. PRSD-Task-1.
	PathClassifier *pathclassifier.Classifier

	// DisableClustering turns off the filesystem-aware clustering
	// pre-pass (PRSD-Task-2). Default false → clustering runs.
	// Operators set this when they want every file recorded as a
	// separate Component (debug, or a downstream tool that already
	// does its own grouping). PRSD-Task-3.
	DisableClustering bool

	// ClusterOptions tunes the clustering detector. Zero value
	// uses the detector's defaults (256 KiB anchor cap, density
	// stage on, MinDirChildren=3). PRSD-Task-3.
	ClusterOptions cluster.Options

	// Extractors is the multi-modal binary extractor registry
	// (PRSD-Task-4). Nil → the bundled default registry from
	// `extractor.NewDefault()` (Go / Rust / Java / Python / PE /
	// ELF). Pass `extractor.New()` (zero extractors) to disable
	// extraction entirely.
	Extractors *extractor.Registry
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
	if o.PathClassifier == nil {
		// Default-rule load failure is treated as "no classifier" —
		// the magic-byte path still runs. Today LoadDefault never
		// fails (the YAML is //go:embed-validated at build time);
		// the soft fallback exists so a bad future edit cannot brick
		// every Astinus call.
		if rules, err := pathclassifier.LoadDefault(); err == nil {
			if c, err := pathclassifier.New(rules); err == nil {
				o.PathClassifier = c
			}
		}
	}
	if o.Extractors == nil {
		o.Extractors = extractor.NewDefault()
	}
	return &Enricher{opts: o}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. Untracked walks the
// image directly via `layer.WalkFiles` and records its own
// LayerInfo per discovered file — it doesn't read attribution's
// output. PRSD-Task-6: declaring no deps lets the topo sort place
// untracked alongside attribution rather than after it.
func (*Enricher) Dependencies() []string { return nil }

// Enrich implements enrich.Enricher.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("untracked: missing sbom/bundle/image")
	}

	clusters := e.runClusterPrePass(ctx, sbom, bundle.Image)
	idx := buildKnownIndex(sbom)
	stats := newScanStats()

	// Matcher tasks are queued by the visitor and processed in
	// parallel AFTER the layer walk completes (so sbom.Components
	// is stable and worker writes by index are safe).
	// post-Stage-13 hardening Task 4.
	var tasks []matchTask

	visitor := func(ctx context.Context, fe layer.FileEntry, body io.Reader) error {
		return e.visit(ctx, sbom, idx, clusters, &stats, &tasks, fe, body)
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

// runClusterPrePass runs the filesystem-aware clustering detector
// (PRSD-Task-3) against the image, then emits one Component per
// detected cluster (skipping clusters whose identity already exists
// in the SBOM — Syft typically discovers npm / pypi / maven
// packages, so we don't want to duplicate them).
//
// Returns the cluster slice the visitor uses to skip files inside
// cluster roots. When clustering is disabled (DisableClustering=true)
// or the detector errors out, returns nil — the visitor degrades to
// pre-clustering behaviour.
func (e *Enricher) runClusterPrePass(ctx context.Context, sbom *model.SBOM, img v1.Image) []cluster.Cluster {
	if e.opts.DisableClustering {
		return nil
	}
	clusters, err := cluster.DetectClusters(ctx, img, e.opts.ClusterOptions)
	if err != nil {
		// Detection failure must not abort the enricher — the
		// per-file walk still produces useful output.
		slog.Default().Warn("untracked.cluster.detect-failed", "err", err.Error())
		return nil
	}
	// Dedup index keyed by both the full PURL (qualifier-stripped)
	// and the type-coordinates triple (`<type>/<namespace>/<name>`,
	// version-stripped) so a cluster whose anchor lacked a version
	// (e.g. package.json with no `version` field) still matches an
	// existing Syft component that does carry one.
	knownPURLs := make(map[string]struct{}, len(sbom.Components))
	knownCoords := make(map[string]struct{}, len(sbom.Components))
	walkComponents(sbom.Components, func(c *model.Component) {
		if c.PURL != "" {
			knownPURLs[normalisePURL(c.PURL)] = struct{}{}
			if coord := purlCoordinates(c.PURL); coord != "" {
				knownCoords[coord] = struct{}{}
			}
		}
	})
	added := 0
	for i := range clusters {
		c := &clusters[i]
		if c.Identity.Name == "" {
			continue
		}
		key := normalisePURL(c.Identity.PURL)
		if _, dup := knownPURLs[key]; dup {
			continue
		}
		if coord := purlCoordinates(c.Identity.PURL); coord != "" {
			if _, dup := knownCoords[coord]; dup {
				continue
			}
		}
		sbom.Components = append(sbom.Components, clusterToComponent(c))
		added++
		knownPURLs[key] = struct{}{}
	}
	slog.Default().Info("untracked.cluster.detected",
		"clusters_total", len(clusters),
		"clusters_added", added,
		"clusters_skipped_duplicate", len(clusters)-added,
	)
	return clusters
}

// walkComponents is the depth-first visitor used to dedup against
// pre-existing Syft components. Mirrored in basediff for the same
// SBOM-shape recursion.
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}

// normalisePURL strips Astinus-emitted ?root= qualifiers and Syft's
// `?package-id=` so dedup compares the same package across sources.
func normalisePURL(purl string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		return purl[:i]
	}
	return purl
}

// purlCoordinates returns the version-stripped `<type>/<namespace>/<name>`
// triple (e.g. `pkg:npm/lodash@4.17.21?id=x` → `npm/lodash`,
// `pkg:maven/com.example/app@1.0` → `maven/com.example/app`). Used
// for dedup when one side lacks a version.
//
// Returns "" when the input is not a parseable PURL.
func purlCoordinates(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	body := purl[len(prefix):]
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}
	if i := strings.IndexByte(body, '@'); i >= 0 {
		body = body[:i]
	}
	return body
}

// clusterToComponent assembles a model.Component for a detected
// cluster: identity → core fields, file list → SubComponents NOT
// (clustered files are described by properties, not exploded as
// individual components).
func clusterToComponent(c *cluster.Cluster) model.Component {
	bomRef := "cluster-" + safeBOMRef(c.Identity.Type+"-"+c.Identity.Name+"-"+c.Identity.Version)
	comp := model.Component{
		BOMRef:  bomRef,
		Type:    componentTypeForCluster(c.Identity.Type),
		Name:    c.Identity.Name,
		Version: c.Identity.Version,
		PURL:    c.Identity.PURL,
		Evidence: &model.Evidence{
			Method: "cluster",
			Locations: []model.EvidenceLocation{
				{Path: c.Root},
			},
		},
		Properties: map[string]string{
			"astinus:cluster:type":             c.Identity.Type,
			"astinus:cluster:detection-method": c.Identity.DetectionMethod,
			"astinus:cluster:confidence":       fmt.Sprintf("%.2f", c.Identity.Confidence),
			"astinus:cluster:file-count":       fmt.Sprintf("%d", len(c.Files)),
			"astinus:cluster:total-size-bytes": fmt.Sprintf("%d", c.TotalSize),
			"astinus:cluster:root":             c.Root,
		},
	}
	if c.Identity.AnchorPath != "" {
		comp.Properties["astinus:cluster:anchor-path"] = c.Identity.AnchorPath
	}
	return comp
}

// componentTypeForCluster maps a cluster type string to the closest
// CycloneDX componentType. Helm charts are "application"; everything
// else is "library" (consistent with how Syft reports the same
// ecosystems).
func componentTypeForCluster(typ string) model.ComponentType {
	switch typ {
	case "helm":
		return model.ComponentTypeApplication
	default:
		return model.ComponentTypeLibrary
	}
}

// safeBOMRef strips characters that would be ugly in a BOMRef. We
// keep ASCII letters, digits, dashes and dots; everything else
// becomes a dash.
func safeBOMRef(s string) string {
	if s == "" {
		return "anon"
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.':
			sb.WriteByte(c)
		default:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

// withinAnyCluster reports whether p sits under any cluster root.
func withinAnyCluster(p string, clusters []cluster.Cluster) (string, bool) {
	for i := range clusters {
		if clusters[i].Within(p) {
			return clusters[i].Identity.Name, true
		}
	}
	return "", false
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
func (e *Enricher) visit(ctx context.Context, sbom *model.SBOM, idx *knownIndex, clusters []cluster.Cluster, stats *scanStats, tasks *[]matchTask, fe layer.FileEntry, body io.Reader) error {
	if e.opts.MaxComponents > 0 && stats.added >= e.opts.MaxComponents {
		return errLimitHit
	}
	stats.scanned++

	if name, ok := withinAnyCluster(fe.Path, clusters); ok {
		// File belongs to a cluster — already represented as a
		// single Component upstream. Drop the per-file row so the
		// SBOM stays compact.
		stats.skippedByCluster++
		stats.byCluster[name]++
		return nil
	}

	preReason, skip := e.preFilter(fe.Path, idx, stats)
	if skip {
		return nil
	}

	r, err := e.processFile(ctx, fe, body)
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

// preFilter runs the redundancy + docs/metadata + declarative-rules
// cheap pre-passes and returns whether the visitor should skip this
// file. When the file is kept under --include-redundant /
// --include-noise, returns the reason string so the resulting
// Component can be stamped.
//
// The PathClassifier from PRSD-Task-1 runs LAST among the pre-pass
// gates: redundancy and the file/extension catalogues are O(1) /
// O(prefixes); the classifier's regex / glob fall-throughs are
// slightly more expensive. The order also keeps the existing
// Hardening-Sprint-1 instrumentation (`stats.redundant`,
// `stats.noise`) intact for every file the legacy filters would
// have caught.
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
	if reason == "" && e.opts.PathClassifier != nil {
		if r, drop := e.applyPathClassifier(filePath, stats); drop {
			return "", true
		} else if r != "" {
			reason = r
		}
	}
	return reason, false
}

// applyPathClassifier consults the declarative classifier and
// translates its Decision into the (reason, skip) shape preFilter
// expects.
//
// PRSD-Task-1: ActionSkip / ActionRedundantUnderArchive both drop
// the file (ActionRedundantUnderArchive will become Task-3 territory
// once clustering lands; today both reduce to "do not record").
// ActionMarkAsNoise / ActionMarkAsRedundant keep the file but stamp
// the bypass property via the existing reason string.
func (e *Enricher) applyPathClassifier(filePath string, stats *scanStats) (string, bool) {
	d := e.opts.PathClassifier.Classify(filePath)
	switch d.Action {
	case pathclassifier.ActionSkip, pathclassifier.ActionRedundantUnderArchive:
		stats.skippedByRule++
		stats.byRule[d.RuleName]++
		return "", true
	case pathclassifier.ActionMarkAsNoise:
		stats.noise++
		if !e.opts.Include.allow(CategoryNoise) {
			return "", true
		}
		stats.byRule[d.RuleName]++
		return "noise:" + d.RuleName, false
	case pathclassifier.ActionMarkAsRedundant:
		stats.redundant++
		if !e.opts.Include.allow(CategoryRedundant) {
			return "", true
		}
		stats.byRule[d.RuleName]++
		return "redundant:" + d.RuleName, false
	default:
		return "", false
	}
}

// scanStats is the per-Enrich-call set of counters that drive the
// `untracked.stats` log line. post-Stage-13 hardening Task 1 + Task 4
// + PRSD-Task-1 (declarative-rules counters) + PRSD-Task-3 (cluster
// counters).
type scanStats struct {
	start             time.Time
	scanned           int
	added             int
	redundant         int
	noise             int
	skippedClassifier int
	skippedByRule     int // PRSD-Task-1: pathclassifier hits
	skippedByCluster  int // PRSD-Task-3: file inside a cluster root
	byCategory        map[string]int
	byRule            map[string]int // PRSD-Task-1: per-rule hit count
	byCluster         map[string]int // PRSD-Task-3: per-cluster file count
}

func newScanStats() scanStats {
	return scanStats{
		start:      time.Now(),
		byCategory: map[string]int{},
		byRule:     map[string]int{},
		byCluster:  map[string]int{},
	}
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
		"files_skipped_by_rule", s.skippedByRule,
		"files_skipped_by_cluster", s.skippedByCluster,
		"by_category", s.byCategory,
		"by_rule", s.byRule,
		"by_cluster", s.byCluster,
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
//
// S4 Task 5: when a file exceeds MaxFileBytes (rare on today's
// raised 2 GiB default but still possible for multi-GB blobs) the
// walk no longer aborts. Instead we drain the body, emit an
// observed-only Component so the file appears in the SBOM inventory
// for transparency, and continue. The pre-S4-Task-5 behaviour
// surfaced as `Trivy input aborts on Grafana's 435 MB binary` on
// real images.
func (e *Enricher) processFile(ctx context.Context, fe layer.FileEntry, body io.Reader) (processResult, error) {
	buf, err := readCapped(body, e.opts.MaxFileBytes)
	if errors.Is(err, errFileTooLarge) {
		return e.observedTooLargeResult(fe), nil
	}
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
	e.enrichEmbedded(ctx, &comp, cls.Category, extractor.File{Path: fe.Path, Body: buf})
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

// enrichEmbedded folds extractor-recovered identity onto comp.
//
// Routes through the multi-modal extractor registry (PRSD-Task-4):
// the registry tries every matching extractor (Go buildinfo, Rust
// auditable, Java JAR metadata, Python METADATA, PE filename, ELF
// SONAME) and returns the highest-confidence Identity. Categories
// the registry can't help with (Noise / Config / Script / etc.)
// are short-circuited.
func (e *Enricher) enrichEmbedded(ctx context.Context, comp *model.Component, cat Category, file extractor.File) {
	switch cat {
	case CategoryExecutable, CategoryArchive, CategoryLibrary:
		// fall through — these are the categories the registry
		// usefully fingerprints.
	case CategoryNoise, CategoryStaticArchive, CategoryScript,
		CategoryConfig, CategoryUnknown, CategoryRedundant:
		return
	}
	if e.opts.Extractors == nil {
		return
	}
	id, ok := e.opts.Extractors.First(ctx, file)
	if !ok {
		return
	}
	applyExtractorIdentity(comp, id)
}

// applyExtractorIdentity copies an Identity onto comp. The base row
// is observed-only (Type=file, Name=path, no PURL); a successful
// extractor upgrades it to identified and fills in package fields.
// Fields are overwritten only when the extractor produced a
// non-empty value so Syft-supplied data is preserved otherwise.
// S4 Task 0.
func applyExtractorIdentity(c *model.Component, id extractor.Identity) {
	if id.Name != "" {
		c.Name = id.Name
	}
	if id.Version != "" {
		c.Version = id.Version
	}
	if id.PURL != "" {
		c.PURL = id.PURL
	}
	if id.Vendor != "" {
		c.Supplier = id.Vendor
	}
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties["astinus:extractor:source"] = id.Source
	c.Properties[model.PropertyEvidenceLevel] = string(model.EvidenceLevelIdentified)
	if t := componentTypeForExtractor(id.Source); t != model.ComponentTypeFile {
		c.Type = t
	}
	for k, v := range id.Properties {
		if v == "" {
			continue
		}
		c.Properties[k] = v
	}
	for _, sub := range id.SubComponents {
		c.SubComponents = append(c.SubComponents, identityToSubComponent(sub, id.Source))
	}
}

// identityToSubComponent renders a SubComponent for nested
// dependencies (Go module deps, Rust crate deps). S4 Task 1 stamps
// the same identity markers the extractor enricher uses when
// attaching deps to a Syft-discovered binary, so the lift phase sees
// a consistent shape regardless of which discovery path produced the
// SubComponent.
func identityToSubComponent(id extractor.Identity, parentSource string) model.Component {
	src := parentSource
	if src == "" {
		src = id.Source
	}
	return model.Component{
		Type:    model.ComponentTypeLibrary,
		Name:    id.Name,
		Version: id.Version,
		PURL:    id.PURL,
		Properties: map[string]string{
			model.PropertyEvidenceLevel: string(model.EvidenceLevelIdentified),
			"astinus:identified:source": identifiedSourceName(src),
		},
	}
}

// identifiedSourceName mirrors extractor.identifiedSource — the
// untracked enricher cannot import the extractor enricher (cycle), so
// we duplicate the small mapping table here. Sources stay in lockstep
// because both enrichers stamp the same Component identity property.
func identifiedSourceName(extractorName string) string {
	switch extractorName {
	case "go":
		return "go-buildinfo"
	case "rust":
		return "rust-auditable"
	case "java":
		return "java-jar-metadata"
	case "python":
		return "python-dist-info"
	case "elf-library":
		return "elf-soname"
	default:
		return extractorName
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
//
// The baseline is deliberately conservative: Type = file, Name = full
// path, no PURL / CPE, and `astinus:evidence-level = observed`. An
// identifying source (the multi-modal extractor registry, or the
// fingerprint matcher) upgrades the row to `identified` and fills in
// the package fields when verifiable metadata exists. S4 Task 0.
func buildBaseComponent(fe layer.FileEntry, cls Result, sha256Short string, hashes []model.Hash) model.Component {
	comp := model.Component{
		BOMRef: "untracked-" + sha256Short[:min(12, len(sha256Short))],
		Type:   model.ComponentTypeFile,
		Name:   fe.Path,
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
			model.PropertyEvidenceLevel:  string(model.EvidenceLevelObserved),
		},
	}
	return comp
}

// componentTypeForExtractor maps an Extractor.Name() to the SBOM
// ComponentType the recovered identity warrants. Used by
// applyExtractorIdentity to upgrade observed rows once an extractor
// finds verifiable metadata. S4 Task 0.
func componentTypeForExtractor(source string) model.ComponentType {
	switch source {
	case "go", "rust":
		return model.ComponentTypeApplication
	case "java", "python", "elf-library":
		return model.ComponentTypeLibrary
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
	// A matcher hit means a content-hash catalogue agreed on identity.
	// Upgrade the row from the observed baseline to identified, and
	// promote Type from `file` to `application` so consumers don't
	// drop it as a non-package row. S4 Task 0.
	c.Properties[model.PropertyEvidenceLevel] = string(model.EvidenceLevelIdentified)
	if c.Type == model.ComponentTypeFile {
		c.Type = model.ComponentTypeApplication
	}
}

// errFileTooLarge is the sentinel readCapped returns when the body
// exceeds MaxFileBytes. The caller distinguishes this from real I/O
// errors so the walk can emit an observed-only Component and
// continue instead of aborting. S4 Task 5.
var errFileTooLarge = errors.New("untracked: file exceeds MaxFileBytes")

// readCapped reads up to limit+1 bytes; if the input is longer it
// returns errFileTooLarge so the caller can branch. limit < 0
// means unlimited.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return io.ReadAll(r)
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w (%d)", errFileTooLarge, limit)
	}
	return body, nil
}

// observedTooLargeResult builds the observed-only Component the
// walk emits when a file exceeds MaxFileBytes. The Component
// carries no hash (we stopped reading before the file ended) and
// stamps `astinus:untracked:skipped-reason = file-exceeds-max-bytes`
// so operators can audit why no identity was attempted. The result
// is otherwise consistent with `buildBaseComponent` so downstream
// passes (layer attribution, evidence-level inference) keep
// working. S4 Task 5.
func (e *Enricher) observedTooLargeResult(fe layer.FileEntry) processResult {
	comp := model.Component{
		BOMRef: "untracked-toolarge-" + sanitiseBOMRefPath(fe.Path),
		Type:   model.ComponentTypeFile,
		Name:   fe.Path,
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
			"astinus:untracked:category":          "unknown",
			"astinus:untracked:skipped-reason":    "file-exceeds-max-bytes",
			"astinus:untracked:max-file-bytes":    strconv.FormatInt(e.opts.MaxFileBytes, 10),
			"astinus:untracked:header-size-bytes": strconv.FormatInt(fe.Header.Size, 10),
			model.PropertyEvidenceLevel:           string(model.EvidenceLevelObserved),
		},
	}
	return processResult{
		comp:     comp,
		category: CategoryUnknown,
		size:     fe.Header.Size,
		ok:       true,
	}
}

// sanitiseBOMRefPath produces a stable BOMRef suffix for the
// over-MaxFileBytes observed-only entry. Path is the only identity
// we have (no hash). Replaces filesystem separators and quotes with
// dashes so the result is safe to embed in a CycloneDX BOMRef.
func sanitiseBOMRefPath(p string) string {
	if p == "" {
		return "anon"
	}
	var sb strings.Builder
	sb.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.':
			sb.WriteByte(c)
		default:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}
