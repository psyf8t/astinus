package extractor

import (
	"context"
	"sort"
)

// Extractor is the per-format identity recoverer.
//
// Match is a cheap predicate (look at the path + a few magic bytes);
// Extract is the actual parse. Both must be safe for concurrent
// callers — Registry does not serialise calls.
type Extractor interface {
	// Name returns the short identifier used in logs and stamped
	// onto Identity.Source.
	Name() string

	// Confidence is the extractor's self-assessed precision in the
	// 0..1 range. Used by Registry.Identify to sort results.
	// Conventional values:
	//
	//   1.00 — perfect, never wrong (extremely rare).
	//   0.95 — exact metadata (Go buildinfo, Rust auditable, Python METADATA).
	//   0.90 — strong heuristic (Java pom.properties, PE VERSIONINFO).
	//   0.80 — secondary metadata (Java MANIFEST.MF).
	//   0.60 — weak heuristic (ELF SONAME, Java filename, PE filename).
	Confidence() float64

	// Match cheaply rejects files this extractor doesn't handle.
	// MUST not allocate beyond a constant; callers run Match on
	// every visible file.
	Match(ctx context.Context, file File) bool

	// Extract returns Identity for files Match accepted. An empty
	// Identity (no Name) plus nil error is the documented
	// "matched the shape but couldn't recover metadata" signal —
	// the Registry drops it. Non-nil error means the file was
	// structurally invalid (corrupt zip, truncated ELF section).
	Extract(ctx context.Context, file File) (Identity, error)
}

// Registry holds an ordered set of Extractors and dispatches
// Identify calls across them.
//
// Concurrency: the slice is read-only after construction; Identify
// is safe to call from multiple goroutines.
type Registry struct {
	extractors []Extractor
}

// New returns a Registry with the supplied extractors in the order
// given.
func New(extractors ...Extractor) *Registry {
	out := &Registry{extractors: make([]Extractor, len(extractors))}
	copy(out.extractors, extractors)
	return out
}

// NewDefault returns a Registry populated with the bundled
// extractors. Order matches the dispatch priority documented in
// the package doc: format-specific extractors first, generic ELF
// last (because the ELF library extractor matches almost every
// ELF file and we want the language-specific signals to win when
// they're present).
func NewDefault() *Registry {
	return New(
		&GoExtractor{},
		&RustExtractor{},
		&JavaExtractor{},
		&PythonExtractor{},
		&PEExtractor{},
		&ELFLibraryExtractor{},
	)
}

// Extractors returns a defensive copy of the registered set.
func (r *Registry) Extractors() []Extractor {
	out := make([]Extractor, len(r.extractors))
	copy(out, r.extractors)
	return out
}

// Identify runs every matching Extractor and returns all
// non-empty Identities sorted by Confidence descending.
//
// Errors from an individual Extractor are logged-via-return (the
// caller can branch on them) but do NOT stop the chain — a
// corrupt JAR shouldn't kill the Go extractor's chance.
func (r *Registry) Identify(ctx context.Context, file File) []Identity {
	var out []Identity
	for _, ext := range r.extractors {
		if !ext.Match(ctx, file) {
			continue
		}
		id, err := ext.Extract(ctx, file)
		if err != nil {
			// Per the interface contract: surfaced via debug
			// log at the caller, not propagated.
			continue
		}
		if id.IsEmpty() {
			continue
		}
		id.Source = ext.Name()
		id.Confidence = ext.Confidence()
		out = append(out, id)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

// First returns the highest-confidence Identity for file, or an
// empty Identity (and ok=false) when no extractor matched.
// Convenience for callers that only want the best guess.
func (r *Registry) First(ctx context.Context, file File) (Identity, bool) {
	ids := r.Identify(ctx, file)
	if len(ids) == 0 {
		return Identity{}, false
	}
	return ids[0], true
}
