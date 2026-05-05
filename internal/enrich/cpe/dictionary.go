package cpe

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// bundledMappingJSON is the hand-curated PURL → CPE mapping that
// ships in the binary. Schema: see purl_to_cpe.json. Stage 12 will
// add a loader for the full NVD CPE Dictionary on disk.
//
//go:embed builtin/purl_to_cpe.json
var bundledMappingJSON []byte

// Source describes which resolver produced a CPE; written into the
// component's properties under `astinus:cpe:source`.
type Source string

const (
	// SourceBundled means the entry came from the embedded
	// purl_to_cpe.json mapping.
	SourceBundled Source = "bundled"
	// SourceHeuristic means the entry was constructed from PURL
	// shape because no bundled match existed.
	SourceHeuristic Source = "heuristic"
	// SourceLocalDict identifies entries from the operator-supplied
	// offline-db catalogue.
	SourceLocalDict Source = "local-dictionary"
	// SourceInput marks CPEs that arrived in the input SBOM
	// (typically Syft's vendor=name placeholder). Kept as a
	// candidate during enrichment so authoritative resolver matches
	// can outrank or coexist with them.
	SourceInput Source = "input"
)

// Confidence score buckets used by the source scorers and
// orchestrator. Float-valued so callers can compare against the
// Threshold cutoffs in confidence.go.
const (
	// ConfidenceHigh is the score given to exact / curated matches
	// such as bundled dictionary hits and local-dictionary lookups.
	ConfidenceHigh = 0.95
	// ConfidenceMedium is the typical score for an existing input
	// CPE (Syft placeholder) — kept as primary when nothing better
	// exists, but outranked by curated resolver answers.
	ConfidenceMedium = 0.70
	// ConfidenceLow is the score given to PURL-shape heuristic
	// guesses — they sit on the AlternativeMin threshold so they
	// remain visible as alternatives but rarely become primary.
	ConfidenceLow = 0.50
	// ConfidenceWeak marks suspicious candidates (NVD substring
	// noise, etc). Below the AlternativeMin cutoff so they are
	// rejected by Classify.
	ConfidenceWeak = 0.30
	// ConfidenceReject is the floor for hard-rejected candidates
	// (e.g. hardware-type CPE attached to a software PURL — the
	// yq → Linksys-router bug from the Sprint 2 benchmark).
	ConfidenceReject = 0.05
)

// bundledEntry mirrors one record in purl_to_cpe.json.
type bundledEntry struct {
	PurlType      string `json:"purl_type"`
	PurlNamespace string `json:"purl_namespace,omitempty"`
	PurlName      string `json:"purl_name"`
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
}

// bundledFile mirrors the top-level JSON.
type bundledFile struct {
	Schema   string         `json:"schema"`
	Snapshot string         `json:"snapshot"`
	Source   string         `json:"source"`
	Entries  []bundledEntry `json:"entries"`
}

// BundledDictionary indexes the embedded mapping for fast lookup.
//
// Indexed by `<type>|<lower(namespace)>|<lower(name)>` — namespace
// is "" for type-name only entries.
type BundledDictionary struct {
	once    sync.Once
	loaded  bundledFile
	index   map[string]bundledEntry
	loadOK  bool
	loadErr error
}

// defaultDictionary is initialised on first use.
var defaultDictionary BundledDictionary

// Default returns the singleton dictionary backed by the embedded
// mapping. Loads lazily on first call; subsequent calls are
// concurrency-safe.
func Default() *BundledDictionary { return &defaultDictionary }

// Load forces the bundled JSON to parse. Subsequent calls are no-ops.
//
// Returns an error if the embedded JSON is malformed; in normal
// operation this should never happen — the embedded file is part of
// the binary build.
func (d *BundledDictionary) Load() error {
	d.once.Do(func() {
		var f bundledFile
		if err := json.Unmarshal(bundledMappingJSON, &f); err != nil {
			d.loadErr = fmt.Errorf("cpe: parse bundled mapping: %w", err)
			return
		}
		d.loaded = f
		d.index = make(map[string]bundledEntry, len(f.Entries))
		for _, e := range f.Entries {
			d.index[bundledKey(e.PurlType, e.PurlNamespace, e.PurlName)] = e
		}
		d.loadOK = true
	})
	return d.loadErr
}

// Snapshot returns the snapshot date recorded in the JSON header.
// Empty string when the dictionary has not been loaded yet.
func (d *BundledDictionary) Snapshot() string {
	if !d.loadOK {
		return ""
	}
	return d.loaded.Snapshot
}

// Len reports how many entries the dictionary holds. 0 before Load.
func (d *BundledDictionary) Len() int {
	if !d.loadOK {
		return 0
	}
	return len(d.index)
}

// Lookup returns the bundled entry for a (type, namespace, name)
// triple, with namespace optional. Lookup is case-insensitive on
// every field. Returns ok=false when no entry exists.
func (d *BundledDictionary) Lookup(purlType, namespace, name string) (bundledEntry, bool) {
	if err := d.Load(); err != nil || !d.loadOK {
		return bundledEntry{}, false
	}
	e, ok := d.index[bundledKey(purlType, namespace, name)]
	return e, ok
}

// bundledKey is the canonical map key.
func bundledKey(purlType, namespace, name string) string {
	return strings.ToLower(purlType) + "|" + strings.ToLower(namespace) + "|" + strings.ToLower(name)
}
