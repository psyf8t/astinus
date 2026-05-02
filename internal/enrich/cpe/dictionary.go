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
)

// Confidence is a coarse quality grade for a Match.
type Confidence string

// Confidence values emitted by the resolvers.
const (
	// ConfidenceHigh is for matches drawn from the bundled dictionary.
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow is for matches built by the heuristic resolver.
	ConfidenceLow Confidence = "low"
)

// Match is one CPE candidate for a PURL.
type Match struct {
	CPE        string
	Source     Source
	Confidence Confidence
}

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
