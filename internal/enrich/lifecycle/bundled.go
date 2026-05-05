package lifecycle

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// bundledSnapshot is the seed offline snapshot — small (~12
// products), hand-curated to cover the most common OS / runtime
// Components in real container SBOMs. The full catalogue is
// available via `astinus lifecycle update` which writes a richer
// snapshot to an operator-supplied path that overrides this
// embedded one at runtime.
//
//go:embed data/endoflife-snapshot.json
var bundledSnapshot []byte

// BundledSource serves Lifecycle data from an in-memory map.
// Primary use: offline / `--no-network` runs and as the hybrid-
// mode fallback when endoflife.date returns ErrNotFound or
// ErrTransient.
//
// The snapshot file's schema is `map[product] -> []Lifecycle`
// (already-parsed dates so the loader doesn't re-run the eolCycle
// projection). `astinus lifecycle update` writes the same shape.
type BundledSource struct {
	once    sync.Once
	loaded  map[string][]Lifecycle
	loadErr error
	source  string
}

// NewBundled returns a BundledSource backed by the embedded
// snapshot. Lazy-loads on first Fetch.
func NewBundled() *BundledSource {
	return &BundledSource{source: "bundled"}
}

// LoadBundled returns a BundledSource backed by the embedded
// snapshot, eagerly loading + returning any parse error. Used by
// the unit test that gates the embedded file is parseable.
func LoadBundled() (*BundledSource, error) {
	b := NewBundled()
	if err := b.ensureLoaded(); err != nil {
		return nil, err
	}
	return b, nil
}

// LoadBundledFromFile returns a BundledSource backed by the JSON
// file at path. Used by `--lifecycle-snapshot <path>` for
// operators who maintain their own snapshot via
// `astinus lifecycle update`.
func LoadBundledFromFile(path string) (*BundledSource, error) {
	body, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("lifecycle: read snapshot %q: %w", path, err)
	}
	b := &BundledSource{source: "snapshot:" + path}
	b.loaded, b.loadErr = parseBundledSnapshot(body)
	if b.loadErr != nil {
		return nil, b.loadErr
	}
	b.once.Do(func() {}) // mark loaded so ensureLoaded is a no-op
	return b, nil
}

// Name implements Source. Reflects the snapshot origin so the
// `astinus:lifecycle:source` stamp tells operators which fallback
// served the data.
func (b *BundledSource) Name() string {
	if b == nil || b.source == "" {
		return "bundled"
	}
	return b.source
}

// RequiresNetwork implements Source.
func (*BundledSource) RequiresNetwork() bool { return false }

// Fetch implements Source. Returns ErrNotFound when the product
// or cycle isn't in the snapshot.
func (b *BundledSource) Fetch(_ context.Context, product, version string) (*Lifecycle, error) {
	if err := b.ensureLoaded(); err != nil {
		return nil, err
	}
	cycles, ok := b.loaded[product]
	if !ok {
		return nil, ErrNotFound
	}
	for i := range cycles {
		if cycleMatches(cycles[i].Cycle, version) {
			out := cycles[i]
			return &out, nil
		}
	}
	return nil, ErrNotFound
}

// ProductCount returns the number of products in the loaded
// snapshot. Used by tests.
func (b *BundledSource) ProductCount() int {
	if err := b.ensureLoaded(); err != nil {
		return 0
	}
	return len(b.loaded)
}

// HasProduct reports whether the snapshot carries a product key.
// Useful for diagnostic CLI surfaces and tests.
func (b *BundledSource) HasProduct(product string) bool {
	if err := b.ensureLoaded(); err != nil {
		return false
	}
	_, ok := b.loaded[product]
	return ok
}

// ensureLoaded triggers the lazy parse on first call. Subsequent
// calls return the cached error (if any).
func (b *BundledSource) ensureLoaded() error {
	if b == nil {
		return ErrNotFound
	}
	b.once.Do(func() {
		if b.loaded != nil {
			return // already populated by LoadBundledFromFile
		}
		b.loaded, b.loadErr = parseBundledSnapshot(bundledSnapshot)
	})
	return b.loadErr
}

// parseBundledSnapshot decodes a snapshot file body into the
// Lifecycle map. The on-disk schema is the endoflife.date wire
// format `{product: [{cycle, releaseDate, support, eol, lts}]}`
// — byte-identical to what the upstream API serves at
// `/<product>.json`. The leading underscore key (`"_": "..."`) is
// allowed for an inline snapshot-author note and is silently
// skipped.
//
// Operators refresh the snapshot via `astinus lifecycle update`
// which writes this same shape verbatim.
func parseBundledSnapshot(body []byte) (map[string][]Lifecycle, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("lifecycle: empty snapshot")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("lifecycle: parse snapshot: %w", err)
	}
	out := make(map[string][]Lifecycle, len(raw))
	for product, payload := range raw {
		// Skip the leading underscore note key (snapshot-author
		// metadata, not an endoflife product).
		if strings.HasPrefix(product, "_") {
			continue
		}
		var cycles []eolCycle
		if err := json.Unmarshal(payload, &cycles); err != nil {
			return nil, fmt.Errorf("lifecycle: parse cycles for %q: %w", product, err)
		}
		converted := make([]Lifecycle, len(cycles))
		for i := range cycles {
			converted[i] = *convertCycle(&cycles[i])
		}
		out[strings.ToLower(product)] = converted
	}
	return out, nil
}
