// Package attribution implements the layer-attribution enricher.
//
// For each Component with file evidence (Component.Evidence.Locations),
// the enricher walks the image's layered filesystem (via
// internal/image/layer) and stamps Component.LayerInfo with the layer
// that LAST modified the path — "latest layer wins".
//
// Components without file evidence are left with LayerInfo == nil.
// Squashed images (one layer) get every located component pinned to
// layer 0.
package attribution

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/image/runtime"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier used by --enable / --disable and
// as the prefix for any properties this enricher emits beyond the
// well-known `astinus:layer:*` set.
const Name = "attribution"

// Enricher implements enrich.Enricher.
//
// The zero value is usable. The walker reads the image at most once
// per Enrich call; it does not cache across calls because Enrich is
// idempotent and the canonical model owns the result.
type Enricher struct {
	// walkFn is overridable for tests.
	walkFn func(context.Context, *image.Bundle) (*layer.FileMap, error)

	// normalizeFn is overridable for tests so the runtime-stamping
	// path can be exercised without going through real layer reads.
	normalizeFn func(runtime.Runtime, *image.Bundle) ([]runtime.NormalizedLayer, error)

	// hasProvenance is overridable for tests. Production passes
	// nil; the BuildKit provenance plumbing reaches the SBOM via
	// Bundle.Runtime evidence today and via a bundle.Provenance
	// field once Task 6 wires it through.
	hasProvenance HasProvenance
}

// New returns a fresh Enricher with the default walker.
func New() *Enricher { return &Enricher{} }

// Name implements enrich.Enricher.
func (e *Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. Attribution is the root
// of the enrichment graph — it derives `LayerInfo` from the image
// directly and depends on no other enricher's output.
func (*Enricher) Dependencies() []string { return nil }

// Enrich implements enrich.Enricher.
//
// Walks the image's layers, builds a path → layer map, then iterates
// every Component (and its SubComponents) and stamps LayerInfo from
// the first matching evidence location. Components with no evidence
// or no matching path are left untouched.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil || bundle == nil || bundle.Image == nil {
		return fmt.Errorf("attribution: missing sbom/bundle/image")
	}

	walk := e.walkFn
	if walk == nil {
		walk = defaultWalk
	}

	fileMap, err := walk(ctx, bundle)
	if err != nil {
		return fmt.Errorf("attribution: walk layers: %w", err)
	}

	stamper := &stamper{fm: fileMap}
	stamper.applyAll(sbom.Components)

	e.stampRuntimeAndConfidence(sbom, bundle)
	return nil
}

// stampRuntimeAndConfidence writes the runtime + attribution-confidence
// metadata on sbom.Metadata.Properties. The decision is per-image,
// not per-component, so it lives at the SBOM level.
//
// Failure to compute confidence (e.g. layers cannot be read) is not
// fatal — we record runtime alone and leave the attribution stamps
// off, so the operator can see "we tried" rather than a silent gap.
func (e *Enricher) stampRuntimeAndConfidence(sbom *model.SBOM, bundle *image.Bundle) {
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	rt := bundle.Runtime
	if rt == "" {
		rt = runtime.RuntimeUnknown
	}
	sbom.Metadata.Properties[model.PropertyRuntime] = string(rt)
	if summary := EvidenceSummary(bundle.RuntimeEvidence); summary != "" {
		sbom.Metadata.Properties[model.PropertyRuntimeEvidence] = summary
	}

	normalize := e.normalizeFn
	if normalize == nil {
		normalize = defaultNormalize
	}
	layers, err := normalize(rt, bundle)
	if err != nil {
		return
	}
	conf, reason := DetermineConfidence(layers, rt, e.hasProvenance)
	sbom.Metadata.Properties[model.PropertyAttributionConfidence] = string(conf)
	sbom.Metadata.Properties[model.PropertyAttributionReason] = reason
}

func defaultWalk(ctx context.Context, b *image.Bundle) (*layer.FileMap, error) {
	return layer.Walk(ctx, b.Image)
}

func defaultNormalize(rt runtime.Runtime, b *image.Bundle) ([]runtime.NormalizedLayer, error) {
	return runtime.Normalize(rt, b.Image)
}

// stamper holds the file map for the duration of one Enrich call so
// the recursion through SubComponents stays cheap.
type stamper struct {
	fm *layer.FileMap
}

// applyAll stamps every component in the slice (recursively into
// SubComponents).
func (s *stamper) applyAll(comps []model.Component) {
	for i := range comps {
		s.apply(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			s.applyAll(comps[i].SubComponents)
		}
	}
}

// apply stamps one component if any of its locations resolves to a
// known layer. Discovery falls through in priority order:
//
//  1. Component.Evidence.Locations vs the FileMap last-touch lookup
//     (latest-layer-wins). Original behaviour.
//  2. `Properties["syft:location:N:path"]` vs the FileMap. S4 Task 2 —
//     Syft's apk/dpkg/rpm catalogers stamp the binary path on
//     Properties rather than Evidence.Locations, so the original
//     pass silently missed every package-managed row on real images.
//  3. `Properties["syft:location:N:layerID"]` direct: when Syft
//     recorded the layer digest itself (no FileMap probe needed),
//     match it against the known layer list to pick up Index +
//     CreatedBy and stamp `astinus:layer:source = syft-location-property`.
//
// The first matching path/layer wins; we don't try to reconcile
// conflicting locations because the FileMap's latest-layer rule
// already produces a well-defined answer per location.
func (s *stamper) apply(c *model.Component) {
	if c == nil {
		return
	}
	if c.LayerInfo != nil {
		// Already attributed (e.g. extractor enricher already set
		// LayerInfo from buildinfo evidence). Honour the
		// "non-destructive" contract from spec section 8.5; just
		// stamp the source so consumers see where it came from.
		ensureProp(c, model.PropertyLayerSource, "preexisting")
		return
	}

	// 1) Evidence.Locations — original path.
	if c.Evidence != nil {
		for _, loc := range c.Evidence.Locations {
			if info, ok := s.lookupPath(loc.Path); ok {
				s.stampFromInfo(c, info, "filemap-last-touch")
				return
			}
		}
	}

	// 2 + 3) Syft-property paths and direct layerID.
	syftLocs := readSyftLocationProps(c.Properties)
	for _, loc := range syftLocs {
		if info, ok := s.lookupPath(loc.path); ok {
			s.stampFromInfo(c, info, "syft-location-property")
			return
		}
	}
	for _, loc := range syftLocs {
		if loc.layerID == "" {
			continue
		}
		if info, ok := s.lookupLayerDigest(loc.layerID); ok {
			s.stampFromInfo(c, info, "syft-location-property")
			return
		}
	}
}

func (s *stamper) lookupPath(p string) (layer.Info, bool) {
	if p == "" {
		return layer.Info{}, false
	}
	return s.fm.Lookup(p)
}

// lookupLayerDigest scans the FileMap's layer descriptors for a
// match against digest. Linear; the layer count is small (<32 for
// production images).
//
// S5 Task 2: matches against both DiffID and CompressedDigest so
// Syft's `syft:location:N:layerID` (whichever shape Syft uses on
// the given image — DiffID is the typical case, CompressedDigest
// happens on daemon backends) finds the right layer.
func (s *stamper) lookupLayerDigest(digest string) (layer.Info, bool) {
	if s.fm == nil || digest == "" {
		return layer.Info{}, false
	}
	for _, info := range s.fm.Layers() {
		if info.DiffID == digest || info.CompressedDigest == digest {
			return info, true
		}
	}
	return layer.Info{}, false
}

func (s *stamper) stampFromInfo(c *model.Component, info layer.Info, source string) {
	c.LayerInfo = &model.LayerInfo{
		LayerDigest:           info.DiffID,
		LayerCompressedDigest: info.CompressedDigest,
		LayerIndex:            info.Index,
		DockerfileLine:        "", // not derivable from history alone
		AddedBy:               info.CreatedBy,
	}
	ensureProp(c, model.PropertyLayerSource, source)
}

// ensureProp inserts (key, value) into c.Properties without
// overwriting a pre-existing entry. Used to stamp the layer:source
// breadcrumb conservatively — a value already there came from an
// upstream enricher and we trust it.
func ensureProp(c *model.Component, key, value string) {
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	if _, exists := c.Properties[key]; exists {
		return
	}
	c.Properties[key] = value
}

// syftLocation pairs the Syft path + layerID for a single location
// index N inside a Component's Properties.
type syftLocation struct {
	idx     string
	path    string
	layerID string
}

// readSyftLocationProps groups `syft:location:N:path` and
// `syft:location:N:layerID` entries by their index N. Returns the
// locations sorted by N (ascending) so two callers see the same
// first-match order.
func readSyftLocationProps(props map[string]string) []syftLocation {
	if len(props) == 0 {
		return nil
	}
	byIdx := map[string]*syftLocation{}
	for k, v := range props {
		if v == "" || !strings.HasPrefix(k, "syft:location:") {
			continue
		}
		rest := strings.TrimPrefix(k, "syft:location:")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			continue
		}
		idx, key := parts[0], parts[1]
		loc, ok := byIdx[idx]
		if !ok {
			loc = &syftLocation{idx: idx}
			byIdx[idx] = loc
		}
		switch key {
		case "path":
			loc.path = v
		case "layerID":
			loc.layerID = v
		}
	}
	out := make([]syftLocation, 0, len(byIdx))
	for _, l := range byIdx {
		if l.path == "" && l.layerID == "" {
			// Annotations-only / unrelated keys grouped under an
			// index but with nothing usable for attribution.
			continue
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].idx < out[j].idx })
	return out
}
