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

// apply stamps one component if any of its evidence locations match
// a known path. The first matching location wins; we don't try to
// reconcile conflicting locations because they would all live in
// the same image and the latest layer rule already produces a
// well-defined answer per location.
func (s *stamper) apply(c *model.Component) {
	if c == nil || c.Evidence == nil || len(c.Evidence.Locations) == 0 {
		return
	}
	if c.LayerInfo != nil {
		// Already attributed — preserve the existing entry. Honors
		// the "non-destructive" contract from spec section 8.5.
		return
	}
	for _, loc := range c.Evidence.Locations {
		if loc.Path == "" {
			continue
		}
		info, ok := s.fm.Lookup(loc.Path)
		if !ok {
			continue
		}
		c.LayerInfo = &model.LayerInfo{
			LayerDigest:    info.Digest,
			LayerIndex:     info.Index,
			DockerfileLine: "", // not derivable from history alone
			AddedBy:        info.CreatedBy,
		}
		return
	}
}
