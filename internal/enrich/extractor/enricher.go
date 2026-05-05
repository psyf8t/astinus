package extractor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	fpextractor "github.com/psyf8t/astinus/internal/fingerprint/extractor"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable extractor`, declared in
// other enrichers' Dependencies()).
const Name = "extractor"

// Enricher walks every Component with a binary file location, runs
// the multi-modal extractor registry, and projects extracted
// dependencies as top-level Components + RelationshipDependsOn
// edges. See package doc for rationale.
type Enricher struct {
	registry *fpextractor.Registry
}

// New returns an Enricher backed by `fpextractor.NewDefault()` (Go,
// Rust, Java, Python, ELF, PE).
func New() *Enricher {
	return &Enricher{registry: fpextractor.NewDefault()}
}

// NewWithRegistry returns an Enricher backed by the supplied
// registry. Tests use this to inject a deterministic single-extractor
// registry; production uses New().
func NewWithRegistry(r *fpextractor.Registry) *Enricher {
	return &Enricher{registry: r}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. We need to run after
// `untracked` so its discovered binaries (and any SubComponents the
// untracked-time extractor wrote) are part of the slate before we
// lift them to top-level. CPE / dedup declare `"extractor"` so the
// added components participate in their passes.
func (*Enricher) Dependencies() []string { return []string{"untracked"} }

// Enrich implements enrich.Enricher.
//
// Two phases:
//
//  1. Walk the layered filesystem ONCE; for every file path that an
//     existing Component lists in Evidence.Locations, run the
//     extractor registry and attach the extracted SubComponents to
//     that Component. Skipped when bundle.Image is nil so unit tests
//     can pass a `*image.Bundle` without a real image.
//  2. Walk every Component (recursively into SubComponents from a
//     prior run) and lift each SubComponent to a top-level Component
//     + RelationshipDependsOn edge. Dedup by PURL so the same
//     `pkg:golang/golang.org/x/net@v0.10.0` referenced by two
//     binaries appears exactly once with two parent edges.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("extractor: nil sbom")
	}
	stats := walkStats{}
	if bundle != nil && bundle.Image != nil && e.registry != nil {
		if err := e.extractFromImage(ctx, sbom, bundle.Image, &stats); err != nil {
			// Walking failures are returned to the pipeline — the
			// operator wants to see them, but we still proceed to
			// the lift phase so any pre-existing SubComponents make
			// it to top-level.
			slog.Default().Warn("extractor.walk.failed", "err", err.Error())
		}
	}

	added, edges := liftSubComponentsToTopLevel(sbom)
	stats.componentsAdded = added
	stats.edgesAdded = edges

	slog.Default().Info("extractor.complete",
		"binaries_visited", stats.binariesVisited,
		"binaries_yielded_deps", stats.binariesYielded,
		"deps_extracted", stats.depsExtracted,
		"components_added", stats.componentsAdded,
		"edges_added", stats.edgesAdded,
	)
	return nil
}

// walkStats records what the enricher did during a single Enrich
// call for the `extractor.complete` log line.
type walkStats struct {
	binariesVisited int
	binariesYielded int
	depsExtracted   int
	componentsAdded int
	edgesAdded      int
}

// extractFromImage walks the image once and attaches extractor
// results to any Component whose Evidence.Locations matches a
// visited file path.
func (e *Enricher) extractFromImage(ctx context.Context, sbom *model.SBOM, img v1.Image, stats *walkStats) error {
	wanted := indexPathsToComponents(sbom)
	if len(wanted) == 0 {
		return nil
	}

	visitor := func(_ context.Context, fe layer.FileEntry, body io.Reader) error {
		owners, ok := wanted[fe.Path]
		if !ok {
			return nil
		}
		stats.binariesVisited++

		buf, err := io.ReadAll(body)
		if err != nil {
			slog.Default().Debug("extractor.read.failed",
				"path", fe.Path, "err", err.Error())
			return nil
		}
		id, ok := e.registry.First(ctx, fpextractor.File{Path: fe.Path, Body: buf})
		if !ok || len(id.SubComponents) == 0 {
			return nil
		}
		stats.binariesYielded++
		stats.depsExtracted += len(id.SubComponents)

		for _, owner := range owners {
			attachExtractedDeps(owner, id)
		}
		return nil
	}

	if err := layer.WalkFiles(ctx, img, visitor); err != nil && !errors.Is(err, layer.SkipFile) {
		return err
	}
	return nil
}

// indexPathsToComponents returns a map from file path → every
// Component that listed that path in Evidence.Locations. A binary
// reused across two SBOM entries (rare but possible) will have both
// owners attached when we encounter the file.
func indexPathsToComponents(sbom *model.SBOM) map[string][]*model.Component {
	out := map[string][]*model.Component{}
	walkComponents(sbom.Components, func(c *model.Component) {
		if c.Evidence == nil {
			return
		}
		for _, loc := range c.Evidence.Locations {
			p := normalizePath(loc.Path)
			if p == "" {
				continue
			}
			out[p] = append(out[p], c)
		}
	})
	return out
}

// attachExtractedDeps merges an Identity's SubComponents onto a
// Component without duplicating ones already present (PURL-keyed).
// The lift phase later promotes them to top-level.
func attachExtractedDeps(c *model.Component, id fpextractor.Identity) {
	if c == nil {
		return
	}
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	if id.Source != "" && c.Properties["astinus:extractor:source"] == "" {
		c.Properties["astinus:extractor:source"] = id.Source
	}
	known := map[string]bool{}
	for _, sub := range c.SubComponents {
		if sub.PURL != "" {
			known[sub.PURL] = true
		}
	}
	for _, dep := range id.SubComponents {
		if dep.Name == "" {
			continue
		}
		if dep.PURL != "" && known[dep.PURL] {
			continue
		}
		c.SubComponents = append(c.SubComponents, model.Component{
			Type:    model.ComponentTypeLibrary,
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    dep.PURL,
		})
		if dep.PURL != "" {
			known[dep.PURL] = true
		}
	}
}

// liftSubComponentsToTopLevel projects every Component's SubComponents
// into the top-level Components slice plus a RelationshipDependsOn
// edge from the parent's BOMRef to the dep's BOMRef. Returns the
// number of Components and edges added.
//
// Dedup strategy: PURL is the dedup key. A dep with no PURL is
// keyed by `name@version`. The first occurrence wins; subsequent
// references reuse its BOMRef (so two binaries depending on the
// same library produce ONE component + TWO edges).
//
// The original SubComponents slice is cleared after lifting so a
// re-run of the enricher (e.g. via re-enrichment of the same SBOM)
// doesn't double-add.
func liftSubComponentsToTopLevel(sbom *model.SBOM) (added, edges int) {
	if sbom == nil {
		return 0, 0
	}

	purlIndex := indexExistingByPURL(sbom)

	// Walk only the top-level components; lifting a Component's
	// children creates new top-level entries that we don't want to
	// recurse into in the same pass.
	for i := range sbom.Components {
		parent := &sbom.Components[i]
		if len(parent.SubComponents) == 0 {
			continue
		}
		if parent.BOMRef == "" {
			parent.BOMRef = synthBOMRef(parent)
		}
		subs := parent.SubComponents
		parent.SubComponents = nil

		seenForParent := map[string]bool{}
		for _, sub := range subs {
			depKey := dedupKey(sub)
			if depKey == "" {
				continue
			}
			depRef, exists := purlIndex[depKey]
			if !exists {
				newComp := buildLiftedComponent(sub, parent)
				sbom.Components = append(sbom.Components, newComp)
				depRef = newComp.BOMRef
				purlIndex[depKey] = depRef
				added++
				// re-take the parent pointer because append may
				// have moved the slice.
				parent = &sbom.Components[i]
			}
			if seenForParent[depRef] {
				continue
			}
			seenForParent[depRef] = true

			sbom.Relationships = append(sbom.Relationships, model.Relationship{
				SourceRef: parent.BOMRef,
				TargetRef: depRef,
				Type:      model.RelationshipDependsOn,
			})
			edges++
		}
	}
	return added, edges
}

// indexExistingByPURL scans the existing top-level Components and
// returns a map from dedup key → BOMRef so the lift step reuses
// already-present library components instead of duplicating them.
func indexExistingByPURL(sbom *model.SBOM) map[string]string {
	out := map[string]string{}
	for i := range sbom.Components {
		c := &sbom.Components[i]
		if c.BOMRef == "" {
			c.BOMRef = synthBOMRef(c)
		}
		k := dedupKey(*c)
		if k == "" {
			continue
		}
		if _, exists := out[k]; !exists {
			out[k] = c.BOMRef
		}
	}
	return out
}

// dedupKey returns the canonical key used to deduplicate lifted
// components. PURL is the strong key; we fall back to
// `name@version` for components that lack a PURL (rare for
// extractor-yielded entries; common for input SBOMs that omit it).
func dedupKey(c model.Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	if c.Name == "" {
		return ""
	}
	return c.Name + "@" + c.Version
}

// buildLiftedComponent renders a top-level Component for a
// SubComponent that's being promoted. The new BOMRef is synthesised
// from the dedup key; we stamp `astinus:extractor:embedded-in` so
// the operator can trace back to the binary that surfaced this
// dependency without consulting the relationships graph.
func buildLiftedComponent(sub model.Component, parent *model.Component) model.Component {
	out := sub
	if out.Type == "" {
		out.Type = model.ComponentTypeLibrary
	}
	if out.BOMRef == "" {
		out.BOMRef = synthBOMRef(&out)
	}
	if out.Properties == nil {
		out.Properties = map[string]string{}
	}
	if parent != nil {
		out.Properties["astinus:extractor:embedded-in"] = parent.BOMRef
	}
	out.SubComponents = nil
	return out
}

// synthBOMRef builds a stable BOMRef from a Component's identity.
// PURL is the preferred input; falls back to `name@version` and
// finally to a SHA-256 prefix when both are empty.
func synthBOMRef(c *model.Component) string {
	if c == nil {
		return ""
	}
	if c.PURL != "" {
		return c.PURL
	}
	if c.Name != "" {
		v := c.Version
		if v == "" {
			v = "unknown"
		}
		return c.Name + "@" + v
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v", c)))
	return "extracted-" + hex.EncodeToString(sum[:6])
}

// normalizePath strips the leading slash so EvidenceLocation paths
// (often `/usr/local/bin/yq`) compare equal to the canonical
// layer-walk paths (`usr/local/bin/yq`).
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if p[0] == '/' {
		p = p[1:]
	}
	return path.Clean(p)
}

// walkComponents recurses depth-first through every component,
// invoking fn on each one (including SubComponents from prior runs).
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}
