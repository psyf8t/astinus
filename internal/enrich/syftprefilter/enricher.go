package syftprefilter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable syft-prefilter`,
// declared in other enrichers' Dependencies()).
const Name = "syft-prefilter"

// Property keys stamped on Components that the classifier marked as
// noise or redundant (action != Skip).
const (
	PropertyNoise     = "astinus:noise"
	PropertyNoiseRule = "astinus:noise:rule"
)

// Enricher applies the bundled path-classifier rules to the
// upstream SBOM's `type=file` Components. See package doc.
type Enricher struct {
	classifier *pathclassifier.Classifier
}

// New returns an Enricher backed by classifier. Pass nil to make the
// enricher a no-op (used by `--no-syft-prefilter`).
func New(classifier *pathclassifier.Classifier) *Enricher {
	return &Enricher{classifier: classifier}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. nil = "no deps" → the
// topological sorter (with stable input-order tie-breaking) places
// this enricher first when it appears first in allEnrichers().
func (*Enricher) Dependencies() []string { return nil }

// Stats records what the enricher did during one Enrich call.
// Surfaced via the `syftprefilter.complete` info log.
type Stats struct {
	Examined int
	Removed  int
	Marked   int
	Kept     int
	ByRule   map[string]int
}

// Enrich implements enrich.Enricher.
//
// bundle is required for signature compatibility but unused — the
// pre-filter only consumes the SBOM.
func (e *Enricher) Enrich(_ context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("syftprefilter: nil sbom")
	}
	if e.classifier == nil {
		return nil
	}

	stats := Stats{ByRule: map[string]int{}}
	removed := map[string]bool{}

	kept := make([]model.Component, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		stats.Examined++
		if !shouldClassify(c) {
			kept = append(kept, c)
			continue
		}
		path := extractPath(&c)
		if path == "" {
			kept = append(kept, c)
			continue
		}
		decision := e.classifier.Classify(path)
		switch decision.Action {
		case pathclassifier.ActionSkip, pathclassifier.ActionRedundantUnderArchive:
			stats.Removed++
			stats.ByRule[decision.RuleName]++
			if c.BOMRef != "" {
				removed[c.BOMRef] = true
			}
			slog.Default().Debug("syftprefilter.removed",
				"path", path,
				"rule", decision.RuleName,
				"reason", decision.Reason,
				"action", string(decision.Action))
		case pathclassifier.ActionMarkAsNoise, pathclassifier.ActionMarkAsRedundant:
			markAsNoise(&c, decision)
			stats.Marked++
			stats.ByRule[decision.RuleName]++
			kept = append(kept, c)
		default:
			kept = append(kept, c)
		}
	}
	sbom.Components = kept
	stats.Kept = len(kept)

	if len(removed) > 0 {
		sbom.Relationships = pruneRelationships(sbom.Relationships, removed)
	}

	slog.Default().Info("syftprefilter.complete",
		"examined", stats.Examined,
		"removed", stats.Removed,
		"marked", stats.Marked,
		"kept", stats.Kept,
		"rules_fired", len(stats.ByRule))
	return nil
}

// shouldClassify reports whether c is in scope for the pre-filter.
// Only `type=file` Syft-baseline rows are touched; everything else
// (libraries, applications, frameworks, …) is preserved untouched —
// even when their path matches a rule, they were intentionally
// surfaced as a real Component.
func shouldClassify(c model.Component) bool {
	return c.Type == model.ComponentTypeFile
}

// extractPath finds the file path Syft recorded for c. Three sources,
// in order of preference:
//
//  1. Component.Name when it looks like an absolute path (Syft's
//     default for file rows).
//  2. Component.Properties["syft:location:0:path"] — the canonical
//     spot when Syft preserves a separate location.
//  3. Component.Evidence.Locations[0].Path — the CycloneDX-portable
//     fallback when Syft used the standard Evidence shape.
//
// Returns empty when none of the sources yield a value.
func extractPath(c *model.Component) string {
	if strings.HasPrefix(c.Name, "/") {
		return c.Name
	}
	if v := c.Properties["syft:location:0:path"]; v != "" {
		return v
	}
	if c.Evidence != nil && len(c.Evidence.Locations) > 0 {
		return c.Evidence.Locations[0].Path
	}
	return ""
}

// markAsNoise stamps the `astinus:noise` properties on c per the
// rule's decision. Idempotent — re-marking is a no-op.
func markAsNoise(c *model.Component, d pathclassifier.Decision) {
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties[PropertyNoise] = "true"
	if d.RuleName != "" {
		c.Properties[PropertyNoiseRule] = d.RuleName
	}
}

// pruneRelationships drops any edge whose Source or Target is in the
// removed set. Kept defensive: a Relationship referencing a removed
// BOMRef from EITHER end is dead — broken pointers in the
// dependency graph are worse than a missing edge.
func pruneRelationships(in []model.Relationship, removed map[string]bool) []model.Relationship {
	if len(in) == 0 {
		return in
	}
	out := make([]model.Relationship, 0, len(in))
	for _, r := range in {
		if removed[r.SourceRef] || removed[r.TargetRef] {
			continue
		}
		out = append(out, r)
	}
	return out
}
