package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Pipeline runs a chain of Enrichers in order over a single SBOM.
//
// Construction:
//
//	p := enrich.NewPipeline(logger, attribution.New(), basediff.New(), ...)
//	if err := p.Run(ctx, sbom, bundle); err != nil { ... }
//
// Order matters: attribution must run before basediff (which uses
// LayerInfo to decide origin), basediff before untracked (which
// inherits origin), and untracked before cpe (CPEs are added to
// already-discovered components).
type Pipeline struct {
	enrichers []Enricher
	logger    *slog.Logger
}

// NewPipeline returns a Pipeline that runs enrichers in the given
// order. logger may be nil — a discard logger is substituted.
func NewPipeline(logger *slog.Logger, enrichers ...Enricher) *Pipeline {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Pipeline{
		enrichers: append([]Enricher(nil), enrichers...),
		logger:    logger,
	}
}

// Enrichers returns the registered enrichers in order.
func (p *Pipeline) Enrichers() []Enricher {
	out := make([]Enricher, len(p.enrichers))
	copy(out, p.enrichers)
	return out
}

// Run iterates through every registered enricher, calling Enrich on
// each. The first error halts the pipeline and is returned wrapped
// with the offending enricher's name.
//
// The SBOM is mutated in place — Run does not return a new instance.
//
// On success, Run stamps the top-level metadata with
// PropertyEnrichedBy / PropertyEnrichedVersion so downstream
// consumers can tell the SBOM has been through Astinus even if they
// do not understand any specific `astinus:*` property.
func (p *Pipeline) Run(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil {
		return errors.New("pipeline: nil sbom")
	}
	if bundle == nil {
		return errors.New("pipeline: nil bundle")
	}

	totalStart := time.Now()
	for _, e := range p.enrichers {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := time.Now()
		p.logger.Debug("enricher.start", "name", e.Name())

		err := e.Enrich(ctx, sbom, bundle)
		dur := time.Since(start)

		if err != nil {
			p.logger.Error("enricher.fail",
				"name", e.Name(),
				"duration_ms", dur.Milliseconds(),
				"error", err.Error(),
			)
			return fmt.Errorf("enricher %q: %w", e.Name(), err)
		}

		p.logger.Info("enricher.done",
			"name", e.Name(),
			"duration_ms", dur.Milliseconds(),
		)
	}

	stampMetadata(sbom)

	p.logger.Info("pipeline.done",
		"enrichers", len(p.enrichers),
		"duration_ms", time.Since(totalStart).Milliseconds(),
	)
	return nil
}

// stampMetadata writes the "this SBOM was enriched by Astinus" tag.
// Idempotent: an already-stamped SBOM keeps the existing values.
func stampMetadata(sbom *model.SBOM) {
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	if _, ok := sbom.Metadata.Properties[model.PropertyEnrichedBy]; !ok {
		sbom.Metadata.Properties[model.PropertyEnrichedBy] = "astinus"
	}
	// Always overwrite the version stamp — the latest enrich wins so
	// consumers can tell which Astinus version touched the SBOM most
	// recently. Reading it back via the cyclonedx mapper is safe.
	sbom.Metadata.Properties[model.PropertyEnrichedVersion] = currentVersion()
}

// Filter returns a new slice containing only the enrichers whose
// Name() is in enabled (and not in disabled). Either set may be nil.
//
// Convenience used by the CLI to honour --enable / --disable flags
// without each call site re-implementing the filter.
func Filter(enrichers []Enricher, enabled, disabled map[string]bool) []Enricher {
	out := make([]Enricher, 0, len(enrichers))
	for _, e := range enrichers {
		if disabled[e.Name()] {
			continue
		}
		if len(enabled) > 0 && !enabled[e.Name()] {
			continue
		}
		out = append(out, e)
	}
	return out
}
