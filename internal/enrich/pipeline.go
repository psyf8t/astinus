package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/telemetry"
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
	tracer    telemetry.Tracer
	metrics   *pipelineMetrics
}

// pipelineMetrics is the bundle of Prometheus metrics Run instruments.
// Built once per Pipeline so per-enricher mutations don't pay a
// registry-lookup cost on every call.
type pipelineMetrics struct {
	enricherDuration *telemetry.Metric // histogram, labels: enricher, status
	enricherErrors   *telemetry.Metric // counter,   labels: enricher
	pipelineRuns     *telemetry.Metric // counter,   labels: status
	pipelineDuration *telemetry.Metric // histogram, labels: status
}

// NewPipeline returns a Pipeline that runs enrichers in the given
// order. logger may be nil — a discard logger is substituted.
//
// Telemetry is opt-in: register a Pipeline-side metrics view via
// WithMetrics; otherwise Run records nothing. A NoopTracer is used
// when no tracer is wired; spans are zero-cost in that mode.
func NewPipeline(logger *slog.Logger, enrichers ...Enricher) *Pipeline {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Pipeline{
		enrichers: append([]Enricher(nil), enrichers...),
		logger:    logger,
		tracer:    telemetry.NoopTracer{},
	}
}

// WithMetrics registers per-enricher and per-run Prometheus metrics
// against the supplied Registry. Calling twice replaces the bound
// metrics; passing nil disables metrics. Returns the Pipeline so
// callers can chain.
//
// PRSD-Task-8: see ADR-0026 for the metric naming + labels rationale.
func (p *Pipeline) WithMetrics(reg *telemetry.Registry) *Pipeline {
	if reg == nil {
		p.metrics = nil
		return p
	}
	p.metrics = &pipelineMetrics{
		enricherDuration: reg.MustRegister(telemetry.NewHistogram(
			"astinus_enricher_duration_seconds",
			"Per-enricher Enrich() duration in seconds.",
			[]string{"enricher", "status"}, nil,
		)),
		enricherErrors: reg.MustRegister(telemetry.NewCounter(
			"astinus_enricher_errors_total",
			"Per-enricher Enrich() error count.",
			[]string{"enricher"},
		)),
		pipelineRuns: reg.MustRegister(telemetry.NewCounter(
			"astinus_pipeline_runs_total",
			"Total pipeline runs labeled by terminal status.",
			[]string{"status"},
		)),
		pipelineDuration: reg.MustRegister(telemetry.NewHistogram(
			"astinus_pipeline_duration_seconds",
			"Total pipeline duration in seconds.",
			[]string{"status"}, nil,
		)),
	}
	return p
}

// WithTracer sets the tracer Run uses to wrap each enricher in a
// span. Pass NoopTracer (the default) to disable tracing.
func (p *Pipeline) WithTracer(tr telemetry.Tracer) *Pipeline {
	if tr == nil {
		tr = telemetry.NoopTracer{}
	}
	p.tracer = tr
	return p
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

	// PRSD-Task-6: re-order via topological sort over each
	// enricher's `Dependencies()` declaration. The sort preserves
	// input order for tie-breaks (peers with no real dependency
	// stay in registration order) so operators see predictable
	// behaviour when no dep forces an order.
	ordered, err := TopoSort(p.enrichers)
	if err != nil {
		return fmt.Errorf("pipeline: topo sort: %w", err)
	}
	p.logger.Info(telemetry.EventPipelineOrder, "order", enricherNames(ordered))

	pipelineCtx, pipelineSpan := p.tracer.Start(ctx, telemetry.EventPipelineStart,
		telemetry.Attr("enrichers", len(ordered)))
	defer pipelineSpan.End()

	totalStart := time.Now()
	if err := p.runEnrichers(pipelineCtx, sbom, bundle, ordered); err != nil {
		p.recordPipelineEnd("error", time.Since(totalStart))
		return err
	}

	stampMetadata(sbom)
	dur := time.Since(totalStart)
	p.recordPipelineEnd("success", dur)
	pipelineSpan.SetAttr("duration_seconds", dur.Seconds())

	p.logger.Info(telemetry.EventPipelineDone,
		"enrichers", len(p.enrichers),
		"duration_ms", dur.Milliseconds(),
	)
	return nil
}

// runEnrichers iterates through ordered, instrumenting each call with
// metrics + tracing. Returns the first error wrapped with the
// offending enricher's name (matching the previous Run contract).
func (p *Pipeline) runEnrichers(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle, ordered []Enricher) error {
	for _, e := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.runOne(ctx, sbom, bundle, e); err != nil {
			return err
		}
	}
	return nil
}

// runOne dispatches a single enricher with span + metrics
// instrumentation.
func (p *Pipeline) runOne(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle, e Enricher) error {
	spanCtx, span := p.tracer.Start(ctx, telemetry.EventEnricherStart,
		telemetry.Attr("enricher", e.Name()))
	defer span.End()

	start := time.Now()
	p.logger.Debug(telemetry.EventEnricherStart, "name", e.Name())

	err := e.Enrich(spanCtx, sbom, bundle)
	dur := time.Since(start)
	span.SetAttr("duration_seconds", dur.Seconds())

	if err != nil {
		span.SetAttr("error", err.Error())
		p.recordEnricherEnd(e.Name(), "error", dur)
		p.logger.Error(telemetry.EventEnricherFail,
			"name", e.Name(),
			"duration_ms", dur.Milliseconds(),
			"error", err.Error(),
		)
		return fmt.Errorf("enricher %q: %w", e.Name(), err)
	}

	p.recordEnricherEnd(e.Name(), "success", dur)
	p.logger.Info(telemetry.EventEnricherDone,
		"name", e.Name(),
		"duration_ms", dur.Milliseconds(),
	)
	return nil
}

func (p *Pipeline) recordEnricherEnd(name, status string, dur time.Duration) {
	if p.metrics == nil {
		return
	}
	p.metrics.enricherDuration.Observe(dur.Seconds(), name, status)
	if status == "error" {
		p.metrics.enricherErrors.Inc(name)
	}
}

func (p *Pipeline) recordPipelineEnd(status string, dur time.Duration) {
	if p.metrics == nil {
		return
	}
	p.metrics.pipelineRuns.Inc(status)
	p.metrics.pipelineDuration.Observe(dur.Seconds(), status)
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

// enricherNames returns the slice of `Name()` values in their
// current order. Used for the `pipeline.order` log line so
// operators can see the sort's effective output.
func enricherNames(enrichers []Enricher) []string {
	out := make([]string, len(enrichers))
	for i, e := range enrichers {
		out[i] = e.Name()
	}
	return out
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
