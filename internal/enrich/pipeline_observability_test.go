package enrich

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/telemetry"
)

// TestPipelineMetricsRecordSuccess verifies the per-enricher
// histogram + per-pipeline counter both fire on a clean Run.
// PRSD-Task-8.
func TestPipelineMetricsRecordSuccess(t *testing.T) {
	reg := telemetry.NewRegistry()
	a := &stubEnricher{name: "a"}
	b := &stubEnricher{name: "b"}
	p := NewPipeline(nil, a, b).WithMetrics(reg)

	if err := p.Run(context.Background(), &model.SBOM{}, &image.Bundle{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var buf bytes.Buffer
	if err := reg.ExportPrometheus(&buf); err != nil {
		t.Fatalf("ExportPrometheus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`astinus_enricher_duration_seconds_count{enricher="a",status="success"} 1`,
		`astinus_enricher_duration_seconds_count{enricher="b",status="success"} 1`,
		`astinus_pipeline_runs_total{status="success"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\nfull output:\n%s", want, out)
		}
	}
	// No errors → error counter must NOT appear for any series.
	if strings.Contains(out, `astinus_enricher_errors_total{enricher="a"} 1`) {
		t.Error("error counter should not have fired for a successful enricher")
	}
}

// TestPipelineMetricsRecordError verifies the error counter +
// "error" status label fire when an enricher fails.
func TestPipelineMetricsRecordError(t *testing.T) {
	reg := telemetry.NewRegistry()
	a := &stubEnricher{name: "a", err: errors.New("boom")}
	p := NewPipeline(nil, a).WithMetrics(reg)

	if err := p.Run(context.Background(), &model.SBOM{}, &image.Bundle{}); err == nil {
		t.Fatal("expected error from failed enricher")
	}

	var buf bytes.Buffer
	if err := reg.ExportPrometheus(&buf); err != nil {
		t.Fatalf("ExportPrometheus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`astinus_enricher_errors_total{enricher="a"} 1`,
		`astinus_enricher_duration_seconds_count{enricher="a",status="error"} 1`,
		`astinus_pipeline_runs_total{status="error"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestPipelineTracerSpansForEachEnricher verifies the recording
// tracer captures one span per enricher + a wrapping pipeline span.
func TestPipelineTracerSpansForEachEnricher(t *testing.T) {
	tr := &telemetry.RecordingTracer{}
	a := &stubEnricher{name: "a"}
	b := &stubEnricher{name: "b"}
	p := NewPipeline(nil, a, b).WithTracer(tr)

	if err := p.Run(context.Background(), &model.SBOM{}, &image.Bundle{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	spans := tr.Spans()
	if len(spans) != 3 {
		t.Fatalf("len(spans) = %d, want 3 (1 pipeline + 2 enricher)", len(spans))
	}
	// All spans must be Ended.
	for _, s := range spans {
		if !s.Ended {
			t.Errorf("span %q not Ended", s.Name)
		}
	}
	// Per-enricher spans should carry an `enricher` attribute.
	enricherSpans := 0
	for _, s := range spans {
		if v, ok := s.Attributes["enricher"]; ok {
			enricherSpans++
			if v != "a" && v != "b" {
				t.Errorf("unexpected enricher attr %v", v)
			}
		}
	}
	if enricherSpans != 2 {
		t.Errorf("got %d enricher spans, want 2", enricherSpans)
	}
}

// TestPipelineNoMetricsByDefault verifies a Pipeline without
// WithMetrics doesn't panic and doesn't pollute any registry.
func TestPipelineNoMetricsByDefault(t *testing.T) {
	a := &stubEnricher{name: "a"}
	p := NewPipeline(nil, a)
	if err := p.Run(context.Background(), &model.SBOM{}, &image.Bundle{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// No metrics registry was wired — Run must complete without a
	// nil-deref. Nothing else to check.
}
