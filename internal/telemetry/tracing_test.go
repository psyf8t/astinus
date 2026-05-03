package telemetry

import (
	"context"
	"testing"
)

func TestNoopTracerStartReturnsNoopSpan(t *testing.T) {
	ctx, span := NoopTracer{}.Start(context.Background(), "test", Attr("k", "v"))
	if ctx == nil {
		t.Fatal("ctx must not be nil")
	}
	// Any of these would panic if the implementation regressed.
	span.SetAttr("k2", 42)
	span.End()
	span.End() // double End must not panic.
}

func TestRecordingTracerCapturesSpans(t *testing.T) {
	tr := &RecordingTracer{}
	_, span := tr.Start(context.Background(), "stage.run", Attr("enricher", "basediff"))
	span.SetAttr("duration_seconds", 0.123)
	span.End()

	got := tr.Spans()
	if len(got) != 1 {
		t.Fatalf("len(spans) = %d, want 1", len(got))
	}
	s := got[0]
	if s.Name != "stage.run" {
		t.Errorf("name = %q, want stage.run", s.Name)
	}
	if !s.Ended {
		t.Error("span should be marked Ended")
	}
	if s.Attributes["enricher"] != "basediff" {
		t.Errorf("attr enricher = %v", s.Attributes["enricher"])
	}
	if s.Attributes["duration_seconds"] != 0.123 {
		t.Errorf("attr duration_seconds = %v", s.Attributes["duration_seconds"])
	}
}

func TestRecordingTracerEndIdempotent(t *testing.T) {
	tr := &RecordingTracer{}
	_, span := tr.Start(context.Background(), "x")
	span.End()
	first := tr.Spans()[0].EndedAt
	span.End()
	second := tr.Spans()[0].EndedAt
	if !first.Equal(second) {
		t.Errorf("End is supposed to be idempotent: %v vs %v", first, second)
	}
}

func TestInitTracingEmptyEndpointReturnsNoop(t *testing.T) {
	tr, deferred := InitTracing("")
	if _, ok := tr.(NoopTracer); !ok {
		t.Errorf("empty endpoint should return NoopTracer, got %T", tr)
	}
	if deferred {
		t.Error("empty endpoint should not signal 'deferred'")
	}
}

func TestInitTracingNonEmptyEndpointSignalsDeferred(t *testing.T) {
	tr, deferred := InitTracing("otlp://collector:4317")
	if _, ok := tr.(NoopTracer); !ok {
		t.Errorf("non-empty endpoint still returns NoopTracer until OTel is wired, got %T", tr)
	}
	if !deferred {
		t.Error("non-empty endpoint should signal 'deferred=true' so CLI can warn")
	}
}
