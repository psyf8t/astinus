package telemetry

import (
	"context"
	"sync"
	"time"
)

// Tracer is the interface Astinus uses to wrap units of work in a
// span. The default implementation (NoopTracer) satisfies it without
// exporting anything; a future build can swap in an OpenTelemetry-
// backed tracer behind the same surface.
//
// # Why a stub instead of OpenTelemetry today
//
// Pulling in `go.opentelemetry.io/otel` + the OTLP exporter adds ~30
// transitive deps and ~6 MB to the binary. The PRSD-Task-8 design
// commits to the call-site shape (Start / span.End / span.SetAttr)
// today and defers the wire protocol — same precedent as PRSD-Task-1
// through PRSD-Task-7 (in-tree where bounded; depend out only when
// the deferred cost can no longer be amortised). ADR-0026.
//
// A future Tracer that actually exports spans only needs to implement
// this interface; existing call sites do not change. The NoopTracer
// remains the default when --tracing-endpoint is empty.
type Tracer interface {
	// Start opens a new span. Returns the (possibly child) context
	// the caller should pass to descendants and a Span the caller
	// MUST call End on (use defer span.End()).
	Start(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span)
}

// Span is one unit of work in a trace. It is intentionally tiny —
// the public surface is what call sites need; everything else is
// hidden behind the implementation.
type Span interface {
	// SetAttr attaches a key/value pair to the span. Repeated calls
	// with the same key overwrite.
	SetAttr(key string, value any)
	// End closes the span. Safe to call exactly once; later calls
	// are no-ops.
	End()
}

// Attribute is a typed key/value pair recorded at span creation
// time. Mirrors the OpenTelemetry shape so a future swap-in does
// not require changing call sites.
type Attribute struct {
	Key   string
	Value any
}

// Attr is a brevity helper for constructing an Attribute inline:
//
//	tracer.Start(ctx, "enricher.run", telemetry.Attr("enricher", e.Name()))
func Attr(key string, value any) Attribute {
	return Attribute{Key: key, Value: value}
}

// NoopTracer satisfies Tracer without recording anything. It is the
// zero-cost default when tracing is disabled (the common production
// case today).
type NoopTracer struct{}

// Start implements Tracer. Returns the original context unchanged
// and a noopSpan whose methods are no-ops.
func (NoopTracer) Start(ctx context.Context, _ string, _ ...Attribute) (context.Context, Span) {
	return ctx, noopSpan{}
}

type noopSpan struct{}

func (noopSpan) SetAttr(string, any) {}
func (noopSpan) End()                {}

// RecordingTracer captures span lifecycle events in memory. Used
// exclusively by the test suite — production code should never
// reach for it. The zero value is ready to use.
//
// It exists so tests can assert on span emission shape without
// linking an exporter. A real OpenTelemetry tracer would replace
// the in-memory store with a span batch + exporter pipeline.
type RecordingTracer struct {
	mu    sync.Mutex
	spans []*RecordedSpan
}

// RecordedSpan is one span captured by RecordingTracer.
type RecordedSpan struct {
	Name       string
	Attributes map[string]any
	StartedAt  time.Time
	EndedAt    time.Time
	Ended      bool
}

// Start implements Tracer for the recording variant.
func (r *RecordingTracer) Start(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span) {
	span := &RecordedSpan{
		Name:       name,
		Attributes: make(map[string]any, len(attrs)),
		StartedAt:  time.Now(),
	}
	for _, a := range attrs {
		span.Attributes[a.Key] = a.Value
	}
	r.mu.Lock()
	r.spans = append(r.spans, span)
	r.mu.Unlock()
	return ctx, &recordedSpanHandle{tracer: r, span: span}
}

// Spans returns a snapshot of every span Start has been called for,
// in the order they were started.
func (r *RecordingTracer) Spans() []*RecordedSpan {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*RecordedSpan, len(r.spans))
	copy(out, r.spans)
	return out
}

type recordedSpanHandle struct {
	tracer *RecordingTracer
	span   *RecordedSpan
}

func (h *recordedSpanHandle) SetAttr(key string, value any) {
	h.tracer.mu.Lock()
	defer h.tracer.mu.Unlock()
	h.span.Attributes[key] = value
}

func (h *recordedSpanHandle) End() {
	h.tracer.mu.Lock()
	defer h.tracer.mu.Unlock()
	if h.span.Ended {
		return
	}
	h.span.EndedAt = time.Now()
	h.span.Ended = true
}

// InitTracing returns the Tracer Astinus should use for the run
// based on the supplied endpoint string.
//
//   - Empty endpoint (the production default today) → NoopTracer.
//   - Any non-empty endpoint → still NoopTracer for now, plus a
//     deferred-feature notice via the returned bool. A future
//     OpenTelemetry build replaces the second branch.
//
// The CLI passes the resolved --tracing-endpoint flag; both arms
// are picked at startup so the per-call hot path doesn't have to
// re-check.
func InitTracing(endpoint string) (Tracer, bool) {
	if endpoint == "" {
		return NoopTracer{}, false
	}
	// Endpoint configured but exporter not compiled in. The CLI
	// surfaces this through EventTracingDisabled so operators see
	// the explicit reason rather than silent absence of spans.
	return NoopTracer{}, true
}
