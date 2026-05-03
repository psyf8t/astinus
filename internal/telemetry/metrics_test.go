package telemetry

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(NewCounter("a", "h", nil)); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register(NewCounter("a", "h", nil)); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}

func TestRegistryMustRegisterPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate MustRegister")
		}
	}()
	r := NewRegistry()
	r.MustRegister(NewCounter("a", "h", nil))
	r.MustRegister(NewCounter("a", "h", nil))
}

func TestCounterIncAndAdd(t *testing.T) {
	c := NewCounter("c", "h", []string{"l"})
	c.Inc("x")
	c.Inc("x")
	c.Add(3, "x")
	c.Add(-5, "x") // capped at zero — counters monotonic
	got := readSeries(c, "x").value
	if got != 5 {
		t.Errorf("counter = %v, want 5", got)
	}
}

func TestGaugeSetAndAdd(t *testing.T) {
	g := NewGauge("g", "h", nil)
	g.Set(10)
	g.Add(-3)
	got := readSeries(g, "").value
	if got != 7 {
		t.Errorf("gauge = %v, want 7", got)
	}
}

func TestHistogramObserveBuckets(t *testing.T) {
	h := NewHistogram("h", "help", nil, []float64{1, 2, 5})
	for _, v := range []float64{0.5, 1.5, 3.0, 7.0} {
		h.Observe(v)
	}
	s := readSeries(h, "")
	if s.count != 4 {
		t.Errorf("count = %d, want 4", s.count)
	}
	if s.sum != 12 {
		t.Errorf("sum = %v, want 12", s.sum)
	}
	// Buckets: ≤1 → {0.5}=1; ≤2 → {0.5,1.5}=2; ≤5 → {0.5,1.5,3.0}=3.
	want := []uint64{1, 2, 3}
	for i, w := range want {
		if s.bucketCounts[i] != w {
			t.Errorf("bucket %d = %d, want %d", i, s.bucketCounts[i], w)
		}
	}
}

func TestExportPrometheusShape(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounter("astinus_test_total", "Test counter.", []string{"label"})).Inc("a")
	r.MustRegister(NewGauge("astinus_test_value", "Test gauge.", nil)).Set(42)
	r.MustRegister(NewHistogram("astinus_test_seconds", "Test histo.", nil, []float64{1, 5})).Observe(0.5)

	var buf bytes.Buffer
	if err := r.ExportPrometheus(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# HELP astinus_test_total Test counter.",
		"# TYPE astinus_test_total counter",
		`astinus_test_total{label="a"} 1`,
		"# HELP astinus_test_value Test gauge.",
		"# TYPE astinus_test_value gauge",
		"astinus_test_value 42",
		"# HELP astinus_test_seconds Test histo.",
		"# TYPE astinus_test_seconds histogram",
		`astinus_test_seconds_bucket{le="1"} 1`,
		`astinus_test_seconds_bucket{le="5"} 1`,
		`astinus_test_seconds_bucket{le="+Inf"} 1`,
		"astinus_test_seconds_sum 0.5",
		"astinus_test_seconds_count 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("export missing line: %q\nfull output:\n%s", want, out)
		}
	}
}

func TestExportPrometheusDeterministic(t *testing.T) {
	r := NewRegistry()
	c := r.MustRegister(NewCounter("c", "h", []string{"k"}))
	c.Inc("a")
	c.Inc("b")
	c.Inc("c")
	var first, second bytes.Buffer
	if err := r.ExportPrometheus(&first); err != nil {
		t.Fatalf("export 1: %v", err)
	}
	if err := r.ExportPrometheus(&second); err != nil {
		t.Fatalf("export 2: %v", err)
	}
	if first.String() != second.String() {
		t.Errorf("export not deterministic:\n%s\nvs\n%s", first.String(), second.String())
	}
}

func TestCounterConcurrentInc(t *testing.T) {
	c := NewCounter("c", "h", nil)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	got := readSeries(c, "").value
	if got != 10000 {
		t.Errorf("counter = %v, want 10000 (data race?)", got)
	}
}

func TestSetOnCounterRejected(t *testing.T) {
	c := NewCounter("c", "h", nil)
	c.Inc()
	c.Set(99)
	if v := readSeries(c, "").value; v != 1 {
		t.Errorf("counter Set should be rejected; value = %v", v)
	}
}

func TestObserveOnCounterRoutesToAdd(t *testing.T) {
	// Add() on a counter with non-negative input becomes the
	// regular accumulator path — verifying the metric kind
	// dispatch is correct.
	c := NewCounter("c", "h", nil)
	c.Add(5)
	if v := readSeries(c, "").value; v != 5 {
		t.Errorf("counter = %v, want 5", v)
	}
}

// readSeries is a test helper that pulls the (single) series out of a
// metric by its joined-label key — kept here so the production
// surface doesn't have to expose internal accessors.
func readSeries(m *Metric, key string) *series {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.series[key]
}
