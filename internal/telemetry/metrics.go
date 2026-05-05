package telemetry

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// MetricKind distinguishes the three Prometheus metric shapes
// Astinus emits.
type MetricKind int

// Recognised metric shapes.
const (
	// KindCounter is monotonic; only Inc / Add(positive).
	KindCounter MetricKind = iota
	// KindGauge is a snapshot value; Set / Inc / Dec / Add (any sign).
	KindGauge
	// KindHistogram bucketises observations; Observe(value).
	KindHistogram
)

// String renders the kind as the Prometheus exposition `# TYPE`
// keyword.
func (k MetricKind) String() string {
	switch k {
	case KindCounter:
		return "counter"
	case KindGauge:
		return "gauge"
	case KindHistogram:
		return "histogram"
	default:
		return "untyped"
	}
}

// Registry is the in-process metrics store. Compose from the
// telemetry package's NewRegistry; callers register Metric
// objects up front and then mutate them throughout the run.
//
// Concurrency: every Metric method is safe; Registry's own state
// (the metric map) is guarded by an RWMutex.
//
// # Why in-tree
//
// Pulling in `prometheus/client_golang` adds 2+ direct deps and a
// MB of binary. Same precedent as PRSD-Task-1/2/3/4/5/6/7
// (in-tree trie / bloom / TOML / extractor / token-bucket /
// topo-sort / structural validators): bounded algorithm + simple
// I/O = in-tree. The Prometheus exposition format is a 100-line
// spec; the encoder below covers the subset Astinus emits
// (counter / gauge / histogram with labels). ADR-0026.
type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*Metric
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{metrics: map[string]*Metric{}}
}

// MustRegister registers m and panics if a metric with the same
// name+labels already exists. Production code should construct
// metrics at startup; a panic on collision surfaces the bug at
// init time rather than as a silent overwrite later.
func (r *Registry) MustRegister(m *Metric) *Metric {
	if err := r.Register(m); err != nil {
		panic(err)
	}
	return m
}

// Register adds m to the registry. Returns an error when a metric
// with the same Name is already registered.
func (r *Registry) Register(m *Metric) error {
	if m == nil {
		return fmt.Errorf("telemetry: nil metric")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.metrics[m.name]; dup {
		return fmt.Errorf("telemetry: duplicate metric %q", m.name)
	}
	r.metrics[m.name] = m
	return nil
}

// Get returns the metric registered under name, or nil when
// absent.
func (r *Registry) Get(name string) *Metric {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metrics[name]
}

// Names returns every registered metric name in lexical order.
// Useful for diagnostic CLI output.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ExportPrometheus writes every metric as Prometheus text-format
// exposition. The output is sorted by metric name so successive
// runs produce byte-identical output (cheap regression check).
func (r *Registry) ExportPrometheus(w io.Writer) error {
	r.mu.RLock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	sort.Strings(names)
	metrics := make([]*Metric, 0, len(names))
	for _, n := range names {
		metrics = append(metrics, r.metrics[n])
	}
	r.mu.RUnlock()

	for _, m := range metrics {
		if err := m.encodePrometheus(w); err != nil {
			return fmt.Errorf("telemetry: encode %s: %w", m.name, err)
		}
	}
	return nil
}

// Metric is one named series — a counter, gauge, or histogram
// with optional label dimensions. Construct via NewCounter /
// NewGauge / NewHistogram. Mutations go through label-keyed
// methods (`m.Counter("a", "b").Inc()`).
type Metric struct {
	name    string
	help    string
	kind    MetricKind
	labels  []string
	buckets []float64 // histograms only

	mu     sync.RWMutex
	series map[string]*series
}

// series is one (name, labels-tuple) data point.
type series struct {
	labelValues []string

	// Counter / gauge value.
	value float64

	// Histogram state.
	bucketCounts []uint64
	count        uint64
	sum          float64
}

// NewCounter creates a counter metric. labels is the list of
// dimension names; pass nil for an unlabelled counter.
func NewCounter(name, help string, labels []string) *Metric {
	return &Metric{name: name, help: help, kind: KindCounter,
		labels: append([]string(nil), labels...),
		series: map[string]*series{}}
}

// NewGauge creates a gauge metric.
func NewGauge(name, help string, labels []string) *Metric {
	return &Metric{name: name, help: help, kind: KindGauge,
		labels: append([]string(nil), labels...),
		series: map[string]*series{}}
}

// DefaultBuckets is the conventional Prometheus histogram bucket
// set covering 5 ms → ~10 s. Suits Astinus's per-enricher
// duration observations; callers needing different buckets
// supply them via NewHistogram.
var DefaultBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// NewHistogram creates a histogram metric with the supplied
// bucket upper bounds. Pass nil to use DefaultBuckets.
func NewHistogram(name, help string, labels []string, buckets []float64) *Metric {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	out := make([]float64, len(buckets))
	copy(out, buckets)
	sort.Float64s(out)
	return &Metric{name: name, help: help, kind: KindHistogram,
		labels:  append([]string(nil), labels...),
		buckets: out,
		series:  map[string]*series{}}
}

// Inc adds 1 to the counter / gauge for the supplied label
// values. Histograms are NOT incrementable; callers should use
// Observe instead — calling Inc on a histogram is a no-op.
func (m *Metric) Inc(labelValues ...string) {
	if m.kind == KindHistogram {
		return
	}
	m.add(1, labelValues)
}

// Add accumulates n on the counter / gauge. For counters n MUST
// be non-negative; the function silently caps negative inputs at
// zero. (A panic would crash production for what's almost always a
// typo.)
func (m *Metric) Add(n float64, labelValues ...string) {
	if m.kind == KindCounter && n < 0 {
		return
	}
	if m.kind == KindHistogram {
		m.observe(n, labelValues)
		return
	}
	m.add(n, labelValues)
}

// Set replaces the gauge's value. Counter Set is rejected
// (counters are monotonic); histogram Set is rejected.
func (m *Metric) Set(n float64, labelValues ...string) {
	if m.kind != KindGauge {
		return
	}
	m.set(n, labelValues)
}

// Observe records a value in the histogram. Increments the count
// and adds the value to the sum + every bucket whose upper bound
// is ≥ value.
func (m *Metric) Observe(value float64, labelValues ...string) {
	if m.kind != KindHistogram {
		return
	}
	m.observe(value, labelValues)
}

func (m *Metric) add(delta float64, labelValues []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.seriesForLocked(labelValues)
	s.value += delta
}

func (m *Metric) set(value float64, labelValues []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.seriesForLocked(labelValues)
	s.value = value
}

func (m *Metric) observe(value float64, labelValues []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.seriesForLocked(labelValues)
	s.sum += value
	s.count++
	if s.bucketCounts == nil {
		s.bucketCounts = make([]uint64, len(m.buckets))
	}
	for i, b := range m.buckets {
		if value <= b {
			s.bucketCounts[i]++
		}
	}
}

// seriesForLocked returns the series for the supplied label values,
// creating it on first observation. Caller MUST hold m.mu (write
// lock) — both the read and the create-on-miss touch the map.
func (m *Metric) seriesForLocked(labelValues []string) *series {
	key := joinLabelValues(labelValues)
	s, ok := m.series[key]
	if !ok {
		s = &series{labelValues: append([]string(nil), labelValues...)}
		m.series[key] = s
	}
	return s
}

// encodePrometheus writes m's HELP/TYPE/series lines to w.
func (m *Metric) encodePrometheus(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n", m.name, escapeHelp(m.help)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", m.name, m.kind.String()); err != nil {
		return err
	}
	m.mu.RLock()
	keys := make([]string, 0, len(m.series))
	for k := range m.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	defer m.mu.RUnlock()

	for _, k := range keys {
		s := m.series[k]
		if err := m.writeSeries(w, s); err != nil {
			return err
		}
	}
	return nil
}

// writeSeries writes one (labels-tuple) data line per metric kind.
func (m *Metric) writeSeries(w io.Writer, s *series) error {
	labels := formatLabels(m.labels, s.labelValues)
	switch m.kind {
	case KindCounter, KindGauge:
		_, err := fmt.Fprintf(w, "%s%s %s\n", m.name, labels, formatFloat(s.value))
		return err
	case KindHistogram:
		for i, b := range m.buckets {
			leLabels := mergeLabels(labels, "le", formatFloat(b))
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", m.name, leLabels, s.bucketCounts[i]); err != nil {
				return err
			}
		}
		// Final +Inf bucket — count of observations regardless of value.
		leInf := mergeLabels(labels, "le", "+Inf")
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", m.name, leInf, s.count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %s\n", m.name, labels, formatFloat(s.sum)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", m.name, labels, s.count); err != nil {
			return err
		}
	}
	return nil
}

// joinLabelValues turns a label-values slice into a stable string
// key for the per-metric series map.
func joinLabelValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, "\x00")
}

// formatLabels renders the `{name="value",…}` clause for a
// series. Returns "" when there are no labels. Output is sorted
// by label name so successive runs produce byte-identical output.
func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(names))
	for i, n := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		pairs = append(pairs, fmt.Sprintf("%s=%q", n, escapeLabelValue(v)))
	}
	sort.Strings(pairs)
	return "{" + strings.Join(pairs, ",") + "}"
}

// mergeLabels appends one extra (name, value) into an existing
// labels clause. Used to add the histogram-specific `le` label
// without shuffling the existing labels.
func mergeLabels(existing, name, value string) string {
	pair := fmt.Sprintf("%s=%q", name, escapeLabelValue(value))
	if existing == "" {
		return "{" + pair + "}"
	}
	// existing is `{...}`; insert before the closing brace.
	return existing[:len(existing)-1] + "," + pair + "}"
}

// escapeLabelValue escapes the three characters Prometheus
// requires backslash-escaping in label values.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// escapeHelp escapes backslash + newline in HELP text per the
// Prometheus exposition format.
func escapeHelp(h string) string {
	h = strings.ReplaceAll(h, `\`, `\\`)
	h = strings.ReplaceAll(h, "\n", `\n`)
	return h
}

// formatFloat renders v as a Prometheus-friendly number. Avoids
// scientific notation for values in the conventional metric range
// — operators reading `astinus_pipeline_duration_seconds 0.123`
// shouldn't have to mentally parse `1.23e-1`.
func formatFloat(v float64) string {
	return fmt.Sprintf("%g", v)
}
