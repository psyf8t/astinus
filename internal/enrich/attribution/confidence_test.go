package attribution

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/image/runtime"
)

func TestDetermineConfidenceProvenanceWins(t *testing.T) {
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: ""}, // even with bad history, provenance wins
	}
	conf, reason := DetermineConfidence(layers, runtime.RuntimeKaniko, func() bool { return true })
	if conf != ConfidenceHigh {
		t.Errorf("conf = %q, want high", conf)
	}
	if !strings.Contains(reason, "provenance") {
		t.Errorf("reason = %q, want to mention provenance", reason)
	}
}

func TestDetermineConfidenceNoLayers(t *testing.T) {
	conf, reason := DetermineConfidence(nil, runtime.RuntimeDocker, nil)
	if conf != ConfidenceNone {
		t.Errorf("conf = %q, want none", conf)
	}
	if reason == "" {
		t.Error("reason should be non-empty")
	}
}

func TestDetermineConfidenceKanikoIsLow(t *testing.T) {
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: "RUN something", RuntimeMetadata: map[string]string{"squashed": "likely"}},
	}
	conf, reason := DetermineConfidence(layers, runtime.RuntimeKaniko, nil)
	if conf != ConfidenceLow {
		t.Errorf("conf = %q, want low", conf)
	}
	if !strings.Contains(strings.ToLower(reason), "kaniko") {
		t.Errorf("reason = %q, want to mention Kaniko", reason)
	}
}

func TestDetermineConfidenceSquashedDocker(t *testing.T) {
	// Docker --squash output: 1 layer with the squash quirk metadata.
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: "RUN apt-get && build && copy", RuntimeMetadata: map[string]string{"squashed": "likely"}},
	}
	conf, _ := DetermineConfidence(layers, runtime.RuntimeDocker, nil)
	if conf != ConfidenceLow {
		t.Errorf("conf = %q, want low", conf)
	}
}

func TestDetermineConfidenceFullHistoryIsMedium(t *testing.T) {
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: "FROM scratch", RuntimeMetadata: map[string]string{}},
		{Index: 1, CreatedBy: "RUN apt-get update", RuntimeMetadata: map[string]string{}},
		{Index: 2, CreatedBy: "COPY app /app", RuntimeMetadata: map[string]string{}},
	}
	conf, _ := DetermineConfidence(layers, runtime.RuntimeDocker, nil)
	if conf != ConfidenceMedium {
		t.Errorf("conf = %q, want medium", conf)
	}
}

func TestDetermineConfidenceMissingHistoryIsLow(t *testing.T) {
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: "FROM scratch", RuntimeMetadata: map[string]string{}},
		{Index: 1, CreatedBy: "", RuntimeMetadata: map[string]string{}}, // missing
		{Index: 2, CreatedBy: "COPY app /app", RuntimeMetadata: map[string]string{}},
	}
	conf, _ := DetermineConfidence(layers, runtime.RuntimeDocker, nil)
	if conf != ConfidenceLow {
		t.Errorf("conf = %q, want low (missing history)", conf)
	}
}

func TestDetermineConfidenceProvenanceCallbackNil(t *testing.T) {
	layers := []runtime.NormalizedLayer{
		{Index: 0, CreatedBy: "FROM scratch", RuntimeMetadata: map[string]string{}},
	}
	// Nil callback must not panic.
	conf, _ := DetermineConfidence(layers, runtime.RuntimeDocker, nil)
	if conf != ConfidenceMedium {
		t.Errorf("conf = %q, want medium", conf)
	}
}

func TestEvidenceSummary(t *testing.T) {
	got := EvidenceSummary(nil)
	if got != "" {
		t.Errorf("got = %q, want empty for nil evidence", got)
	}

	ev := []runtime.DetectionEvidence{
		{Field: "config.Author", Value: "Kaniko", Reason: "exact author match"},
		{Field: "config.Labels[moby.buildkit.frontend]", Value: "dockerfile.v1", Reason: "label present"},
	}
	got = EvidenceSummary(ev)
	if !strings.Contains(got, "config.Author") || !strings.Contains(got, "Kaniko") {
		t.Errorf("got = %q, want to include author evidence", got)
	}
	if !strings.Contains(got, "label present") {
		t.Errorf("got = %q, want reason text", got)
	}
}

func TestEvidenceSummaryTruncatesValue(t *testing.T) {
	long := strings.Repeat("a", 200)
	ev := []runtime.DetectionEvidence{{Field: "x", Value: long, Reason: "r"}}
	got := EvidenceSummary(ev)
	if !strings.Contains(got, "…") {
		t.Errorf("got = %q, want truncation marker", got)
	}
	if len(got) > 100 {
		t.Errorf("got len = %d, want truncated", len(got))
	}
}
