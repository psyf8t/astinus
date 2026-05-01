package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(Options{Format: FormatJSON, Writer: &buf, Level: slog.LevelInfo})
	logger.Info("hello", "k", "v")

	out := buf.String()
	if !strings.Contains(out, `"msg":"hello"`) {
		t.Fatalf("expected JSON output with msg, got %q", out)
	}
	if !strings.Contains(out, `"k":"v"`) {
		t.Fatalf("expected JSON output with attr, got %q", out)
	}
}

func TestNewLoggerTextHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(Options{Format: FormatText, Writer: &buf, Level: slog.LevelInfo})
	logger.Info("hello", "k", "v")

	out := buf.String()
	if !strings.Contains(out, "msg=hello") {
		t.Fatalf("expected text output with msg, got %q", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Fatalf("expected text output with attr, got %q", out)
	}
}

func TestNewLoggerAutoFormatNonTTY(t *testing.T) {
	// A bytes.Buffer is not an *os.File and not a CI signal sentinel,
	// so auto detection should land on JSON because non-TTY -> JSON.
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")

	var buf bytes.Buffer
	logger := NewLogger(Options{Writer: &buf})
	logger.Info("auto")

	if !strings.Contains(buf.String(), `"msg":"auto"`) {
		t.Fatalf("auto format on non-TTY should pick JSON; got %q", buf.String())
	}
}

func TestNewLoggerLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(Options{Format: FormatJSON, Writer: &buf, Level: slog.LevelWarn})
	logger.Info("info-msg")
	logger.Warn("warn-msg")

	out := buf.String()
	if strings.Contains(out, "info-msg") {
		t.Fatalf("info record should be filtered by LevelWarn, got %q", out)
	}
	if !strings.Contains(out, "warn-msg") {
		t.Fatalf("warn record missing, got %q", out)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]struct {
		want slog.Level
		ok   bool
	}{
		"debug":    {slog.LevelDebug, true},
		"INFO":     {slog.LevelInfo, true},
		"":         {slog.LevelInfo, true},
		"warn":     {slog.LevelWarn, true},
		"warning":  {slog.LevelWarn, true},
		"error":    {slog.LevelError, true},
		"verbose ": {slog.LevelInfo, false},
	}
	for input, want := range cases {
		got, ok := ParseLevel(input)
		if got != want.want || ok != want.ok {
			t.Errorf("ParseLevel(%q) = (%v, %v); want (%v, %v)", input, got, ok, want.want, want.ok)
		}
	}
}

func TestIsCITreatsFalseAsAbsent(t *testing.T) {
	t.Setenv("CI", "false")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "0")
	if isCI() {
		t.Fatal("isCI() should return false when CI=false / GITLAB_CI=0")
	}
}

func TestIsCIDetectsTruthy(t *testing.T) {
	t.Setenv("CI", "true")
	if !isCI() {
		t.Fatal("isCI() should return true when CI=true")
	}
}
