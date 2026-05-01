// Package telemetry wires up structured logging for the CLI.
//
// The default behavior follows the contract from the spec section 9.2:
//
//   - When stdout is a TTY and CI env vars are absent, use the human-readable
//     text handler with the configured level.
//   - When running in CI (CI=true, GITHUB_ACTIONS=true, GITLAB_CI=true) or
//     when stdout is not a TTY, use the JSON handler.
//
// The package exposes a single constructor; there is intentionally no
// global default logger — callers wire the returned *slog.Logger through
// constructors to keep test isolation straightforward.
package telemetry

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the slog handler shape.
type Format int

const (
	// FormatAuto picks Text for TTY/non-CI and JSON otherwise.
	FormatAuto Format = iota
	// FormatText forces the human-readable handler.
	FormatText
	// FormatJSON forces the structured JSON handler.
	FormatJSON
)

// Options configures NewLogger.
type Options struct {
	// Level is the slog.Level threshold. Zero value = LevelInfo.
	Level slog.Level
	// Format chooses handler shape; FormatAuto by default.
	Format Format
	// Writer is where log records are emitted. Defaults to os.Stderr.
	Writer io.Writer
	// NoColor disables ANSI color codes in text mode. The stdlib text
	// handler does not currently emit colors, so this is reserved for
	// future use; preserved here so the CLI flag has a stable home.
	NoColor bool
}

// NewLogger builds a *slog.Logger according to opts. It never returns nil.
func NewLogger(opts Options) *slog.Logger {
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	format := opts.Format
	if format == FormatAuto {
		format = autoDetectFormat(w)
	}

	var h slog.Handler
	switch format {
	case FormatJSON:
		h = slog.NewJSONHandler(w, handlerOpts)
	default:
		h = slog.NewTextHandler(w, handlerOpts)
	}
	return slog.New(h)
}

// ParseLevel converts a CLI-friendly level string to slog.Level.
// Unknown values fall back to slog.LevelInfo; the caller can decide
// whether to treat that as a hard error.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// autoDetectFormat returns FormatJSON if the process is clearly running
// under a CI system OR if w is not a TTY; FormatText otherwise.
func autoDetectFormat(w io.Writer) Format {
	if isCI() {
		return FormatJSON
	}
	if !isTerminal(w) {
		return FormatJSON
	}
	return FormatText
}

// isCI checks the standard CI signal env vars from spec section 9.2.
func isCI() bool {
	for _, v := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
		if val := os.Getenv(v); val != "" && val != "false" && val != "0" {
			return true
		}
	}
	return false
}

// isTerminal reports whether w is an *os.File pointing at a character
// device (i.e. a terminal). For non-*os.File writers it returns false,
// which keeps tests deterministic without depending on golang.org/x/term.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
