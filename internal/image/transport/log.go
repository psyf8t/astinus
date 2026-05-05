package transport

import (
	"context"
	"fmt"
	"log/slog"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

// retryLogger adapts retryablehttp.Logger to *slog.Logger so retry
// chatter follows the same logging contract as the rest of the
// project. A nil slog logger silences the adapter.
type retryLogger struct {
	logger *slog.Logger
}

// newRetryLogger returns a retryablehttp.Logger backed by logger.
// If logger is nil, a no-op logger is returned so retryablehttp does
// not write to stdout.
func newRetryLogger(logger *slog.Logger) retryablehttp.Logger {
	return &retryLogger{logger: logger}
}

// Printf implements retryablehttp.Logger.
//
// retryablehttp writes one line per retry decision via
// `Printf("[DEBUG] retrying ...")`. We strip the bracketed prefix
// and emit a structured slog event at the corresponding level.
func (r *retryLogger) Printf(format string, args ...any) {
	if r.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	level := slog.LevelDebug
	switch {
	case len(msg) >= 7 && msg[:7] == "[ERROR]":
		level = slog.LevelError
		msg = msg[7:]
	case len(msg) >= 6 && msg[:6] == "[WARN]":
		level = slog.LevelWarn
		msg = msg[6:]
	case len(msg) >= 6 && msg[:6] == "[INFO]":
		level = slog.LevelInfo
		msg = msg[6:]
	case len(msg) >= 7 && msg[:7] == "[DEBUG]":
		msg = msg[7:]
	}
	r.logger.Log(context.Background(), level, "transport.retry: "+msg)
}
