package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// loggerKey is the context key used to attach the configured *slog.Logger.
type loggerKey struct{}

// WithLogger returns a context carrying logger.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFrom retrieves the *slog.Logger attached by WithLogger. If none
// was set, the slog default is returned so callers never need a nil
// check.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// exitError carries a semantic exit code from a deep handler back to
// Execute. It implements error so it threads through cobra unchanged.
type exitError struct {
	code int
	err  error
}

func newExitError(code int, err error) *exitError {
	return &exitError{code: code, err: err}
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// asExitError is a thin wrapper around errors.As so callers don't have
// to import errors just for the type assertion.
func asExitError(err error, target **exitError) bool {
	return errors.As(err, target)
}

// mapPipelineError translates a non-nil pipeline error to the
// appropriate exit code. cpe.ErrSourceUnavailable (S6 Task 0 strict-
// mode timeout) becomes ExitCPESourceUnavailable=60 with the
// actionable resolution hint; everything else stays
// ExitEnrich=ExitInvalidArgs+offsets per the legacy contract.
// Extracted from runEnrich so the latter stays under the gocyclo
// budget (S6 Task 0). ADR-0051 + ADR-0057.
func mapPipelineError(err error) error {
	if errors.Is(err, cpe.ErrSourceUnavailable) {
		return newExitError(ExitCPESourceUnavailable,
			fmt.Errorf("cpe-mode=hybrid: source unavailable (per-call or total wall-time bound fired); "+
				"resolve by setting NVD_API_KEY, using --cpe-mode=auto, or --cpe-mode=offline"))
	}
	return newExitError(ExitEnrich, err)
}
