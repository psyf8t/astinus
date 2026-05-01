package cli

import (
	"context"
	"errors"
	"log/slog"
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
