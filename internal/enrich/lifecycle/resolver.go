package lifecycle

import (
	"context"
	"errors"
	"log/slog"
)

// Resolver routes per-Component lifecycle lookups through the
// configured Sources per Mode policy:
//
//   - online  — only the online Source (EndOfLifeSource).
//   - offline — only the bundled Source.
//   - hybrid  — online first; on ErrNotFound / ErrTransient, fall
//     back to bundled.
//
// `--no-network` overrides Mode to ModeOffline at the CLI layer.
type Resolver struct {
	online  Source
	bundled Source
	mode    Mode
	logger  *slog.Logger
}

// ResolverOptions configures NewResolver.
type ResolverOptions struct {
	// Online is the network-backed Source. Pass nil to skip the
	// online tier (effectively forces offline mode).
	Online Source
	// Bundled is the offline Source. Pass nil to skip the bundled
	// tier (effectively forces online mode).
	Bundled Source
	// Mode selects the tier policy. Empty value defaults to
	// hybrid via Mode.EffectiveMode.
	Mode Mode
	// Logger receives per-resolve diagnostics. Nil → slog.Default.
	Logger *slog.Logger
}

// NewResolver returns a Resolver configured per opts.
func NewResolver(opts ResolverOptions) *Resolver {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{
		online:  opts.Online,
		bundled: opts.Bundled,
		mode:    opts.Mode.EffectiveMode(),
		logger:  logger,
	}
}

// Mode returns the resolver's effective mode.
func (r *Resolver) Mode() Mode { return r.mode }

// Resolve fetches lifecycle data for the (product, version) pair
// per the resolver's mode.
//
// Returns:
//   - (Lifecycle, "endoflife.date" | "bundled" | snapshot:<path>, nil)
//   - (nil, "", ErrNotFound) when no source had data
//   - propagates ErrTransient when ALL queried sources returned it
//     (the caller can choose to log and skip)
func (r *Resolver) Resolve(ctx context.Context, product, version string) (*Lifecycle, string, error) {
	if r == nil || product == "" {
		return nil, "", ErrUnsupported
	}
	transientSeen := false
	if r.mode != ModeOffline {
		lc, src, transient, ok := r.tryOnline(ctx, product, version)
		if ok {
			return lc, src, nil
		}
		if transient {
			transientSeen = true
		}
		if r.mode == ModeOnline {
			return nil, "", finalErr(transientSeen)
		}
	}
	if r.mode != ModeOnline && r.bundled != nil {
		if lc, err := r.bundled.Fetch(ctx, product, version); err == nil && lc != nil {
			return lc, r.bundled.Name(), nil
		}
	}
	return nil, "", finalErr(transientSeen)
}

// tryOnline calls the online source once. Returns:
//   - (lc, name, false, true)  — success
//   - (nil, "", true, false)   — ErrTransient
//   - (nil, "", false, false)  — ErrNotFound or other error / no online source
func (r *Resolver) tryOnline(ctx context.Context, product, version string) (*Lifecycle, string, bool, bool) {
	if r.online == nil {
		return nil, "", false, false
	}
	lc, err := r.online.Fetch(ctx, product, version)
	switch {
	case err == nil && lc != nil:
		return lc, r.online.Name(), false, true
	case errors.Is(err, ErrTransient):
		r.logger.Debug("lifecycle.transient",
			"source", r.online.Name(),
			"product", product, "version", version)
		return nil, "", true, false
	case err != nil && !errors.Is(err, ErrNotFound):
		r.logger.Debug("lifecycle.online.error",
			"source", r.online.Name(),
			"product", product, "version", version,
			"err", err.Error())
	}
	return nil, "", false, false
}

// finalErr picks the right sentinel for the no-result path.
func finalErr(transient bool) error {
	if transient {
		return ErrTransient
	}
	return ErrNotFound
}
