package registry

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// Resolver routes a parsed PURL to the right Source(s), enforces
// the cache layer, and serializes per-PURL fetches so the same
// component asked for twice in a run only hits the network once.
//
// Sources are tried in registration order; the first non-empty
// metadata wins. ErrNotFound / ErrTransient cause fall-through to
// the next Source.
type Resolver struct {
	sources   []Source
	cache     Cache
	networkOK bool
	logger    *slog.Logger
}

// ResolverOptions configures NewResolver.
type ResolverOptions struct {
	// Sources is the ordered registry source slate.
	Sources []Source
	// Cache fronts the source chain. NoopCache disables.
	Cache Cache
	// NetworkOK gates Sources whose RequiresNetwork is true.
	// Set to false under `--no-network`.
	NetworkOK bool
	// Logger receives per-resolve diagnostics. Nil → slog.Default.
	Logger *slog.Logger
}

// NewResolver returns a Resolver configured per opts. Defaults:
// MemoryCache, NetworkOK=true.
func NewResolver(opts ResolverOptions) *Resolver {
	cache := opts.Cache
	if cache == nil {
		cache = NewMemoryCache()
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{
		sources:   append([]Source(nil), opts.Sources...),
		cache:     cache,
		networkOK: opts.NetworkOK,
		logger:    logger,
	}
}

// Sources returns a defensive copy of the registered Sources. Used
// by tests + diagnostic CLI surfaces.
func (r *Resolver) Sources() []Source {
	out := make([]Source, len(r.sources))
	copy(out, r.sources)
	return out
}

// Resolve finds metadata for the parsed PURL by walking the source
// chain. Cache is consulted first; on miss every Source whose
// Supports(purl.Type) returns true is tried in order until one
// returns non-empty metadata. The result (including ErrNotFound)
// is cached so a re-run on the same SBOM is free.
func (r *Resolver) Resolve(ctx context.Context, purl cpe.PURL) (*Metadata, error) {
	key := canonicalPURLKey(purl)
	if cached, ok := r.cache.Get(key); ok {
		if cached == nil {
			return nil, ErrNotFound
		}
		return cached, nil
	}

	tried := 0
	for _, src := range r.sources {
		if !src.Supports(purl.Type) {
			continue
		}
		if src.RequiresNetwork() && !r.networkOK {
			continue
		}
		tried++
		meta, err := src.Fetch(ctx, purl)
		switch {
		case err == nil && meta != nil && !meta.IsEmpty():
			r.cache.Set(key, meta)
			return meta, nil
		case errors.Is(err, ErrNotFound):
			continue
		case errors.Is(err, ErrTransient):
			r.logger.Debug("registry.transient",
				"source", src.Name(), "purl", key, "err", errSafe(err))
			continue
		case errors.Is(err, ErrUnsupported):
			continue
		case err != nil:
			r.logger.Warn("registry.error",
				"source", src.Name(), "purl", key, "err", err.Error())
			continue
		}
	}
	// Cache the negative result so we don't re-walk on the next call.
	r.cache.Set(key, nil)
	if tried == 0 {
		return nil, ErrUnsupported
	}
	return nil, ErrNotFound
}

// errSafe returns a non-nil error's message or empty string for nil.
// Defensive helper for slog payloads.
func errSafe(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// canonicalPURLKey returns the stable cache key for a PURL. Type +
// namespace + name + version are the keying axes; qualifiers and
// subpath are dropped since they don't affect the registry response.
func canonicalPURLKey(p cpe.PURL) string {
	out := strings.ToLower(p.Type) + "|" + strings.ToLower(p.Namespace) +
		"|" + strings.ToLower(p.Name) + "|" + p.Version
	return out
}

// MirrorsByEcosystem indexes a MirrorsConfig into per-ecosystem
// slices the Source constructors consume. The ordering within an
// ecosystem is preserved from config.
func MirrorsByEcosystem(cfg *config.MirrorsConfig) map[string][]config.MirrorEntry {
	out := map[string][]config.MirrorEntry{}
	if cfg == nil {
		return out
	}
	for _, m := range cfg.Mirrors {
		key := strings.ToLower(m.Ecosystem)
		out[key] = append(out[key], m)
	}
	return out
}
