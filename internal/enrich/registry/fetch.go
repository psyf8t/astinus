package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
)

// MirrorChain orders the per-ecosystem mirror list per the
// replace/fallback semantics. Replace-mode mirrors come FIRST and
// the upstream is dropped entirely; fallback-mode mirrors come
// first then the upstream is appended.
//
// Empty mirror slate → just the upstream. Used by every Source's
// fetch loop so the policy lives in one place.
type MirrorChain struct {
	Mirrors  []config.MirrorEntry
	Upstream string
}

// Endpoint is one (URL, mirror) pair the source iterates through.
// Mirror is the empty MirrorEntry when Endpoint represents the
// upstream public registry.
type Endpoint struct {
	URL    string
	Mirror config.MirrorEntry
	Source string // human label for logs ("upstream" / mirror host)
}

// Endpoints returns the ordered list of URLs to try for a given
// path suffix. Replace-mode mirrors come first and exclude
// upstream. Fallback-mode mirrors come next; upstream is appended
// last unless a replace-mode mirror was configured.
func (c MirrorChain) Endpoints(pathSuffix string) []Endpoint {
	out := make([]Endpoint, 0, len(c.Mirrors)+1)
	hasReplace := false
	for _, m := range c.Mirrors {
		if m.Mode.EffectiveMode() == config.MirrorModeReplace {
			out = append(out, Endpoint{
				URL:    joinURL(m.URL, pathSuffix),
				Mirror: m,
				Source: HostOf(m.URL),
			})
			hasReplace = true
		}
	}
	for _, m := range c.Mirrors {
		if m.Mode.EffectiveMode() == config.MirrorModeFallback {
			out = append(out, Endpoint{
				URL:    joinURL(m.URL, pathSuffix),
				Mirror: m,
				Source: HostOf(m.URL),
			})
		}
	}
	if !hasReplace && c.Upstream != "" {
		out = append(out, Endpoint{
			URL:    joinURL(c.Upstream, pathSuffix),
			Source: "upstream",
		})
	}
	return out
}

// joinURL concatenates base + suffix without producing double slashes.
func joinURL(base, suffix string) string {
	base = strings.TrimRight(base, "/")
	if suffix == "" {
		return base
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return base + suffix
}

// FetchJSON does GET on each endpoint in chain, applies the mirror's
// auth + headers, and decodes the first 2xx body into out via a
// caller-supplied parser. Returns ErrNotFound when every endpoint
// returned 404; ErrTransient when at least one endpoint returned
// 5xx and none succeeded; the wrapped real error otherwise.
//
// The Resolver layer logs `registry.request` per endpoint via
// `log` (passed in from the Source). When log is nil, slog.Default
// is used.
func FetchJSON(ctx context.Context, client *http.Client, chain MirrorChain,
	pathSuffix, sourceName string, parser func(io.Reader) error,
	log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	endpoints := chain.Endpoints(pathSuffix)
	if len(endpoints) == 0 {
		return ErrNotFound
	}

	var (
		notFoundCount int
		transientSeen bool
		lastErr       error
	)
	for _, ep := range endpoints {
		mirrorClient, err := buildMirrorClient(client, &ep.Mirror)
		if err != nil {
			lastErr = err
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/json")
		applyHeaders(req, ep.Mirror.Headers)
		if err := applyAuth(req, ep.Mirror.Auth); err != nil {
			lastErr = err
			continue
		}
		viaProxy := proxyInUse(req)
		isMirror := ep.Mirror.URL != ""
		log.Debug("registry.request",
			"source", sourceName,
			"url", ep.URL,
			"via_mirror", isMirror,
			"via_proxy", viaProxy,
			"mode", string(ep.Mirror.Mode.EffectiveMode()))

		resp, err := mirrorClient.Do(req)
		if err != nil {
			log.Warn("registry.fetch.error",
				"source", sourceName, "url", ep.URL, "err", err.Error())
			lastErr = err
			continue
		}
		err = handleResponse(resp, sourceName, parser)
		_ = resp.Body.Close()
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrNotFound):
			notFoundCount++
			continue
		case errors.Is(err, ErrTransient):
			transientSeen = true
			continue
		default:
			lastErr = err
		}
	}
	switch {
	case lastErr != nil:
		return lastErr
	case transientSeen:
		return ErrTransient
	case notFoundCount > 0:
		return ErrNotFound
	}
	return ErrNotFound
}

// handleResponse maps the HTTP status code to the registry sentinel
// error vocabulary and invokes parser on a 2xx body. The parser
// reads from the body directly so callers can stream large
// responses (Maven pom.xml, NuGet catalog pages) without
// io.ReadAll'ing them first.
func handleResponse(resp *http.Response, sourceName string, parser func(io.Reader) error) error {
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("registry %s: auth failed (status %d)", sourceName, resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrTransient
	case resp.StatusCode >= 500:
		return ErrTransient
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("registry %s: unexpected status %d", sourceName, resp.StatusCode)
	}
	return parser(resp.Body)
}

// proxyInUse reports whether the env-driven proxy resolver picks
// a proxy URL for req. Cheap probe — does NOT actually open a
// connection. Used only for log fields.
func proxyInUse(req *http.Request) bool {
	u, err := http.ProxyFromEnvironment(req)
	return err == nil && u != nil
}

// Per-mirror rate limiting (config.MirrorRateLimitConfig) is
// declared in the schema but not yet enforced — deferred to the
// follow-up alongside the cargo / gem / nuget / deb / apk source
// implementations. ADR-0033 §6.
