package sources

import (
	"context"
	"net/http"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// This file holds stub Source implementations for ecosystems and
// aggregators whose full registry adapter is deferred to a Sprint 3
// follow-up (ADR-0033 §6 deferred sources). Each stub:
//
//   - Reports its ecosystem via Supports() so the Resolver routes to
//     it correctly.
//   - Has Fetch() return ErrNotFound so the Resolver falls through
//     to the next source (typically an aggregator or no-op).
//   - Carries the mirrors slice + http.Client + logger so wiring
//     the full implementation later is a single-file change.
//
// The stubs are NOT no-ops in pipeline metrics — `registry.complete`
// log line counts ErrNotFound responses per source, so operators
// see "cargo source returned 0 hits" in the aggregate.

// stubSource is the shared shape for every deferred Source.
type stubSource struct {
	name     string
	purlType string
	mirrors  []config.MirrorEntry
	client   *http.Client
}

func (s *stubSource) Name() string           { return s.name }
func (s *stubSource) Supports(t string) bool { return strings.EqualFold(t, s.purlType) }
func (s *stubSource) RequiresNetwork() bool  { return true }
func (s *stubSource) Fetch(_ context.Context, _ cpe.PURL) (*registry.Metadata, error) {
	return nil, registry.ErrNotFound
}

// NewCargo returns a stub Source for crates.io. Full implementation
// deferred — crates.io publishes per-version metadata at
// `/api/v1/crates/<name>/<version>` (license, homepage, repository).
func NewCargo(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{name: "cargo", purlType: "cargo", mirrors: mirrors, client: client}
}

// NewRubyGems returns a stub Source for rubygems.org. Full
// implementation deferred — rubygems.org publishes per-version JSON
// at `/api/v2/rubygems/<name>/versions/<version>.json`.
func NewRubyGems(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{name: "rubygems", purlType: "gem", mirrors: mirrors, client: client}
}

// NewNuGet returns a stub Source for nuget.org. Full implementation
// deferred — nuget.org Catalog API at
// `/v3/registration5-semver1/<id>/<version>.json`.
func NewNuGet(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{name: "nuget", purlType: "nuget", mirrors: mirrors, client: client}
}

// NewDebian returns a stub Source for sources.debian.org. Full
// implementation deferred — sources.debian.org JSON API at
// `/api/info/package/<name>/<version>/`.
func NewDebian(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{name: "debian", purlType: "deb", mirrors: mirrors, client: client}
}

// NewAlpine returns a stub Source for pkgs.alpinelinux.org. Full
// implementation deferred — Alpine doesn't publish a stable JSON
// API; aports git scrape required.
func NewAlpine(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{name: "alpine", purlType: "apk", mirrors: mirrors, client: client}
}

// NewRepology returns a stub Source for the Repology aggregator.
// Full implementation deferred — Repology project API at
// `/api/v1/project/<projectname>` returns one entry per distro.
// Used as a fallback when ecosystem-native sources don't carry
// the metadata.
func NewRepology(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{
		name: "repology", purlType: "repology", mirrors: mirrors, client: client,
	}
}

// NewEcosystems returns a stub Source for ecosyste.ms aggregator.
// Full implementation deferred — ecosyste.ms packages API.
func NewEcosystems(mirrors []config.MirrorEntry, client *http.Client) registry.Source {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &stubSource{
		name: "ecosystems", purlType: "ecosyste-ms", mirrors: mirrors, client: client,
	}
}
