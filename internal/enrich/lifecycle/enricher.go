package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable lifecycle`, declared
// in other enrichers' Dependencies()).
const Name = "lifecycle"

// Property keys this enricher writes onto Components. Centralised
// so output / SARIF / compliance consumers reference them by
// constant.
const (
	PropertyLifecycleProduct          = "astinus:lifecycle:product"
	PropertyLifecycleCycle            = "astinus:lifecycle:cycle"
	PropertyLifecycleReleaseDate      = "astinus:lifecycle:release-date"
	PropertyLifecycleActiveSupportEnd = "astinus:lifecycle:active-support-end"
	PropertyLifecycleEOL              = "astinus:lifecycle:eol"
	PropertyLifecycleLTS              = "astinus:lifecycle:lts"
	PropertyLifecycleLatest           = "astinus:lifecycle:latest"
	PropertyLifecycleStatus           = "astinus:lifecycle:status"
	PropertyLifecycleDaysUntilEOL     = "astinus:lifecycle:days-until-eol"
	PropertyLifecycleSource           = "astinus:lifecycle:source"
	PropertyLifecycleFetchedAt        = "astinus:lifecycle:fetched-at"
)

// Enricher applies endoflife.date lifecycle data to OS / runtime
// Components. See package doc.
type Enricher struct {
	resolver *Resolver
	logger   *slog.Logger
	now      func() time.Time
}

// New returns an Enricher backed by resolver. nil resolver disables
// the enricher (no-op Enrich) — used by `--no-lifecycle`.
func New(resolver *Resolver) *Enricher {
	return &Enricher{
		resolver: resolver,
		logger:   slog.Default(),
		now:      time.Now,
	}
}

// WithLogger overrides the slog destination.
func (e *Enricher) WithLogger(l *slog.Logger) *Enricher {
	if l != nil {
		e.logger = l
	}
	return e
}

// WithClock overrides the now() function. Test-only — production
// uses time.Now.
func (e *Enricher) WithClock(now func() time.Time) *Enricher {
	if now != nil {
		e.now = now
	}
	return e
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. We need the discovery
// stages to populate the Component slate; we don't depend on cpe
// (lifecycle data and CPE are independent axes).
func (*Enricher) Dependencies() []string { return []string{"untracked", "extractor"} }

// stats records what the enricher did during one Enrich call.
// Surfaced via the `lifecycle.complete` info log.
type stats struct {
	examined    int
	enriched    int
	unmapped    int
	notFound    int
	transient   int
	eolHits     int
	maintenance int
	active      int
	unknown     int
}

// Enrich implements enrich.Enricher.
//
// bundle is unused — the lifecycle enricher only consumes the SBOM.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("lifecycle: nil sbom")
	}
	if e.resolver == nil {
		return nil // disabled (--no-lifecycle)
	}
	now := e.now().UTC()
	s := stats{}
	walkComponents(sbom.Components, func(c *model.Component) {
		e.processComponent(ctx, c, &s, now)
	})
	e.logger.Info("lifecycle.complete",
		"components_examined", s.examined,
		"enriched", s.enriched,
		"unmapped", s.unmapped,
		"not_found", s.notFound,
		"transient", s.transient,
		"eol_hits", s.eolHits,
		"maintenance", s.maintenance,
		"active", s.active,
		"unknown_status", s.unknown)
	return nil
}

// processComponent handles one Component: map to product, resolve,
// project Lifecycle properties, classify status, bump counters.
// Extracted from Enrich to keep the entry point under the gocognit
// cap.
func (e *Enricher) processComponent(ctx context.Context, c *model.Component, s *stats, now time.Time) {
	s.examined++
	product, version, ok := MapToProduct(c)
	if !ok {
		s.unmapped++
		return
	}
	lc, src, err := e.resolver.Resolve(ctx, product, version)
	switch {
	case err == nil && lc != nil:
		status := ClassifyStatus(lc, now)
		e.applyLifecycle(c, lc, product, src, status, now)
		s.enriched++
		bumpStatus(s, status)
		if status == StatusEOL {
			e.logger.Warn("lifecycle.eol",
				"component", c.Name,
				"version", c.Version,
				"product", product,
				"cycle", lc.Cycle,
				"eol", formatDate(lc.EOL),
				"source", src)
		}
	case errors.Is(err, ErrNotFound):
		s.notFound++
	case errors.Is(err, ErrTransient):
		s.transient++
	}
}

// bumpStatus increments the per-status counter so the summary log
// surfaces how the SBOM splits across active / maintenance / EOL.
func bumpStatus(s *stats, status Status) {
	switch status {
	case StatusEOL:
		s.eolHits++
	case StatusMaintenance:
		s.maintenance++
	case StatusActive:
		s.active++
	default:
		s.unknown++
	}
}

// applyLifecycle stamps the per-Component properties.
func (e *Enricher) applyLifecycle(c *model.Component, lc *Lifecycle,
	product, source string, status Status, now time.Time) {
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties[PropertyLifecycleProduct] = product
	c.Properties[PropertyLifecycleCycle] = lc.Cycle
	if !lc.ReleaseDate.IsZero() {
		c.Properties[PropertyLifecycleReleaseDate] = formatDate(lc.ReleaseDate)
	}
	if !lc.ActiveSupportEnd.IsZero() {
		c.Properties[PropertyLifecycleActiveSupportEnd] = formatDate(lc.ActiveSupportEnd)
	} else if lc.SupportBoolean != "" {
		c.Properties[PropertyLifecycleActiveSupportEnd] = lc.SupportBoolean
	}
	switch {
	case !lc.EOL.IsZero():
		c.Properties[PropertyLifecycleEOL] = formatDate(lc.EOL)
	case lc.EOLBoolean != "":
		c.Properties[PropertyLifecycleEOL] = lc.EOLBoolean
	}
	c.Properties[PropertyLifecycleLTS] = strconv.FormatBool(lc.LTS)
	if lc.Latest != "" {
		c.Properties[PropertyLifecycleLatest] = lc.Latest
	}
	c.Properties[PropertyLifecycleStatus] = string(status)
	if days, ok := DaysUntilEOL(lc, now); ok {
		c.Properties[PropertyLifecycleDaysUntilEOL] = strconv.Itoa(days)
	}
	c.Properties[PropertyLifecycleSource] = source
	c.Properties[PropertyLifecycleFetchedAt] = now.Format(time.RFC3339)
}

// formatDate renders a time.Time as the canonical ISO date
// `2006-01-02` we use across the project.
func formatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// walkComponents recurses depth-first into SubComponents (for
// pre-S3-Task-1 SBOMs that nest dependencies).
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}
