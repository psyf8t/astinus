package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable registry`, declared in
// other enrichers' Dependencies()).
const Name = "registry"

// Property keys this enricher writes onto Components. Centralised
// so output / SARIF / compliance consumers can reference them by
// constant.
const (
	PropertyRegistrySource     = "astinus:registry:source"
	PropertyRegistryFetchedAt  = "astinus:registry:fetched-at"
	PropertyRegistryHomepage   = "astinus:registry:homepage"
	PropertyRegistryRepository = "astinus:registry:repository"
	PropertyRegistryBugs       = "astinus:registry:bug-tracker"
	PropertyRegistryDocs       = "astinus:registry:documentation"
)

// Enricher applies metadata from package registries to every
// Component with a PURL the resolver knows how to handle. Missing-
// only fill — never overrides upstream data.
//
// See package doc for the corporate-environment story (mirrors,
// auth, mTLS, proxy).
type Enricher struct {
	resolver *Resolver
	logger   *slog.Logger
}

// New returns an Enricher backed by resolver. Pass nil resolver to
// disable (the no-op path used by `--no-registry`).
func New(resolver *Resolver) *Enricher {
	return &Enricher{
		resolver: resolver,
		logger:   slog.Default(),
	}
}

// WithLogger overrides the slog destination.
func (e *Enricher) WithLogger(l *slog.Logger) *Enricher {
	if l != nil {
		e.logger = l
	}
	return e
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. We need the discovery
// stages (untracked + extractor) to populate the full Component
// slate before we fetch metadata; we run before cpe and dedup so
// the registry-derived signals participate downstream.
func (*Enricher) Dependencies() []string { return []string{"untracked", "extractor"} }

// stats records what the enricher did during one Enrich call.
type stats struct {
	examined       int
	enriched       int
	noPURL         int
	purlError      int
	notFound       int
	unsupported    int
	transient      int
	licensesFilled int
	supplierFilled int
	homepageFilled int
	repoFilled     int
	hashesFilled   int
}

// Enrich implements enrich.Enricher.
//
// bundle is unused — the registry enricher only consumes the SBOM.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("registry: nil sbom")
	}
	if e.resolver == nil {
		// Disabled (--no-registry).
		return nil
	}
	s := stats{}
	walkComponents(sbom.Components, func(c *model.Component) {
		e.processComponent(ctx, c, &s)
	})

	e.logger.Info("registry.complete",
		"components_examined", s.examined,
		"enriched", s.enriched,
		"no_purl", s.noPURL,
		"purl_error", s.purlError,
		"not_found", s.notFound,
		"unsupported", s.unsupported,
		"transient", s.transient,
		"licenses_filled", s.licensesFilled,
		"supplier_filled", s.supplierFilled,
		"homepage_filled", s.homepageFilled,
		"repository_filled", s.repoFilled,
		"hashes_filled", s.hashesFilled)
	return nil
}

// processComponent handles one Component: parse PURL, resolve via
// the source chain, project metadata, update stats. Extracted from
// Enrich to keep that function under the gocognit cap.
func (e *Enricher) processComponent(ctx context.Context, c *model.Component, s *stats) {
	s.examined++
	if c.PURL == "" {
		s.noPURL++
		return
	}
	purl, err := cpe.ParsePURL(c.PURL)
	if err != nil {
		s.purlError++
		return
	}
	meta, err := e.resolver.Resolve(ctx, purl)
	switch {
	case err == nil && meta != nil:
		e.applyAndCount(c, meta, s)
	case errors.Is(err, ErrNotFound):
		s.notFound++
	case errors.Is(err, ErrUnsupported):
		s.unsupported++
	case errors.Is(err, ErrTransient):
		s.transient++
	}
}

// applyAndCount projects meta onto c, then bumps the per-field
// counters when the projection actually changed something.
func (e *Enricher) applyAndCount(c *model.Component, meta *Metadata, s *stats) {
	before := componentFingerprint(c)
	e.applyMetadata(c, meta)
	if componentFingerprint(c) == before {
		return
	}
	s.enriched++
	if len(meta.Licenses) > 0 {
		s.licensesFilled++
	}
	if meta.Supplier.Name != "" {
		s.supplierFilled++
	}
	if meta.Homepage != "" {
		s.homepageFilled++
	}
	if meta.Repository != "" {
		s.repoFilled++
	}
	if len(meta.Hashes) > 0 {
		s.hashesFilled++
	}
}

// applyMetadata projects meta onto c — fill-only, never overrides
// upstream values. Stamps `astinus:registry:*` provenance so
// downstream consumers can tell which fields the registry filled.
func (e *Enricher) applyMetadata(c *model.Component, meta *Metadata) {
	if c.Description == "" && meta.Description != "" {
		c.Description = meta.Description
	}
	if c.Author == "" && meta.Author != "" {
		c.Author = meta.Author
	}
	if c.Supplier == "" && meta.Supplier.Name != "" {
		// Canonical model flattens supplier to a string; we render
		// "Name <email>" when both available, just Name otherwise.
		c.Supplier = formatSupplier(meta.Supplier)
	}
	mergeLicenses(c, meta.Licenses)
	mergeHashes(c, meta.Hashes)

	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties[PropertyRegistrySource] = sourceForType(c.PURL)
	c.Properties[PropertyRegistryFetchedAt] = time.Now().UTC().Format(time.RFC3339)
	if meta.Homepage != "" {
		setIfAbsent(c.Properties, PropertyRegistryHomepage, meta.Homepage)
	}
	if meta.Repository != "" {
		setIfAbsent(c.Properties, PropertyRegistryRepository, meta.Repository)
	}
	if meta.BugTracker != "" {
		setIfAbsent(c.Properties, PropertyRegistryBugs, meta.BugTracker)
	}
	if meta.Documentation != "" {
		setIfAbsent(c.Properties, PropertyRegistryDocs, meta.Documentation)
	}
}

// mergeLicenses appends meta licenses that aren't already present
// on c (deduped by SPDXID + Name + URL). Doesn't drop existing
// entries.
func mergeLicenses(c *model.Component, in []License) {
	for _, l := range in {
		if l.SPDXID == "" && l.Name == "" {
			continue
		}
		if licensePresent(c.Licenses, l) {
			continue
		}
		c.Licenses = append(c.Licenses, model.License{
			SPDXID: l.SPDXID,
			Name:   l.Name,
			URL:    l.URL,
		})
	}
}

// licensePresent reports whether l is already in existing under
// any of its identifying fields.
func licensePresent(existing []model.License, l License) bool {
	for _, e := range existing {
		if l.SPDXID != "" && e.SPDXID == l.SPDXID {
			return true
		}
		if l.Name != "" && e.Name == l.Name {
			return true
		}
		if l.SPDXID != "" && e.Expression == l.SPDXID {
			return true
		}
	}
	return false
}

// mergeHashes appends meta hashes that aren't already present on
// c. Algorithm normalised via model.NormalizeHashAlgorithm so the
// dedup is canonical-form.
func mergeHashes(c *model.Component, in map[string]string) {
	for alg, hex := range in {
		alg = model.NormalizeHashAlgorithm(alg)
		if alg == "" || hex == "" {
			continue
		}
		exists := false
		for _, h := range c.Hashes {
			if h.Algorithm == alg {
				exists = true
				break
			}
		}
		if !exists {
			c.Hashes = append(c.Hashes, model.Hash{Algorithm: alg, Value: hex})
		}
	}
}

// formatSupplier renders a Supplier as the flattened string the
// canonical model carries. "Name" or "Name <email>".
func formatSupplier(s Supplier) string {
	if s.Email == "" {
		return s.Name
	}
	return s.Name + " <" + s.Email + ">"
}

// sourceForType returns the short source label for a PURL based on
// its type. Used for the `astinus:registry:source` stamp without
// touching the Resolver internals.
func sourceForType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	idx := strings.IndexAny(rest, "/@?#")
	if idx < 0 {
		return strings.ToLower(rest)
	}
	return strings.ToLower(rest[:idx])
}

// componentFingerprint captures the fields applyMetadata touches
// so the enricher can tell whether anything actually changed
// (used for the `enriched` counter).
func componentFingerprint(c *model.Component) string {
	var b strings.Builder
	b.WriteString(c.Description)
	b.WriteByte('|')
	b.WriteString(c.Author)
	b.WriteByte('|')
	b.WriteString(c.Supplier)
	b.WriteByte('|')
	for _, l := range c.Licenses {
		b.WriteString(l.SPDXID)
		b.WriteByte(':')
		b.WriteString(l.Name)
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, h := range c.Hashes {
		b.WriteString(h.Algorithm)
		b.WriteByte(':')
		b.WriteString(h.Value)
		b.WriteByte(',')
	}
	return b.String()
}

// setIfAbsent writes (k, v) into m iff k isn't already present.
// Used for provenance properties so a re-enrichment doesn't
// overwrite an operator's manual additions.
func setIfAbsent(m map[string]string, k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// walkComponents recurses depth-first into SubComponents (S3 Task 1
// lifted most embedded deps to top-level, but we walk subs anyway
// for backward compatibility with input SBOMs that nest).
func walkComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkComponents(comps[i].SubComponents, fn)
		}
	}
}
