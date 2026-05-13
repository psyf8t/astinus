package cpe

import (
	"context"
	"strings"
)

// Resolver yields zero or more CPE candidates for a parsed PURL.
type Resolver interface {
	// Resolve returns 0 or more Candidate proposals. An empty slice
	// + nil error means "no match"; non-nil error is reserved for
	// true failures (the bundled JSON did not load, etc.).
	Resolve(p PURL) []Candidate
}

// ContextResolver is the opt-in context-aware variant of Resolver.
// Resolvers that implement it receive the parent context the
// enricher was invoked with, so wall-time bounds (total cap, per-
// source budget) and cancellation propagate end-to-end. S6 Task 0.
//
// The enricher type-asserts on this interface; resolvers that don't
// implement it fall back to the context-less Resolve path.
type ContextResolver interface {
	Resolver

	// ResolveCtx mirrors Resolve but accepts the enricher's ctx.
	// Returning a non-nil error puts the enricher in fail-fast mode
	// — used by the multi-source orchestrator in --cpe-mode hybrid
	// to surface ErrSourceUnavailable when a per-call deadline
	// elapses (ADR-0051 + ADR-0057).
	ResolveCtx(ctx context.Context, p PURL) ([]Candidate, error)
}

// versionMatchKind classifies how the PURL version was honoured by
// the resolver. Used to populate Candidate.MatchDetails.VersionMatch
// so operators (and `--include-rejected-cpe` debug output) can see
// which proposals are exact-version vs wildcard.
func versionMatchKind(version string) string {
	if version == "" {
		return "wildcard"
	}
	return "exact"
}

// BundledResolver resolves PURLs against the embedded bundled
// dictionary. Always emits ConfidenceHigh + SourceBundled.
type BundledResolver struct {
	Dict *BundledDictionary
}

// NewBundledResolver returns a resolver backed by Default().
func NewBundledResolver() *BundledResolver { return &BundledResolver{Dict: Default()} }

// Resolve implements Resolver.
func (b *BundledResolver) Resolve(p PURL) []Candidate {
	if b.Dict == nil {
		return nil
	}
	if entry, ok := b.Dict.Lookup(p.Type, p.Namespace, p.Name); ok {
		return []Candidate{{
			CPE:        Build(entry.Vendor, entry.Product, p.Version),
			Source:     SourceBundled,
			Confidence: ConfidenceHigh,
			Evidence:   "bundled purl_to_cpe.json hit",
			MatchDetails: MatchDetails{
				VendorMatch:  "known-mapping",
				ProductMatch: "known-mapping",
				VersionMatch: versionMatchKind(p.Version),
				SearchMethod: "dictionary-lookup",
			},
		}}
	}
	return nil
}

// HeuristicResolver constructs a CPE 2.3 from PURL shape when no
// bundled entry exists. Always emits ConfidenceLow + SourceHeuristic.
//
// The vendor/product mapping per PURL type tries to mirror common
// NVD conventions:
//
//	npm/<name>            → vendor=name,        product=name
//	pypi/<name>           → vendor=name_project, product=name
//	gem/<name>            → vendor=name,        product=name
//	cargo/<name>          → vendor=name,        product=name
//	maven/<ns>/<name>     → vendor=last(ns),    product=name
//	golang/<host>/<u>/<p> → vendor=u,           product=p
//	nuget/<name>          → vendor=name,        product=name
//	deb/<ns>/<name>       → vendor=name,        product=name
//	rpm/<ns>/<name>       → vendor=name,        product=name
//	apk/<ns>/<name>       → vendor=name,        product=name
//	other                 → vendor=name,        product=name
type HeuristicResolver struct{}

// NewHeuristicResolver returns the canonical heuristic resolver.
func NewHeuristicResolver() *HeuristicResolver { return &HeuristicResolver{} }

// Resolve implements Resolver.
//
// Confidence is ConfidenceMedium (0.70): heuristic guesses of the
// shape vendor=name=name are correct for the long tail of npm/cargo
// /gem packages where the vendor and product collapse to the same
// token. They sit at the PrimaryMin floor so they remain primary
// when no curated source has anything better, but any bundled or
// dictionary hit (ConfidenceHigh = 0.95) still wins. ADR-0029.
func (h *HeuristicResolver) Resolve(p PURL) []Candidate {
	if p.Name == "" {
		return nil
	}
	vendor, product := guessVendorProduct(p)
	return []Candidate{{
		CPE:        Build(vendor, product, p.Version),
		Source:     SourceHeuristic,
		Confidence: ConfidenceMedium,
		Evidence:   "PURL-shape guess",
		MatchDetails: MatchDetails{
			VendorMatch:  "fuzzy",
			ProductMatch: "fuzzy",
			VersionMatch: versionMatchKind(p.Version),
			SearchMethod: "purl-direct",
		},
	}}
}

// guessVendorProduct picks a (vendor, product) pair based on PURL type.
func guessVendorProduct(p PURL) (string, string) {
	name := p.Name
	switch p.Type {
	case "pypi":
		return name + "_project", name
	case "maven":
		if p.Namespace != "" {
			parts := strings.Split(p.Namespace, ".")
			return parts[len(parts)-1], name
		}
		return name, name
	case "golang":
		// PURL golang namespace usually looks like
		// "github.com/<user>"; vendor = <user>, product = <name>.
		if p.Namespace != "" {
			segs := strings.Split(p.Namespace, "/")
			return segs[len(segs)-1], name
		}
		return name, name
	default:
		return name, name
	}
}

// Chain queries multiple resolvers in order and concatenates their
// non-empty results. The CHAIN does not de-duplicate — duplicate CPEs
// across resolvers are surfaced so the caller knows multiple sources
// agreed.
type Chain struct {
	resolvers []Resolver
}

// NewChain returns a Chain over the given resolvers.
func NewChain(resolvers ...Resolver) *Chain {
	return &Chain{resolvers: append([]Resolver(nil), resolvers...)}
}

// Resolve implements Resolver.
//
// Strategy: prefer high-confidence matches. If any resolver in the
// chain returns at least one match, return ALL matches from THAT
// resolver and stop — we don't mix high and low confidence in one
// answer. This way the bundled mapping always wins when it has an
// entry; the heuristic only kicks in when nobody else does.
func (c *Chain) Resolve(p PURL) []Candidate {
	for _, r := range c.resolvers {
		if out := r.Resolve(p); len(out) > 0 {
			return out
		}
	}
	return nil
}

// DefaultChain returns the canonical bundled→heuristic chain.
func DefaultChain() *Chain {
	return NewChain(NewBundledResolver(), NewHeuristicResolver())
}
