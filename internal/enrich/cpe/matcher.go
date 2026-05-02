package cpe

import "strings"

// Resolver yields zero or more CPE candidates for a parsed PURL.
type Resolver interface {
	// Resolve returns 0 or more Match candidates. An empty slice +
	// nil error means "no match"; non-nil error is reserved for true
	// failures (the bundled JSON did not load, etc.).
	Resolve(p PURL) []Match
}

// BundledResolver resolves PURLs against the embedded bundled
// dictionary. Always emits ConfidenceHigh + SourceBundled.
type BundledResolver struct {
	Dict *BundledDictionary
}

// NewBundledResolver returns a resolver backed by Default().
func NewBundledResolver() *BundledResolver { return &BundledResolver{Dict: Default()} }

// Resolve implements Resolver.
func (b *BundledResolver) Resolve(p PURL) []Match {
	if b.Dict == nil {
		return nil
	}
	if entry, ok := b.Dict.Lookup(p.Type, p.Namespace, p.Name); ok {
		return []Match{{
			CPE:        Build(entry.Vendor, entry.Product, p.Version),
			Source:     SourceBundled,
			Confidence: ConfidenceHigh,
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
func (h *HeuristicResolver) Resolve(p PURL) []Match {
	if p.Name == "" {
		return nil
	}
	vendor, product := guessVendorProduct(p)
	return []Match{{
		CPE:        Build(vendor, product, p.Version),
		Source:     SourceHeuristic,
		Confidence: ConfidenceLow,
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
func (c *Chain) Resolve(p PURL) []Match {
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
