package cpe

import (
	"context"
	"fmt"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable cpe`).
const Name = "cpe"

// Enricher is the cpe enrich.Enricher implementation.
//
// Behavior per Component:
//
//   - If the component has a PURL but no CPE → run the resolver
//     chain, append any matches to Component.CPEs, record provenance
//     in Properties.
//   - If the component already has CPEs → validate each. Drop
//     malformed entries (logged via the property bag) and stamp
//     `astinus:cpe:validated = true` on survivors so a downstream
//     consumer can tell we've checked them.
//   - If the component has no PURL → no-op.
//
// Idempotent: re-running over the same SBOM yields the same answer.
// Recurses into SubComponents so untracked Go-binary modules also
// benefit.
type Enricher struct {
	chain Resolver
}

// New returns an Enricher with DefaultChain().
func New() *Enricher { return &Enricher{chain: DefaultChain()} }

// NewWithResolver returns an Enricher with the supplied resolver.
// Useful for tests that want to drive a deterministic chain.
func NewWithResolver(r Resolver) *Enricher { return &Enricher{chain: r} }

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Enrich implements enrich.Enricher.
//
// bundle is required for signature compatibility with the pipeline
// but the cpe enricher does not consume the image — its inputs are
// purely the SBOM components.
func (e *Enricher) Enrich(_ context.Context, sbom *model.SBOM, bundle *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("cpe: nil sbom")
	}
	_ = bundle // unused; kept for the Enricher signature
	walk(sbom.Components, func(c *model.Component) {
		e.enrichOne(c)
	})
	return nil
}

// enrichOne mutates c in place per the contract above.
func (e *Enricher) enrichOne(c *model.Component) {
	if len(c.CPEs) > 0 {
		validateExisting(c)
		return
	}
	if c.PURL == "" {
		return
	}

	purl, err := ParsePURL(c.PURL)
	if err != nil {
		// Malformed PURL: leave a breadcrumb so the operator sees
		// why no CPE was added.
		setProp(c, "astinus:cpe:purl-error", err.Error())
		return
	}

	matches := e.chain.Resolve(purl)
	if len(matches) == 0 {
		setProp(c, "astinus:cpe:lookup", "no-match")
		return
	}

	// First-source-wins inside Chain (already enforced); record the
	// source and confidence of the WINNING source.
	c.CPEs = appendUnique(c.CPEs, matches)
	setProp(c, "astinus:cpe:source", string(matches[0].Source))
	setProp(c, "astinus:cpe:confidence", string(matches[0].Confidence))
}

// validateExisting drops malformed CPE strings from c.CPEs and
// stamps a property recording how many survived. Deliberately does
// NOT remove a single-CPE entry that is malformed (that would lose
// the data); instead it stamps `:invalid = true` so a downstream
// consumer can decide.
func validateExisting(c *model.Component) {
	good := make([]string, 0, len(c.CPEs))
	for _, s := range c.CPEs {
		if IsValidCPE(s) {
			good = append(good, s)
		}
	}
	if len(good) == len(c.CPEs) {
		setProp(c, "astinus:cpe:validated", "true")
		return
	}
	if len(good) == 0 {
		// Keep at least one so the data is not silently lost.
		setProp(c, "astinus:cpe:validated", "false")
		setProp(c, "astinus:cpe:invalid", "true")
		return
	}
	c.CPEs = good
	setProp(c, "astinus:cpe:validated", "partial")
}

// appendUnique appends every match's CPE to existing iff not already
// present. Matches preserve order; existing CPEs are left in place
// at their original position.
func appendUnique(existing []string, matches []Match) []string {
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		have[e] = true
	}
	out := existing
	for _, m := range matches {
		if !have[m.CPE] {
			out = append(out, m.CPE)
			have[m.CPE] = true
		}
	}
	return out
}

// walk applies fn to every component (recursively into SubComponents).
func walk(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walk(comps[i].SubComponents, fn)
		}
	}
}

// setProp inserts (key, value) into c.Properties, creating the map
// when needed.
func setProp(c *model.Component, key, value string) {
	if c.Properties == nil {
		c.Properties = map[string]string{}
	}
	c.Properties[key] = value
}
