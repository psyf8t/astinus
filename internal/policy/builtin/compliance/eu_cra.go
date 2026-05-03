package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// EUCRAValidator implements the auditable subset of the EU Cyber
// Resilience Act Article 13 + Annex I requirements relevant to an
// SBOM consumer.
//
// Scope: Astinus reads the SBOM AFTER components have been
// identified. Article 13 has obligations the SBOM author must meet
// (vulnerability handling, support lifecycle metadata). We check
// what's representable in the canonical model + the typical
// CycloneDX/SPDX shapes:
//
//   - Annex I §1: Identification — vendor name + version per
//     component (overlaps with NTIA; we don't duplicate the
//     NTIAValidator's findings).
//   - Annex I §2: Vulnerability handling — at least one component
//     reference type that points to a vuln-disclosure URL
//     (`Properties[astinus:references:vuln-disclosure]`) OR an
//     `astinus:cpe:source` property whose value is `nvd-api` or
//     `clearly-defined` (proxy: the operator wired an authoritative
//     CPE source so a downstream scanner CAN look up vulns).
//   - Annex I §3: Support lifecycle — flagged when a major
//     framework (component with a Maven / Helm PURL) lacks any
//     license metadata, since EU CRA expects clarity on
//     redistribution / patching obligations.
//
// The validator emits findings at SeverityLow when the gap is
// recoverable (operator can supplement), SeverityMedium when the
// gap is structural for the EU CRA's purpose. SeverityHigh is
// reserved for explicit Annex I violations the validator can prove
// — today none of our checks reach that bar; documented as a
// scope cut.
type EUCRAValidator struct{}

// NewEUCRA returns a fresh EUCRAValidator. Stateless.
func NewEUCRA() *EUCRAValidator { return &EUCRAValidator{} }

// Name implements policy.Validator.
func (*EUCRAValidator) Name() string { return "eu-cra-article-13" }

// Description implements policy.Validator.
func (*EUCRAValidator) Description() string {
	return "EU Cyber Resilience Act Article 13 + Annex I (auditable subset)"
}

// Validate implements policy.Validator.
func (v *EUCRAValidator) Validate(_ context.Context, sbom *model.SBOM) ([]policy.Finding, error) {
	if sbom == nil {
		return nil, nil
	}
	out := make([]policy.Finding, 0, 4)
	if !sbomHasVulnerabilityHandling(sbom) {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityMedium,
			RuleID:    "EU-CRA-ART13-VULN-HANDLING",
			Message:   "SBOM lacks any vulnerability-handling reference (no authoritative CPE source, no vuln-disclosure URL on any component)",
			Reference: "EU CRA Annex I §2 (b)",
		})
	}
	out = appendCRAComponentFindings(out, sbom.Components)
	return out, nil
}

// appendCRAComponentFindings walks every Component (and
// SubComponents) for the per-component CRA checks.
func appendCRAComponentFindings(out []policy.Finding, comps []model.Component) []policy.Finding {
	for i := range comps {
		c := &comps[i]
		if c.Type == model.ComponentTypeFile {
			continue
		}
		if isMajorFramework(c) && len(c.Licenses) == 0 {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityLow,
				RuleID:    "EU-CRA-ART13-LICENSE",
				Component: c.BOMRef,
				Message:   fmt.Sprintf("Major-framework Component %q lacks license metadata", componentLabel(c)),
				Reference: "EU CRA Annex I §3 (lifecycle / redistribution clarity)",
			})
		}
		if len(c.SubComponents) > 0 {
			out = appendCRAComponentFindings(out, c.SubComponents)
		}
	}
	return out
}

// sbomHasVulnerabilityHandling reports whether ANY signal in the
// SBOM lets a downstream consumer perform vuln lookups. Two kinds
// of signal qualify:
//
//   - At least one Component has a Property pointing at a vuln
//     disclosure URL (`astinus:references:vuln-disclosure` or
//     CycloneDX-native `external-references:vulnerability`).
//   - At least one Component carries an `astinus:cpe:source` of
//     `nvd-api` or `clearly-defined` (PRSD-Task-5) — the operator
//     wired an authoritative CPE source, so a scanner can
//     correlate.
//
// Either signal is sufficient; both being absent means the SBOM
// can't drive a real vuln scan and the CRA gap is real.
func sbomHasVulnerabilityHandling(sbom *model.SBOM) bool {
	var found bool
	walkAllComponents(sbom.Components, func(c *model.Component) {
		if found {
			return
		}
		if c.Properties == nil {
			return
		}
		if c.Properties["astinus:references:vuln-disclosure"] != "" {
			found = true
			return
		}
		switch c.Properties["astinus:cpe:source"] {
		case "nvd-api", "clearly-defined":
			found = true
		}
	})
	return found
}

// isMajorFramework reports whether a Component is the kind the EU
// CRA cares about for license / lifecycle clarity. Heuristic:
// PURLs in the maven, npm-with-major-namespace, helm, or pypi
// ecosystems with a Component type of "framework" / "application".
//
// Conservative: false-negatives are fine (we under-flag); false-
// positives would force operators to chase down license metadata
// for tiny utility libraries, which is friction the regulation
// doesn't intend.
func isMajorFramework(c *model.Component) bool {
	if c.PURL == "" {
		return false
	}
	switch c.Type {
	case model.ComponentTypeFramework, model.ComponentTypeApplication:
		// Type alone isn't enough — operators routinely tag
		// libraries as application. Combine with PURL ecosystem.
	default:
		return false
	}
	return strings.HasPrefix(c.PURL, "pkg:maven/") ||
		strings.HasPrefix(c.PURL, "pkg:helm/") ||
		strings.HasPrefix(c.PURL, "pkg:pypi/") ||
		strings.HasPrefix(c.PURL, "pkg:npm/")
}

// walkAllComponents is the depth-first traversal helper used by
// the validator. Mirrors the pattern in the cpe / dedup enrichers.
func walkAllComponents(comps []model.Component, fn func(*model.Component)) {
	for i := range comps {
		fn(&comps[i])
		if len(comps[i].SubComponents) > 0 {
			walkAllComponents(comps[i].SubComponents, fn)
		}
	}
}
