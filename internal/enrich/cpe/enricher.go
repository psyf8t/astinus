package cpe

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable cpe`).
const Name = "cpe"

// Enricher is the cpe enrich.Enricher implementation.
//
// Sprint 3 Task 0 changed the output schema:
//
//   - The Component's `cpe` field carries the single highest-confidence
//     candidate (>= Threshold.PrimaryMin).
//   - Other candidates that score >= Threshold.AlternativeMin are
//     surfaced as `astinus:cpe:alternative:N` properties, with their
//     own `:source` and `:confidence` siblings.
//   - Candidates below the alternative floor (and any hard-rejected
//     hardware-CPE-on-software-PURL entries from NVD) are dropped from
//     the SBOM by default. With `--include-rejected-cpe` they appear
//     as `astinus:cpe:rejected:N` for diagnostics.
//
// The previous schema stamped a single `astinus:cpe:confidence=high`
// onto the Component regardless of the underlying candidates, which
// surfaced router/auction-site CPEs to vulnerability scanners as
// authoritative — see ADR-0029.
type Enricher struct {
	chain           Resolver
	threshold       Threshold
	includeRejected bool
}

// New returns an Enricher with DefaultChain() and DefaultThreshold().
func New() *Enricher {
	return &Enricher{chain: DefaultChain(), threshold: DefaultThreshold()}
}

// NewWithResolver returns an Enricher with the supplied resolver.
// Useful for tests that want to drive a deterministic chain.
func NewWithResolver(r Resolver) *Enricher {
	return &Enricher{chain: r, threshold: DefaultThreshold()}
}

// WithIncludeRejected toggles whether rejected candidates are written
// to the SBOM as `astinus:cpe:rejected:N` properties (in addition to
// the always-on debug log). Used by `--include-rejected-cpe`.
func (e *Enricher) WithIncludeRejected(b bool) *Enricher {
	e.includeRejected = b
	return e
}

// WithThreshold overrides the confidence cutoffs the enricher applies
// when classifying candidates. Useful for policy-driven tuning.
func (e *Enricher) WithThreshold(t Threshold) *Enricher {
	e.threshold = t
	return e
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. PRSD-Task-6: cpe needs
// PURLs on every Component the SBOM carries — the multi-modal
// extractors (PRSD-Task-4, wired into untracked.processFile) are
// the source of those PURLs for binary-shaped untracked entries.
// Declaring "untracked" guarantees we only resolve once the PURLs
// are populated. S3 Task 1 adds "extractor" so the lifted
// embedded-dependency components (yq's gopkg.in/yaml.v3 etc.) also
// pick up CPEs.
func (*Enricher) Dependencies() []string { return []string{"untracked", "extractor"} }

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

	stats := enrichStats{}
	walk(sbom.Components, func(c *model.Component) {
		e.enrichOne(c, &stats)
	})

	slog.Default().Info("cpe.complete",
		"components_examined", stats.examined,
		"had_cpe_already", stats.hadCPEAlready,
		"added_cpe", stats.addedCPE,
		"validated", stats.validated,
		"no_match", stats.noMatch,
		"no_purl", stats.noPURL,
		"purl_error", stats.purlError,
		"alternatives_kept", stats.alternativesKept,
		"rejected", stats.rejectedCount,
	)
	return nil
}

// enrichStats counts what the enricher did across one Enrich call.
// Surfaced via the cpe.complete log so operators can see actual
// enrichment effectiveness (post-Stage-13 hardening Task 5.3).
type enrichStats struct {
	examined         int
	hadCPEAlready    int
	addedCPE         int // components for which the resolver added at least one CPE
	validated        int // existing CPEs validated (and the component had any)
	noMatch          int // no candidate cleared even the alternative floor
	noPURL           int // no PURL at all → can't enrich
	purlError        int // PURL malformed
	alternativesKept int // count of `astinus:cpe:alternative:N` properties written
	rejectedCount    int // count of candidates classified as rejected
}

// enrichOne mutates c in place per the contract above.
func (e *Enricher) enrichOne(c *model.Component, stats *enrichStats) {
	stats.examined++

	// Wipe any astinus:cpe:* breadcrumbs from a previous run so re-
	// enrichment is idempotent and the alternative numbering does
	// not pile up.
	clearCPEProperties(c)

	hadExisting := len(c.CPEs) > 0
	if hadExisting {
		stats.hadCPEAlready++
	}

	// Build the candidate slate: existing CPEs + resolver matches.
	cands := candidatesFromExistingCPEs(c.CPEs)
	if hadExisting {
		stats.validated++
	}

	if c.PURL == "" {
		if !hadExisting {
			stats.noPURL++
			return
		}
		// No PURL but pre-existing CPEs — apply classification on the
		// existing ones alone.
		e.writeResults(c, cands, stats)
		return
	}

	purl, err := ParsePURL(c.PURL)
	if err != nil {
		stats.purlError++
		setProp(c, "astinus:cpe:purl-error", err.Error())
		return
	}

	cands = append(cands, e.chain.Resolve(purl)...)

	if len(cands) == 0 {
		stats.noMatch++
		setProp(c, "astinus:cpe:lookup", "no-match")
		return
	}

	addedCPE := e.writeResults(c, cands, stats)
	if addedCPE {
		stats.addedCPE++
	}
}

// candidatesFromExistingCPEs converts CPE strings already on a
// Component into Candidate proposals. Valid entries score
// ConfidenceMedium so they remain primary in the absence of a better
// resolver match; invalid entries score ConfidenceReject so Classify
// surfaces them with an explanatory RejectedReason.
func candidatesFromExistingCPEs(cpes []string) []Candidate {
	if len(cpes) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(cpes))
	for _, s := range cpes {
		if IsValidCPE(s) {
			out = append(out, Candidate{
				CPE:        s,
				Source:     SourceInput,
				Confidence: ConfidenceMedium,
				Evidence:   "input SBOM",
				MatchDetails: MatchDetails{
					SearchMethod: "purl-direct",
				},
			})
			continue
		}
		out = append(out, Candidate{
			CPE:            s,
			Source:         SourceInput,
			Confidence:     ConfidenceReject,
			Evidence:       "input SBOM",
			RejectedReason: "input CPE failed CPE 2.3 syntax validation",
		})
	}
	return out
}

// writeResults runs Classify over cands and projects the result onto
// the Component. Returns true when the Component picked up at least
// one CPE that wasn't already present.
func (e *Enricher) writeResults(c *model.Component, cands []Candidate, stats *enrichStats) bool {
	cands = DedupeCandidates(cands)
	primary, alts, rejected := Classify(cands, e.threshold)

	originalCPEs := append([]string(nil), c.CPEs...)
	c.CPEs = nil

	added := false
	if primary != nil {
		c.CPEs = []string{primary.CPE}
		setProp(c, "astinus:cpe:source", string(primary.Source))
		setProp(c, "astinus:cpe:confidence", formatConfidence(primary.Confidence))
		if primary.Evidence != "" {
			setProp(c, "astinus:cpe:evidence", primary.Evidence)
		}
		setValidationStamps(c, originalCPEs)
		if !contains(originalCPEs, primary.CPE) {
			added = true
		}
	} else if len(originalCPEs) > 0 {
		// Nothing cleared the primary floor but we shouldn't drop
		// the input CPEs silently — keep them so downstream consumers
		// still see the data the operator started with.
		c.CPEs = originalCPEs
		setValidationStamps(c, originalCPEs)
		setProp(c, "astinus:cpe:lookup", "no-primary-above-threshold")
	} else {
		setProp(c, "astinus:cpe:lookup", "no-match")
	}

	for i, alt := range alts {
		idx := i + 1
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d", idx), alt.CPE)
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d:source", idx), string(alt.Source))
		setProp(c, fmt.Sprintf("astinus:cpe:alternative:%d:confidence", idx), formatConfidence(alt.Confidence))
		stats.alternativesKept++
	}

	for i, rej := range rejected {
		slog.Default().Debug("cpe.rejected",
			"component", c.Name,
			"cpe", rej.CPE,
			"confidence", rej.Confidence,
			"source", rej.Source,
			"reason", rej.RejectedReason)
		stats.rejectedCount++
		if !e.includeRejected {
			continue
		}
		idx := i + 1
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d", idx), rej.CPE)
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:source", idx), string(rej.Source))
		setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:confidence", idx), formatConfidence(rej.Confidence))
		if rej.RejectedReason != "" {
			setProp(c, fmt.Sprintf("astinus:cpe:rejected:%d:reason", idx), rej.RejectedReason)
		}
	}

	return added
}

// setValidationStamps mirrors the legacy validated/invalid stamps so
// downstream consumers (compliance, sarif, summary) keep working.
// Looks at the ORIGINAL set of CPEs that the component arrived with,
// not the post-classification slate.
func setValidationStamps(c *model.Component, original []string) {
	if len(original) == 0 {
		return
	}
	good, bad := 0, 0
	for _, s := range original {
		if IsValidCPE(s) {
			good++
		} else {
			bad++
		}
	}
	switch {
	case bad == 0:
		setProp(c, "astinus:cpe:validated", "true")
	case good == 0:
		setProp(c, "astinus:cpe:validated", "false")
		setProp(c, "astinus:cpe:invalid", "true")
	default:
		setProp(c, "astinus:cpe:validated", "partial")
	}
}

// clearCPEProperties drops every astinus:cpe:* breadcrumb from c so
// the enricher can rewrite a fresh slate. Kept tight on the cpe:
// prefix so we don't accidentally clobber other astinus:* keys.
func clearCPEProperties(c *model.Component) {
	if c.Properties == nil {
		return
	}
	for k := range c.Properties {
		if strings.HasPrefix(k, "astinus:cpe:") {
			delete(c.Properties, k)
		}
	}
}

// formatConfidence renders a confidence float as a 2-decimal string
// for property values. Renderers that gate on it (sarif, summary)
// parse it back to compare against their own thresholds.
func formatConfidence(c float64) string {
	return fmt.Sprintf("%.2f", c)
}

// contains is a tiny helper used to dedupe primary CPEs against the
// component's prior set.
func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
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
