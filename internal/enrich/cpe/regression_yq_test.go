package cpe

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// fakeYqSource fabricates the exact NVD keyword response that broke
// the v0.2 benchmark on `yq`: a Linksys router (hardware), a German
// auction site (substring noise), and the legitimate yq:v4 entry.
// Returning these as Candidate values with the per-source scoring
// applied lets us assert end-to-end that the enricher quarantines
// the false positives. ADR-0029.
type fakeYqSource struct{}

func (*fakeYqSource) Resolve(_ PURL) []Candidate {
	return []Candidate{
		{
			CPE:            "cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*",
			Source:         "nvd-api",
			Confidence:     ConfidenceReject,
			RejectedReason: "hardware-type CPE for software PURL",
		},
		{
			CPE:            "cpe:2.3:a:miethner-scripting:dz_erotik_auktionshaus_v4rgo:-:*:*:*:*:*:*:*",
			Source:         "nvd-api",
			Confidence:     0.10,
			RejectedReason: "weak nvd substring match",
		},
		{
			CPE:        "cpe:2.3:a:yq:v4:v0.0.0-20231212003515-dd648994340a:*:*:*:*:*:*:*",
			Source:     "nvd-api",
			Confidence: 0.85,
		},
	}
}

// TestRegression_YqFalsePositivesNotInPrimary — end-to-end assertion
// that the v0.2 benchmark bug stays fixed: the Linksys router /
// auction-site CPEs DO NOT appear in c.CPEs nor in any
// `astinus:cpe:alternative:N` slot. They land in the debug log only
// (and, with --include-rejected-cpe, in `astinus:cpe:rejected:N`).
//
// S4 Task 3 update: yq is a `pkg:golang/...` module, and the golang
// ecosystem policy is evidence-only — the legitimate yq:v4 CPE
// surfaces in `astinus:cpe:evidence` instead of `c.CPEs[0]`, with
// `astinus:cpe:scope=evidence-only` and a rationale property.
// This change reduces the test's regression scope to the
// false-positive-quarantine assertion (still the primary contract
// of ADR-0029); the v-prefix / evidence-only path is exercised by
// the policy-specific tests in policy_test.go.
func TestRegression_YqFalsePositivesNotInPrimary(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "yq",
		PURL: "pkg:golang/github.com/mikefarah/yq@v0.0.0-20231212003515-dd648994340a",
	}}}
	enr := NewWithResolver(&fakeYqSource{})
	if err := enr.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	c := sbom.Components[0]
	// Golang ecosystem is evidence-only: c.CPEs must be empty.
	if len(c.CPEs) != 0 {
		t.Errorf("golang component primary CPEs should be empty under "+
			"evidence-only policy; got %v", c.CPEs)
	}
	// The legitimate yq:v4 row should still surface — under evidence.
	if ev := c.Properties["astinus:cpe:evidence"]; !strings.Contains(ev, ":a:yq:v4:") {
		t.Errorf("evidence CPE = %q, want the legitimate yq:v4 entry", ev)
	}
	if scope := c.Properties["astinus:cpe:scope"]; scope != "evidence-only" {
		t.Errorf("astinus:cpe:scope = %q, want evidence-only", scope)
	}

	// Ensure no false-positive CPE landed anywhere visible to a
	// vulnerability scanner (primary cpe field, alternatives, or
	// evidence).
	forbidden := []string{
		"linksys", "befw11s4", "miethner", "erotik", "auktionshaus",
	}
	for _, prim := range c.CPEs {
		for _, bad := range forbidden {
			if strings.Contains(prim, bad) {
				t.Errorf("forbidden token %q in primary CPE %q", bad, prim)
			}
		}
	}
	for k, v := range c.Properties {
		// astinus:cpe:source / :confidence / :rationale / :scope are
		// metadata for the chosen primary, not additional CPE values
		// — skip them in the forbidden-token sweep.
		if !strings.Contains(v, "cpe:2.3:") {
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(v, bad) {
				t.Errorf("forbidden token %q in property %s = %q", bad, k, v)
			}
		}
	}
}

// TestRegression_OutputDoesNotUseDeprecatedNumberedCPEProperty —
// the legacy `astinus:cpe:N` property naming is the v0.2 bug surface.
// After Sprint 3 Task 0, Astinus-emitted SBOMs MUST use the
// `astinus:cpe:alternative:N` schema. This guards against a
// regression where the cpe enricher accidentally re-introduces the
// numbered properties.
func TestRegression_OutputDoesNotUseDeprecatedNumberedCPEProperty(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "with-input", PURL: "pkg:npm/express@4.18.0",
			CPEs: []string{"cpe:2.3:a:placeholder:placeholder:4.18.0:*:*:*:*:*:*:*"}},
		{Name: "no-input", PURL: "pkg:npm/express@4.18.0"},
		{Name: "rejected-input", PURL: "pkg:npm/express@4.18.0",
			CPEs: []string{"not-a-cpe"}},
	}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	deprecated := regexp.MustCompile(`^astinus:cpe:\d+$`)
	for _, c := range sbom.Components {
		for k := range c.Properties {
			if deprecated.MatchString(k) {
				t.Errorf("component %q kept deprecated property %q (should be astinus:cpe:alternative:N)",
					c.Name, k)
			}
		}
	}
}

// TestEnricher_IncludeRejectedCPEFlagSurfacesRejectedProperties —
// without the flag, rejected candidates are debug-log only. With it,
// they become `astinus:cpe:rejected:N` properties so operators can
// inspect what the resolver chain saw.
func TestEnricher_IncludeRejectedCPEFlagSurfacesRejectedProperties(t *testing.T) {
	build := func(includeRejected bool) *model.Component {
		sbom := &model.SBOM{Components: []model.Component{{
			Name: "yq",
			PURL: "pkg:golang/github.com/mikefarah/yq@v0.0.0-20231212003515-dd648994340a",
		}}}
		enr := NewWithResolver(&fakeYqSource{}).WithIncludeRejected(includeRejected)
		if err := enr.Enrich(context.Background(), sbom, nil); err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		return &sbom.Components[0]
	}

	off := build(false)
	for k := range off.Properties {
		if strings.HasPrefix(k, "astinus:cpe:rejected:") {
			t.Errorf("flag off but rejected property leaked: %q", k)
		}
	}

	on := build(true)
	hasRejected := false
	for k := range on.Properties {
		if strings.HasPrefix(k, "astinus:cpe:rejected:") {
			hasRejected = true
		}
	}
	if !hasRejected {
		t.Errorf("flag on but no astinus:cpe:rejected:N property emitted: %v", on.Properties)
	}
}
