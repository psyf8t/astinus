package cpe

import "testing"

func TestCandidate_MatchAlias(t *testing.T) {
	// Match is the deprecated alias for Candidate; existing call
	// sites that build a `Match{...}` literal should still compile
	// and produce a Candidate of the same shape.
	m := Match{
		CPE:        "cpe:2.3:a:foo:bar:1:*:*:*:*:*:*:*",
		Source:     SourceBundled,
		Confidence: ConfidenceHigh,
	}
	if m.CPE == "" || m.Source != SourceBundled || m.Confidence != ConfidenceHigh {
		t.Errorf("Match alias broken: %+v", m)
	}
}

func TestCandidate_RejectedReasonRoundtrip(t *testing.T) {
	c := Candidate{
		CPE:            "cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*",
		Confidence:     ConfidenceReject,
		Source:         "nvd-api",
		RejectedReason: "hardware-type CPE for software PURL",
		MatchDetails: MatchDetails{
			VendorMatch:  "no-match",
			ProductMatch: "no-match",
			VersionMatch: "n/a",
			SearchMethod: "keyword-search",
		},
	}
	if c.RejectedReason == "" {
		t.Error("RejectedReason should round-trip")
	}
	if c.MatchDetails.SearchMethod != "keyword-search" {
		t.Errorf("MatchDetails.SearchMethod = %q", c.MatchDetails.SearchMethod)
	}
}
