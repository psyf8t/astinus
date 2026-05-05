package cpe

import (
	"strings"
	"testing"
)

func TestClassify_PrimaryAndAlts(t *testing.T) {
	cands := []Candidate{
		{CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", Confidence: 0.95, Source: SourceBundled},
		{CPE: "cpe:2.3:a:log4j:log4j-core:2.14.1:*:*:*:*:*:*:*", Confidence: 0.85, Source: SourceInput},
		{CPE: "cpe:2.3:a:foo:bar:1.0:*:*:*:*:*:*:*", Confidence: 0.20, Source: "nvd-api"},
	}
	primary, alts, rejected := Classify(cands, DefaultThreshold())

	if primary == nil {
		t.Fatal("primary should be the apache:log4j hit")
	}
	if primary.CPE != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("primary = %+v", primary)
	}
	if len(alts) != 1 {
		t.Errorf("alts = %d, want 1", len(alts))
	}
	if len(rejected) != 1 {
		t.Errorf("rejected = %d, want 1", len(rejected))
	}
	if !strings.Contains(rejected[0].RejectedReason, "below threshold") {
		t.Errorf("rejected reason = %q, want a threshold-explanation", rejected[0].RejectedReason)
	}
}

// TestClassify_NoPrimaryWhenAllBelowFloor — when nothing clears the
// PrimaryMin, classification yields nil primary; the orchestrator
// then keeps the original input CPEs (handled in enricher.writeResults).
func TestClassify_NoPrimaryWhenAllBelowFloor(t *testing.T) {
	cands := []Candidate{
		{CPE: "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", Confidence: 0.55, Source: "nvd-api"},
		{CPE: "cpe:2.3:a:p:q:1:*:*:*:*:*:*:*", Confidence: 0.50, Source: SourceHeuristic},
	}
	primary, alts, _ := Classify(cands, DefaultThreshold())
	if primary != nil {
		t.Errorf("primary should be nil when no candidate clears PrimaryMin: %+v", primary)
	}
	if len(alts) != 2 {
		t.Errorf("alts = %d, want both candidates as alternatives", len(alts))
	}
}

// TestClassify_PreservesInputOrderOnTies — confidence ties resolve
// in input order so reruns are deterministic and the operator can
// influence ranking by ordering Sources.
func TestClassify_PreservesInputOrderOnTies(t *testing.T) {
	cands := []Candidate{
		{CPE: "cpe:2.3:a:first:thing:1:*:*:*:*:*:*:*", Confidence: 0.95, Source: SourceBundled},
		{CPE: "cpe:2.3:a:second:thing:1:*:*:*:*:*:*:*", Confidence: 0.95, Source: SourceLocalDict},
	}
	primary, _, _ := Classify(cands, DefaultThreshold())
	if primary == nil || primary.CPE != "cpe:2.3:a:first:thing:1:*:*:*:*:*:*:*" {
		t.Errorf("primary = %+v, want first input on tie", primary)
	}
}

// TestClassify_PreservesExplicitRejectedReason — a Source that hard-
// rejects (e.g. NVD's hardware-CPE-on-software-PURL path) attaches
// its own RejectedReason; Classify must not overwrite it with the
// generic "below threshold" message.
func TestClassify_PreservesExplicitRejectedReason(t *testing.T) {
	cands := []Candidate{
		{CPE: "cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*",
			Confidence: 0.05, Source: "nvd-api",
			RejectedReason: "hardware-type CPE for software PURL"},
	}
	_, _, rejected := Classify(cands, DefaultThreshold())
	if len(rejected) != 1 {
		t.Fatalf("rejected len = %d", len(rejected))
	}
	if !strings.Contains(rejected[0].RejectedReason, "hardware-type") {
		t.Errorf("explicit rejection reason was overwritten: %q", rejected[0].RejectedReason)
	}
}

func TestClassify_EmptyInput(t *testing.T) {
	primary, alts, rejected := Classify(nil, DefaultThreshold())
	if primary != nil || len(alts) != 0 || len(rejected) != 0 {
		t.Errorf("empty input should yield (nil, nil, nil); got (%v, %v, %v)", primary, alts, rejected)
	}
}

func TestDefaultThresholdValues(t *testing.T) {
	t1 := DefaultThreshold()
	if t1.PrimaryMin != 0.70 {
		t.Errorf("PrimaryMin = %v, want 0.70", t1.PrimaryMin)
	}
	if t1.AlternativeMin != 0.50 {
		t.Errorf("AlternativeMin = %v, want 0.50", t1.AlternativeMin)
	}
}

func TestDedupeCandidates_MergesAndKeepsHighest(t *testing.T) {
	cpe := "cpe:2.3:a:expressjs:express:4.18.0:*:*:*:*:*:*:*"
	in := []Candidate{
		{CPE: cpe, Confidence: 0.50, Source: SourceHeuristic},
		{CPE: cpe, Confidence: 0.95, Source: SourceBundled},
		{CPE: "cpe:2.3:a:other:thing:1:*:*:*:*:*:*:*", Confidence: 0.70, Source: "nvd-api"},
	}
	out := DedupeCandidates(in)
	if len(out) != 2 {
		t.Fatalf("dedup len = %d, want 2", len(out))
	}
	for _, c := range out {
		if c.CPE == cpe && c.Confidence != 0.95 {
			t.Errorf("kept lower-confidence copy: %+v", c)
		}
		if c.CPE == cpe && !strings.Contains(string(c.Source), "bundled") {
			t.Errorf("merged source missing bundled: %q", c.Source)
		}
		if c.CPE == cpe && !strings.Contains(string(c.Source), "heuristic") {
			t.Errorf("merged source missing heuristic: %q", c.Source)
		}
	}
}

func TestDedupeCandidates_SingleEntryPassThrough(t *testing.T) {
	in := []Candidate{{CPE: "x", Confidence: 0.5}}
	if got := DedupeCandidates(in); len(got) != 1 || got[0].CPE != "x" {
		t.Errorf("got %+v", got)
	}
}
