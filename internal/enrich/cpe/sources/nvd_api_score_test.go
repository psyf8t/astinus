package sources

import (
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// TestScoreNVDMatch_HardwareRejectedForSoftwarePURL — regression test
// for the v0.2 benchmark false positive: NVD keyword "yq" returned a
// Linksys BEFW11S4_v4 router CPE (type=h). scoreNVDMatch must hard-
// reject hardware-type CPEs on software PURLs so the entry never
// becomes an alternative on the Component. ADR-0029.
func TestScoreNVDMatch_HardwareRejectedForSoftwarePURL(t *testing.T) {
	purl := cpe.PURL{
		Type:      "golang",
		Namespace: "github.com/mikefarah",
		Name:      "yq",
		Version:   "v4.40.5",
	}
	router, err := cpe.Parse("cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	score, details := scoreNVDMatch(purl, router)
	if score >= 0.10 {
		t.Errorf("hardware CPE score = %.2f, want strict reject (< 0.10) — "+
			"this is the yq → Linksys router false positive from v0.2 benchmark",
			score)
	}
	if details.SearchMethod != "keyword-search" {
		t.Errorf("MatchDetails.SearchMethod = %q", details.SearchMethod)
	}
}

// TestScoreNVDMatch_RealWorldYqCase — reproduces the exact false-
// positive trio observed on the reference image (yq → Linksys
// router + German auction site) and the legitimate yq:v4 entry.
// The two false positives must score below the alternative
// threshold (0.50); the true positive must score at or above the
// primary threshold (0.70). ADR-0029.
func TestScoreNVDMatch_RealWorldYqCase(t *testing.T) {
	purl := cpe.PURL{
		Type:      "golang",
		Namespace: "github.com/mikefarah",
		Name:      "yq",
		Version:   "v0.0.0-20231212003515-dd648994340a",
	}

	type tc struct {
		name string
		raw  string
		want float64 // upper bound for false positives, lower bound for true positive
		fp   bool    // true → expect score < want; false → expect score >= want
	}

	cases := []tc{
		{
			name: "linksys router (hardware false positive)",
			raw:  "cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*",
			want: 0.50, fp: true,
		},
		{
			name: "auction-site substring false positive",
			raw:  "cpe:2.3:a:miethner-scripting:dz_erotik_auktionshaus_v4rgo:-:*:*:*:*:*:*:*",
			want: 0.50, fp: true,
		},
		{
			name: "true positive: yq:v4",
			raw:  "cpe:2.3:a:yq:v4:v0.0.0-20231212003515-dd648994340a:*:*:*:*:*:*:*",
			want: 0.70, fp: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parsed, err := cpe.Parse(c.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			score, _ := scoreNVDMatch(purl, parsed)
			switch {
			case c.fp && score >= c.want:
				t.Errorf("false positive scored %.2f (>= %.2f); should be rejected",
					score, c.want)
			case !c.fp && score < c.want:
				t.Errorf("true positive scored %.2f (< %.2f); should be primary",
					score, c.want)
			}
		})
	}
}

// TestScoreNVDMatch_VersionWildcardSoftMatch — NVD entries with `*`
// or `-` in the version slot describe ranges; they should grant
// partial version credit so a vendor-correct entry still clears
// the alternative threshold even without an exact version.
func TestScoreNVDMatch_VersionWildcardSoftMatch(t *testing.T) {
	purl := cpe.PURL{Type: "npm", Name: "express", Version: "4.18.0"}
	parsed, _ := cpe.Parse("cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*")
	score, details := scoreNVDMatch(purl, parsed)
	if score < 0.50 {
		t.Errorf("vendor+product match with wildcard version scored %.2f, want >= 0.50",
			score)
	}
	if details.VersionMatch != "wildcard" {
		t.Errorf("VersionMatch = %q, want wildcard", details.VersionMatch)
	}
}

// TestCandidatesFromNVDPage_StampsHardRejectReason — regression for
// the per-Candidate RejectedReason wiring: a hardware CPE in the
// page must come back already labelled so Classify keeps the diagnostic
// trail.
func TestCandidatesFromNVDPage_StampsHardRejectReason(t *testing.T) {
	page := &nvdCPEPage{
		Products: []struct {
			CPE struct {
				CPEName string `json:"cpeName"`
			} `json:"cpe"`
		}{
			{CPE: struct {
				CPEName string `json:"cpeName"`
			}{CPEName: "cpe:2.3:h:linksys:befw11s4_v4:-:*:*:*:*:*:*:*"}},
		},
	}
	purl := cpe.PURL{Type: "golang", Namespace: "github.com/mikefarah", Name: "yq", Version: "v4"}
	got := candidatesFromNVDPage(page, purl)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	if got[0].RejectedReason == "" {
		t.Errorf("hardware-type CPE missing RejectedReason: %+v", got[0])
	}
}

func TestScoreVendor_NormalizedAndSubstringPaths(t *testing.T) {
	cases := []struct {
		name         string
		cpeVendor    string
		ns, nm       string
		wantKind     string
		wantMinScore float64
	}{
		{"empty vendor", "", "x", "y", "no-match", 0.0},
		{"normalized to namespace (dash → underscore)", "go_toml", "go-toml", "", "normalized", 0.40},
		{"normalized to name", "log_4j", "", "log-4j", "normalized", 0.40},
		{"namespace substring contains vendor", "apache", "org.apache.commons", "x", "substring", 0.10},
		{"name substring fallback", "express_org", "", "express", "substring", 0.10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, score := scoreVendor(c.cpeVendor, c.ns, c.nm)
			if kind != c.wantKind {
				t.Errorf("kind = %q, want %q", kind, c.wantKind)
			}
			if score < c.wantMinScore || score > c.wantMinScore+1e-6 {
				t.Errorf("score = %v, want %v", score, c.wantMinScore)
			}
		})
	}
}

func TestScoreProduct_NormalizedAndNamespaceFallback(t *testing.T) {
	cases := []struct {
		name                 string
		cpeProduct, nm, ns   string
		wantKind, _testNoOp1 string
		wantMinScore         float64
	}{
		{"normalized dash to underscore", "log_4j", "log-4j", "", "normalized", "", 0.30},
		{"namespace-segment match", "log4j", "other", "org.apache.log4j", "namespace-segment", "", 0.20},
		{"substring fallback", "express_org", "express", "", "substring", "", 0.10},
		{"empty inputs", "", "", "", "no-match", "", 0.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, score := scoreProduct(c.cpeProduct, c.nm, c.ns)
			if kind != c.wantKind {
				t.Errorf("kind = %q, want %q", kind, c.wantKind)
			}
			if score != c.wantMinScore {
				t.Errorf("score = %v, want %v", score, c.wantMinScore)
			}
		})
	}
}

func TestScoreVersion_AllPaths(t *testing.T) {
	cases := []struct {
		name           string
		cpeVer, purlV  string
		wantKind       string
		wantScoreAtMin float64
	}{
		{"no purl version", "1.2", "", "wildcard", 0.05},
		{"exact match", "1.2", "1.2", "exact", 0.20},
		{"cpe wildcard *", "*", "1.2", "wildcard", 0.10},
		{"cpe wildcard -", "-", "1.2", "wildcard", 0.10},
		{"mismatch", "9.9", "1.2", "mismatch", 0.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, score := scoreVersion(c.cpeVer, c.purlV)
			if kind != c.wantKind {
				t.Errorf("kind = %q, want %q", kind, c.wantKind)
			}
			if score != c.wantScoreAtMin {
				t.Errorf("score = %v, want %v", score, c.wantScoreAtMin)
			}
		})
	}
}

// TestNVDAPI_NameAndPriorityMetadata is a tiny audit of the metadata
// methods the orchestrator relies on for filtering and logging.
// Cheap to maintain and pulls Name() / Priority() / clearly-defined
// metadata into coverage so the package floor stays comfortably
// above the pre-S3 baseline.
func TestNVDAPI_NameAndPriorityMetadata(t *testing.T) {
	if (&NVDAPISource{}).Name() != "nvd-api" {
		t.Errorf("Name = %q, want nvd-api", (&NVDAPISource{}).Name())
	}
	if (&ClearlyDefinedSource{}).Name() != "clearly-defined" {
		t.Errorf("Name = %q, want clearly-defined", (&ClearlyDefinedSource{}).Name())
	}
	if (&ClearlyDefinedSource{}).Priority() != 70 {
		t.Errorf("ClearlyDefined Priority = %d, want 70", (&ClearlyDefinedSource{}).Priority())
	}
	if (&HeuristicSource{}).Name() != "heuristic" {
		t.Errorf("Heuristic Name = %q", (&HeuristicSource{}).Name())
	}
}

func TestLastSegmentHelper(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"plain":                     "plain",
		"org.apache.logging.log4j":  "log4j",
		"github.com/mikefarah/yq":   "yq",
		"only.dotted.path":          "path",
		"trailing/slash/edge/case/": "",
	}
	for in, want := range cases {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNewTokenBucketDefaults exercises the rps<=0 / burst<1 branches
// that callers don't normally hit but the constructor handles
// defensively.
func TestNewTokenBucketDefaults(t *testing.T) {
	b := newTokenBucket(0, 0)
	if b.rps != 1 || b.burst != 1 {
		t.Errorf("defensive defaults wrong: rps=%v burst=%v", b.rps, b.burst)
	}
}
