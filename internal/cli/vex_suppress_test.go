package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/vex"
)

// TestApplyVEXSuppression_FiltersNotAffectedCVE — S6 Task 6 core
// contract. A CVE-shaped finding (RuleID matches the `CVE-` shape)
// whose (vulnID, componentPURL) is `not_affected` in the VEX store
// is suppressed and stamps SBOM metadata.
func TestApplyVEXSuppression_FiltersNotAffectedCVE(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "comp-1",
			Name:    "log4j-core",
			Version: "2.14.1",
			PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		}},
	}
	store := vex.NewStore()
	store.AddEffect(vex.Effect{
		VulnID:        "CVE-2024-12345",
		ProductPURL:   "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Status:        vex.StatusNotAffected,
		Justification: vex.JustVulnerableCodeNotInExecutePath,
		Source:        "/path/to/vex.json",
	})
	findings := []policy.Finding{
		{Severity: policy.SeverityHigh, RuleID: "CVE-2024-12345", Component: "comp-1"},
		{Severity: policy.SeverityHigh, RuleID: "NTIA-VERSION", Component: "comp-1"},
	}

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	suppressed := applyVEXSuppression(sbom, findings, store, logger)

	if _, ok := suppressed["CVE-2024-12345"]; !ok {
		t.Errorf("CVE-2024-12345 not suppressed: got %v", suppressed)
	}
	if _, ok := suppressed["NTIA-VERSION"]; ok {
		t.Errorf("NTIA-VERSION (non-CVE) suppressed; VEX layer must not touch non-CVE findings")
	}
	if got := sbom.Metadata.Properties["astinus:vex:suppressed:CVE-2024-12345"]; got == "" {
		t.Error("astinus:vex:suppressed:CVE-2024-12345 not stamped")
	}
	if !strings.Contains(sbom.Metadata.Properties["astinus:vex:suppressed:CVE-2024-12345"],
		string(vex.StatusNotAffected)) {
		t.Errorf("suppressed value = %q, want to mention not_affected",
			sbom.Metadata.Properties["astinus:vex:suppressed:CVE-2024-12345"])
	}
	if got := sbom.Metadata.Properties["astinus:vex:total-suppressed"]; got != "1" {
		t.Errorf("total-suppressed = %q, want 1", got)
	}
	if got := sbom.Metadata.Properties["astinus:vex:sources"]; got != "/path/to/vex.json" {
		t.Errorf("sources = %q, want /path/to/vex.json", got)
	}
	if !strings.Contains(logBuf.String(), "compliance.vex.suppressed") {
		t.Errorf("expected suppression log line, got:\n%s", logBuf.String())
	}
}

// TestApplyVEXSuppression_AffectedDoesNotSuppress — VEX `affected`
// statements explicitly mark a CVE as applicable; the gate must NOT
// suppress those.
func TestApplyVEXSuppression_AffectedDoesNotSuppress(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "c", PURL: "pkg:npm/x@1.0",
		}},
	}
	store := vex.NewStore()
	store.AddEffect(vex.Effect{
		VulnID:      "CVE-2024-99999",
		ProductPURL: "pkg:npm/x@1.0",
		Status:      vex.StatusAffected,
		Source:      "vex.json",
	})
	findings := []policy.Finding{
		{Severity: policy.SeverityHigh, RuleID: "CVE-2024-99999", Component: "c"},
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	suppressed := applyVEXSuppression(sbom, findings, store, logger)
	if len(suppressed) != 0 {
		t.Errorf("affected status suppressed %v findings, want 0", suppressed)
	}
}

// TestApplyVEXSuppression_NoVexStoreNoOp — passing a nil/empty
// store flows through unchanged; no metadata stamps, no
// suppression.
func TestApplyVEXSuppression_NoVexStoreNoOp(t *testing.T) {
	sbom := &model.SBOM{}
	findings := []policy.Finding{{RuleID: "CVE-2024-XXX"}}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	suppressed := applyVEXSuppression(sbom, findings, nil, logger)
	if len(suppressed) != 0 {
		t.Errorf("nil store produced suppressions: %v", suppressed)
	}
	if got := sbom.Metadata.Properties["astinus:vex:total-suppressed"]; got != "" {
		t.Errorf("nil store stamped total-suppressed = %q", got)
	}
}

// TestApplyVEXSuppression_PURLMappingViaBOMRef — Findings carry
// Component=BOMRef, not PURL. The suppression layer must resolve
// BOMRef → PURL via the SBOM's component list before querying the
// store.
func TestApplyVEXSuppression_PURLMappingViaBOMRef(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef: "bom-ref-only",
			Name:   "express",
			PURL:   "pkg:npm/express@4.18.2",
		}},
	}
	store := vex.NewStore()
	store.AddEffect(vex.Effect{
		VulnID: "CVE-2024-EXPR", ProductPURL: "pkg:npm/express@*",
		Status: vex.StatusNotAffected, Source: "/x.vex",
	})
	findings := []policy.Finding{
		{Severity: policy.SeverityHigh, RuleID: "CVE-2024-EXPR", Component: "bom-ref-only"},
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	suppressed := applyVEXSuppression(sbom, findings, store, logger)
	if _, ok := suppressed["CVE-2024-EXPR"]; !ok {
		t.Errorf("BOMRef → PURL lookup failed; suppressed = %v", suppressed)
	}
}

// TestIsCVERuleID pins the helper that gates the VEX layer to
// CVE-shaped rule IDs. Compliance findings (NTIA-, EU-CRA-, etc.)
// must not flow through VEX suppression.
func TestIsCVERuleID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"CVE-2024-12345", true},
		{"CVE-1999-0001", true},
		{"NTIA-VERSION", false},
		{"NTIA-SUPPLIER", false},
		{"EU-CRA-ART13-VULN", false},
		{"", false},
		{"CVE-", false},
	}
	for _, c := range cases {
		if got := isCVERuleID(c.id); got != c.want {
			t.Errorf("isCVERuleID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}
