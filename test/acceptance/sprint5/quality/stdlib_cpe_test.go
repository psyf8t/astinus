//go:build acceptance

package quality

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	s3 "github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
	s4 "github.com/psyf8t/astinus/test/acceptance/sprint4/helpers"
)

// TestS5T0_StdlibCPEKeepsPrimaryViaException — S5 Task 0 regression
// gate. The Sprint 4 Task 3 policy (ADR-0042) demotes every
// `pkg:golang/...` CPE to `astinus:cpe:evidence` so scanner-facing
// `Component.CPE` doesn't carry the resolver's guess. The Go
// stdlib (`pkg:golang/stdlib@<go-version>`) is the one exception:
// NVD does register `cpe:2.3:a:golang:go:<version>:*`, real CVEs
// (e.g. CVE-2024-24783) carry that CPE, and scanners need it on
// the scanner-facing slot to find them. ADR-0047 narrows the S4-T3
// demotion via a per-PURL `KeepPrimaryPurls` allow-list. This test
// drives a stdlib row through the actual binary and asserts:
//
//  1. Primary CPE survives on `c.CPE` (scanner-facing).
//  2. `astinus:cpe:exception-applied = keep-primary` stamps the row
//     for audit traceability.
//  3. The companion `astinus:cpe:exception-rationale` is non-empty.
//  4. The component does NOT pick up the evidence-only stamps
//     (`astinus:cpe:scope = evidence-only` etc.) that other golang
//     rows acquire.
func TestS5T0_StdlibCPEKeepsPrimaryViaException(t *testing.T) {
	stdlibPURL := "pkg:golang/stdlib@1.21.5"
	// Mirror what Syft / Trivy actually stamp on stdlib rows in
	// real input SBOMs (run #3 inspected the Grafana baseline and
	// both producers carry the canonical `cpe:2.3:a:golang:go:`
	// shape). Without an input CPE the heuristic resolver would
	// derive a `cpe:2.3:a:stdlib:stdlib:` shape — also a primary,
	// also exception-applied, but not what an operator sees.
	inputCPE := "cpe:2.3:a:golang:go:1.21.5:-:*:*:*:*:*:*"
	inputSBOM := s4.WriteCDXSBOM(t,
		[]cdx.Component{{
			BOMRef:     "comp-stdlib",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "stdlib",
			Version:    "1.21.5",
			PackageURL: stdlibPURL,
			CPE:        inputCPE,
		}},
		cdx.Tool{Name: "syft"},
	)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      inputSBOM,
		Image:     "test/empty:1",
		NoNetwork: true,
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	stdlib := s4.FindComponent(res.BOM, "stdlib", "")
	if stdlib == nil {
		t.Fatalf("stdlib component missing from output; %d components total",
			countComponents(res.BOM))
	}
	if stdlib.CPE == "" {
		t.Errorf("stdlib.CPE empty — S5-T0 keep-primary exception did not run (input CPE dropped by ADR-0042 demotion)")
	}
	if !strings.HasPrefix(stdlib.CPE, "cpe:2.3:a:golang:go:") {
		t.Errorf("stdlib.CPE = %q, want cpe:2.3:a:golang:go:<version>:* (the operator-visible CPE shape NVD carries)",
			stdlib.CPE)
	}
	if got := s4.PropertyValue(stdlib, "astinus:cpe:exception-applied"); got != "keep-primary" {
		t.Errorf("astinus:cpe:exception-applied = %q, want keep-primary", got)
	}
	if got := s4.PropertyValue(stdlib, "astinus:cpe:exception-rationale"); got == "" {
		t.Errorf("astinus:cpe:exception-rationale empty on stdlib row — rationale not surfaced")
	}
	if got := s4.PropertyValue(stdlib, "astinus:cpe:scope"); got == "evidence-only" {
		t.Errorf("astinus:cpe:scope = %q on stdlib — exception did not bypass evidence-only demotion",
			got)
	}
}

// TestS5T0_NonStdlibGolangRowStaysEvidenceOnly — guards the
// narrow-scope clause of ADR-0047: the keep-primary exception MUST
// NOT widen to ordinary `pkg:golang/<vendor>/<module>` rows.
// Non-stdlib golang components keep the S4-T3 evidence-only demotion.
func TestS5T0_NonStdlibGolangRowStaysEvidenceOnly(t *testing.T) {
	logrusPURL := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	inputSBOM := s4.WriteCDXSBOM(t,
		[]cdx.Component{{
			BOMRef:     "comp-logrus",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "github.com/sirupsen/logrus",
			Version:    "v1.9.3",
			PackageURL: logrusPURL,
		}},
		cdx.Tool{Name: "syft"},
	)

	res := s3.RunEnrichOK(t, s3.EnrichOpts{
		SBOM:      inputSBOM,
		Image:     "test/empty:1",
		NoNetwork: true,
	})
	if res.BOM == nil {
		t.Fatal("no BOM in output")
	}
	logrus := s4.FindComponent(res.BOM, "github.com/sirupsen/logrus", "")
	if logrus == nil {
		t.Fatal("logrus component missing from output")
	}
	if logrus.CPE != "" {
		t.Errorf("logrus.CPE = %q on non-stdlib golang row — exception widened past stdlib",
			logrus.CPE)
	}
	if got := s4.PropertyValue(logrus, "astinus:cpe:exception-applied"); got != "" {
		t.Errorf("astinus:cpe:exception-applied = %q on non-stdlib row, want empty (exception too broad)",
			got)
	}
}

func countComponents(bom *cdx.BOM) int {
	if bom == nil || bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}
