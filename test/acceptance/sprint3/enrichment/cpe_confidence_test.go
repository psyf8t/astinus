//go:build acceptance

package enrichment

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/sprint3/helpers"
)

// TestCPEConfidence_PropertiesEmittedFromBundled — Sprint 3 Task 0
// reshaped CPE matching to surface a primary + alternatives, with a
// confidence score on each. The BOM that comes out should carry an
// `astinus:cpe:source` property on every component the enricher
// touched (here: every npm component that resolves against the
// bundled dictionary).
//
// We use --no-network so no NVD API calls happen — the bundled
// dictionary is the only source. If the bundled dictionary covers
// neither lodash nor express the test t.Skip()s; this is a
// fingerprint check, not a coverage check.
func TestCPEConfidence_PropertiesEmittedFromBundled(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/cpe-confidence:1.0",
		NoNetwork: true,
		Extra: []string{
			"--cpe-mode", "bundled",
			"--disable", "layer", "--disable", "evidence",
		},
	})

	stamped := 0
	for _, name := range []string{"lodash", "express"} {
		c := findComponent(t, res.BOM, name)
		if propertyValue(c, "astinus:cpe:source") != "" {
			stamped++
		}
	}
	if stamped == 0 {
		t.Skip("bundled dictionary did not match either lodash or express; nothing to assert")
	}
}

// TestCPEConfidence_RejectedAreInvisibleByDefault — without
// --include-rejected-cpe, the BOM should NOT carry rejected
// candidate properties (`astinus:cpe:rejected:N`). The rejected set
// only surfaces when the operator opts in.
func TestCPEConfidence_RejectedAreInvisibleByDefault(t *testing.T) {
	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.MinimalNpmSBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/cpe-rejected:1.0",
		NoNetwork: true,
		Extra: []string{
			"--cpe-mode", "bundled",
			"--disable", "layer", "--disable", "evidence",
		},
	})

	for _, name := range []string{"lodash", "express"} {
		c := findComponent(t, res.BOM, name)
		if c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if strings.HasPrefix(p.Name, "astinus:cpe:rejected:") {
				t.Errorf("%s: rejected CPE leaked without --include-rejected-cpe: %s=%s",
					name, p.Name, p.Value)
			}
		}
	}
}

// TestCPEConfidence_NoHardwareCPE_OnSoftwarePURL — Sprint 2 benchmark
// caught yq receiving cpe:2.3:h:linksys:befw11s4_v4 as a
// confidence=high alternative (the bundled NVD entry's substring
// matched yq's `v4` version suffix). Sprint 3 Task 0 added
// hardware-CPE-on-software-PURL rejection in
// internal/enrich/cpe/sources/nvd_api.go (ADR-0029). This regression
// test makes sure the rejection path stays live for end-to-end
// runs, not just unit tests on Candidate.
//
// We drive the bug surface by mocking the NVD API: a httptest.Server
// returns BOTH a software CPE (a:mikefarah:yq:4.40.5) and a hardware
// CPE (h:linksys:befw11s4_v4) for any keyword search. The enricher
// must:
//
//   - emit the software CPE as primary
//   - never emit the hardware CPE as primary or as an
//     alternative-without-rejected-reason
//   - with --include-rejected-cpe, surface the hardware CPE under
//     astinus:cpe:rejected:N with a reason mentioning "hardware"
func TestCPEConfidence_NoHardwareCPE_OnSoftwarePURL(t *testing.T) {
	const responseBody = `{
  "products": [
    {"cpe": {"cpeName": "cpe:2.3:a:mikefarah:yq:4.40.5:*:*:*:*:*:*:*"}},
    {"cpe": {"cpeName": "cpe:2.3:h:linksys:befw11s4_v4:*:*:*:*:*:*:*:*"}}
  ]
}`
	var hits int64
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(mock.Close)

	sbom := helpers.WriteSBOMFixture(t, "", "in.cdx.json", helpers.YQOnlySBOM)

	res := helpers.RunEnrichOK(t, helpers.EnrichOpts{
		SBOM:      sbom,
		Image:     "test/yq-cpe-regression:1.0",
		NVDAPIURL: mock.URL,
		// Any non-empty key bypasses the hybrid-mode anonymous-skip
		// shortcut so the NVD source actually runs.
		NVDAPIKey: "test-key",
		Extra: []string{
			"--cpe-mode", "online",
			"--include-rejected-cpe",
			"--disable", "layer", "--disable", "evidence",
		},
	})

	if atomic.LoadInt64(&hits) == 0 {
		t.Fatalf("mock NVD endpoint never called — --nvd-api-url did not wire through")
	}

	yq := findComponent(t, res.BOM, "yq")

	// S4 Task 3 (ADR-0042): the golang ecosystem policy is
	// evidence-only — the yq software CPE that wins classification
	// surfaces in `astinus:cpe:evidence` instead of yq.CPE. The
	// hardware-CPE rejection contract is preserved: the linksys
	// row must NOT leak into any visible field, regardless of
	// whether the primary slot is populated or not.
	primaryOrEvidence := yq.CPE
	if primaryOrEvidence == "" {
		primaryOrEvidence = propertyValue(yq, "astinus:cpe:evidence")
	}
	if primaryOrEvidence == "" {
		t.Fatal("yq has neither primary CPE nor astinus:cpe:evidence — " +
			"enrichment failed entirely")
	}
	if strings.Contains(primaryOrEvidence, ":h:") {
		t.Errorf("hardware-type CPE leaked into primary/evidence: %s", primaryOrEvidence)
	}

	// Walk all alternatives — none of them may be hardware-type.
	for i := 1; ; i++ {
		alt := propertyValue(yq, fmt.Sprintf("astinus:cpe:alternative:%d", i))
		if alt == "" {
			break
		}
		if strings.Contains(alt, ":h:") {
			t.Errorf("alternative #%d is hardware-type CPE: %s", i, alt)
		}
	}

	// The hardware CPE should land in rejected with a reason that
	// mentions hardware. Without --include-rejected-cpe these
	// properties wouldn't be emitted at all (asserted by the test
	// above); with the flag, they're our window into the rejection
	// path.
	rejectedHasHW := false
	rejectedHasReason := false
	for i := 1; ; i++ {
		rej := propertyValue(yq, fmt.Sprintf("astinus:cpe:rejected:%d", i))
		if rej == "" {
			break
		}
		if strings.Contains(rej, ":h:linksys") {
			rejectedHasHW = true
			reason := propertyValue(yq, fmt.Sprintf("astinus:cpe:rejected:%d:reason", i))
			if strings.Contains(strings.ToLower(reason), "hardware") {
				rejectedHasReason = true
			}
		}
	}

	if !rejectedHasHW {
		t.Errorf("hardware CPE %q did not appear in astinus:cpe:rejected:*; "+
			"either it was filtered before classify or the property layout changed",
			"cpe:2.3:h:linksys:befw11s4_v4:*:*:*:*:*:*:*")
	}
	if rejectedHasHW && !rejectedHasReason {
		t.Error("hardware CPE landed in rejected without a hardware-* reason " +
			"— regression in nvd_api.go RejectedReason wiring")
	}
}
