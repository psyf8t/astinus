package cpe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestEnricher_AlternativesCappedAtTen — S6 Task 5 defensive cap.
// A pathological input with 30 CPE candidates must NOT produce 30
// `astinus:cpe:alternative:N` properties on the output; capped at
// `maxAlternativesEmitted = 10`. The total seen count is preserved
// via `astinus:cpe:alternatives-count`. ADR-0062.
func TestEnricher_AlternativesCappedAtTen(t *testing.T) {
	const N = 30
	c := model.Component{
		Name:    "stress-test",
		Version: "1.0",
		PURL:    "pkg:apk/alpine/stress-test@1.0",
	}
	for i := 0; i < N; i++ {
		c.CPEs = append(c.CPEs,
			fmt.Sprintf("cpe:2.3:a:vendor%02d:product%02d:1.0:*:*:*:*:*:*:*", i, i))
	}
	sbom := &model.SBOM{Components: []model.Component{c}}

	e := NewWithResolver(stubResolver{}).WithTotalCap(0)
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	out := sbom.Components[0]

	var altCount int
	for k := range out.Properties {
		if strings.HasPrefix(k, "astinus:cpe:alternative:") &&
			!strings.Contains(k, ":source") &&
			!strings.Contains(k, ":confidence") {
			altCount++
		}
	}
	if altCount > maxAlternativesEmitted {
		t.Errorf("emitted %d alternatives, cap is %d", altCount, maxAlternativesEmitted)
	}
	if altCount == 0 {
		t.Error("zero alternatives emitted — cap shouldn't suppress everything")
	}
	got, _ := strconv.Atoi(out.Properties["astinus:cpe:alternatives-count"])
	if got < altCount {
		t.Errorf("alternatives-count = %d, want ≥ %d (the emitted altCount)",
			got, altCount)
	}
}

// TestEnricher_PreservesMultipleCPECandidates pins the operator-
// facing contract: a component arriving with N CPE candidates
// (from a CDX with multiple syft:cpe23 properties OR an
// Astinus-enriched SBOM with numeric astinus:cpe:K extras) should
// expose them all on the way out as alternatives. The busybox/
// ssl_client run-#4 case is the motivating example. ADR-0062.
func TestEnricher_PreservesMultipleCPECandidates(t *testing.T) {
	c := model.Component{
		Name:    "ssl_client",
		Version: "1.37.0-r30",
		PURL:    "pkg:apk/alpine/ssl_client@1.37.0-r30",
		CPEs: []string{
			"cpe:2.3:a:ssl_client:ssl_client:1.37.0-r30:*:*:*:*:*:*:*",
			"cpe:2.3:a:busybox:busybox:1.37.0-r30:*:*:*:*:*:*:*",
			"cpe:2.3:a:busybox:ssl_client:1.37.0-r30:*:*:*:*:*:*:*",
			"cpe:2.3:a:busybox:ssl-client:1.37.0-r30:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl-client:ssl-client:1.37.0-r30:*:*:*:*:*:*:*",
		},
	}
	sbom := &model.SBOM{Components: []model.Component{c}}

	e := NewWithResolver(stubResolver{}).WithTotalCap(0)
	if err := e.Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	out := sbom.Components[0]

	// One primary survives, the other 4 should land as
	// alternatives.
	if len(out.CPEs) != 1 {
		t.Errorf("expected exactly 1 primary CPE; got %d (%v)", len(out.CPEs), out.CPEs)
	}
	var alts []string
	for k, v := range out.Properties {
		if strings.HasPrefix(k, "astinus:cpe:alternative:") &&
			!strings.Contains(k, ":source") &&
			!strings.Contains(k, ":confidence") {
			alts = append(alts, v)
		}
	}
	if len(alts) < 4 {
		t.Errorf("preserved %d alternatives, want ≥ 4 (busybox + ssl-client + ssl_client variants)",
			len(alts))
	}

	// All 4 alt variants must be findable across primary + alts.
	have := map[string]bool{out.CPEs[0]: true}
	for _, a := range alts {
		have[a] = true
	}
	for _, fragment := range []string{
		"busybox:busybox",
		"busybox:ssl_client",
		"busybox:ssl-client",
		"ssl-client:ssl-client",
	} {
		seen := false
		for v := range have {
			if strings.Contains(v, fragment) {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("expected %q variant somewhere in CPEs; got %v", fragment, have)
		}
	}
}

// stubResolver returns no extra candidates so the test drives only
// the existing-CPE classification path.
type stubResolver struct{}

func (stubResolver) Resolve(_ PURL) []Candidate { return nil }
