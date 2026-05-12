package cpe

import (
	"context"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestStripVPrefix(t *testing.T) {
	cases := map[string]string{
		"v1.2.3":                             "1.2.3",
		"v1.0.0-rc1":                         "1.0.0-rc1",
		"v0.0.0-20231212003515-deadbeefcafe": "0.0.0-20231212003515-deadbeefcafe",
		"v28.5.2+incompatible":               "28.5.2+incompatible",
		"1.2.3":                              "1.2.3",
		"":                                   "",
		"(devel)":                            "(devel)",
		"vbroken-but-keep-passing-through":   "broken-but-keep-passing-through",
	}
	for in, want := range cases {
		if got := stripVPrefix(in); got != want {
			t.Errorf("stripVPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyVersionNormalization_StripsVPrefixInVersionSlotOnly(t *testing.T) {
	in := "cpe:2.3:a:go.uber.org:atomic:v1.11.0:*:*:*:*:*:*:*"
	out := applyVersionNormalization(in, stripVPrefix)
	want := "cpe:2.3:a:go.uber.org:atomic:1.11.0:*:*:*:*:*:*:*"
	if out != want {
		t.Errorf("normalised = %q, want %q", out, want)
	}
}

func TestApplyVersionNormalization_LeavesNonCPEAlone(t *testing.T) {
	in := "not-a-cpe-2.3:string"
	if got := applyVersionNormalization(in, stripVPrefix); got != in {
		t.Errorf("non-CPE input was rewritten: %q → %q", in, got)
	}
}

func TestCpeVendor(t *testing.T) {
	cases := map[string]string{
		"cpe:2.3:a:Go.Uber.Org:atomic:1.11.0:*:*:*:*:*:*:*": "go.uber.org",
		"cpe:2.3:a:foo:bar:1:*:*:*:*:*:*:*":                 "foo",
		"not-a-cpe":                                         "",
		"":                                                  "",
	}
	for in, want := range cases {
		if got := cpeVendor(in); got != want {
			t.Errorf("cpeVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesAnyVendor_CaseInsensitiveExact(t *testing.T) {
	rejects := []string{"go.uber.org", "k8s.io"}
	if !matchesAnyVendor("GO.UBER.ORG", rejects) {
		t.Error("should match (case-insensitive)")
	}
	if !matchesAnyVendor("k8s.io", rejects) {
		t.Error("should match exact")
	}
	if matchesAnyVendor("uber", rejects) {
		t.Error("should NOT match (substring)")
	}
	if matchesAnyVendor("k8s.io.malicious", rejects) {
		t.Error("should NOT match (longer string)")
	}
}

// TestEcosystemPolicy_GolangIsEvidenceOnly — a Go-module Component
// must not carry a primary CPE; the resolver's pick lands in
// `astinus:cpe:evidence` with the scope + rationale stamped.
func TestEcosystemPolicy_GolangIsEvidenceOnly(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "logrus",
		PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 0 {
		t.Errorf("golang component CPEs = %v, want empty under evidence-only policy", c.CPEs)
	}
	ev := c.Properties["astinus:cpe:evidence"]
	if ev == "" || !strings.HasPrefix(ev, "cpe:2.3:") {
		t.Errorf("evidence CPE = %q, want a CPE 2.3 URI", ev)
	}
	if scope := c.Properties["astinus:cpe:scope"]; scope != "evidence-only" {
		t.Errorf("astinus:cpe:scope = %q, want evidence-only", scope)
	}
	if rat := c.Properties["astinus:cpe:rationale"]; rat == "" {
		t.Errorf("astinus:cpe:rationale missing on evidence-only row")
	}
	// v-prefix in the evidence CPE version slot must be stripped: the
	// heuristic resolver produced `:v1.9.3:` and the policy normaliser
	// rewrote it to `:1.9.3:`.
	if strings.Contains(ev, ":v1.9.3:") {
		t.Errorf("v-prefix leaked in evidence CPE: %q", ev)
	}
}

// TestEcosystemPolicy_NpmEmitsPrimary — npm packages keep the primary
// CPE field populated; the policy isn't evidence-only for them.
func TestEcosystemPolicy_NpmEmitsPrimary(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "express",
		PURL: "pkg:npm/express@4.18.0",
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 1 {
		t.Errorf("npm primary CPE count = %d, want 1; CPEs = %v", len(c.CPEs), c.CPEs)
	}
	if c.Properties["astinus:cpe:scope"] == "evidence-only" {
		t.Error("npm policy should NOT be evidence-only")
	}
}

// TestEcosystemPolicy_RejectsModulePathVendors — the heuristic
// resolver fabricates `cpe:2.3:a:go.uber.org:atomic:...` for a
// Go-module PURL. The Golang policy's RejectVendors entry must drop
// it before Classify runs, so no CPE surfaces at all (primary OR
// evidence). The component still appears in the SBOM, just without
// a CPE breadcrumb pointing at a non-existent NVD entry.
func TestEcosystemPolicy_RejectsModulePathVendors(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "atomic",
		PURL: "pkg:golang/go.uber.org/atomic@v1.11.0",
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 0 {
		t.Errorf("rejected vendor leaked into c.CPEs: %v", c.CPEs)
	}
	ev := c.Properties["astinus:cpe:evidence"]
	if strings.Contains(ev, "go.uber.org") {
		t.Errorf("rejected vendor leaked into evidence CPE: %q", ev)
	}
}

// TestPolicyForEcosystem_FallsBackToDefault — an unknown ecosystem
// (e.g. `pkg:swift/...`) falls through to the default-policy entry.
func TestPolicyForEcosystem_FallsBackToDefault(t *testing.T) {
	policies := DefaultPolicies()
	p := policyForEcosystem(policies, "swift")
	if !p.EmitPrimary {
		t.Errorf("default policy should emit primary; got %+v", p)
	}
	if p.EvidenceOnly {
		t.Errorf("default policy should NOT be evidence-only")
	}
}

// TestPolicyForEcosystem_ReturnsNonNilOnEmptyMap — a deliberately
// empty policy map still produces a usable fallback policy so the
// enricher doesn't panic on a misconfigured override.
func TestPolicyForEcosystem_ReturnsNonNilOnEmptyMap(t *testing.T) {
	p := policyForEcosystem(map[string]*EcosystemPolicy{}, "golang")
	if p == nil {
		t.Fatal("nil policy returned for empty map")
	}
	if !p.EmitPrimary {
		t.Errorf("hard-coded fallback should emit primary; got %+v", p)
	}
}

// TestWithPolicies_OperatorOverride — exercises the public
// WithPolicies surface. An operator-supplied policy that flips
// golang back to emit-primary changes the enricher's behaviour.
func TestWithPolicies_OperatorOverride(t *testing.T) {
	override := DefaultPolicies()
	override["golang"] = &EcosystemPolicy{
		Ecosystem:        "golang",
		EmitPrimary:      true,
		EvidenceOnly:     false,
		NormalizeVersion: stripVPrefix,
	}
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "logrus",
		PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
	}}}
	if err := New().WithPolicies(override).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components[0].CPEs) != 1 {
		t.Errorf("override should restore primary; got CPEs = %v", sbom.Components[0].CPEs)
	}
	if strings.Contains(sbom.Components[0].CPEs[0], ":v1.9.3:") {
		t.Errorf("v-prefix should still be normalised under override; got %q",
			sbom.Components[0].CPEs[0])
	}
}
