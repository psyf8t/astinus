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

// ─── S5 Task 0: stdlib exception (ADR-0047) ───────────────────────────

// TestStdlibPolicyException_KeepsPrimaryCPE — the Go stdlib has 351
// CPE-aliased entries in NVD under vendor=golang, product=go. The
// over-broad ADR-0042 golang demotion swallowed `cpe:2.3:a:golang:go:*`
// alongside module-path CPEs, costing 22 Grype matches on a real
// Grafana benchmark. The KeepPrimaryPurls exception (ADR-0047)
// restores the primary CPE for `pkg:golang/stdlib` while every
// other golang PURL stays evidence-only.
func TestStdlibPolicyException_KeepsPrimaryCPE(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "stdlib",
		Version: "1.25.9",
		PURL:    "pkg:golang/stdlib@1.25.9",
		CPEs:    []string{"cpe:2.3:a:golang:go:1.25.9:-:*:*:*:*:*:*"},
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 1 {
		t.Fatalf("primary CPE missing on stdlib component; got CPEs=%v", c.CPEs)
	}
	if !strings.Contains(c.CPEs[0], ":a:golang:go:") {
		t.Errorf("primary CPE = %q, want vendor=golang product=go", c.CPEs[0])
	}
	if got := c.Properties["astinus:cpe:exception-applied"]; got != "keep-primary" {
		t.Errorf("astinus:cpe:exception-applied = %q, want keep-primary", got)
	}
	if got := c.Properties["astinus:cpe:exception-rationale"]; got == "" {
		t.Errorf("astinus:cpe:exception-rationale missing on exception path")
	}
	// scope=evidence-only is the marker for the demotion path; it
	// must NOT appear on the exception path even though the
	// ecosystem default would have demoted.
	if got := c.Properties["astinus:cpe:scope"]; got == "evidence-only" {
		t.Errorf("astinus:cpe:scope = evidence-only — exception failed to override")
	}
}

// TestNonStdlibGolangPolicyUnchanged — the exception MUST NOT leak.
// A non-stdlib golang PURL whose vendor isn't on the reject list
// (so it reaches the primary-classification branch) stays
// evidence-only. Pins that the narrow scope of ADR-0047 doesn't
// accidentally widen to other module-path rows.
//
// `github.com/sirupsen/logrus` is the canonical case: the
// heuristic resolver fabricates vendor=product=logrus, which is
// NOT in RejectVendors, so primary classification produces a
// candidate. The S4 Task 3 evidence-only policy then demotes it
// to `astinus:cpe:evidence` + `astinus:cpe:scope = evidence-only`,
// and ADR-0047 leaves that demotion untouched.
func TestNonStdlibGolangPolicyUnchanged(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "logrus",
		Version: "1.9.3",
		PURL:    "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 0 {
		t.Errorf("non-stdlib golang primary CPEs = %v, want empty (evidence-only path)", c.CPEs)
	}
	if got := c.Properties["astinus:cpe:exception-applied"]; got != "" {
		t.Errorf("astinus:cpe:exception-applied = %q, want empty on non-stdlib row", got)
	}
	if got := c.Properties["astinus:cpe:scope"]; got != "evidence-only" {
		t.Errorf("astinus:cpe:scope = %q, want evidence-only", got)
	}
}

// TestRejectVendorsStillReject — the exception MUST NOT widen to
// rescue policy-rejected vendors. A `go.uber.org/atomic` PURL has
// its heuristic CPE (`vendor=go.uber.org`) dropped before
// classification by RejectVendors, so no primary candidate ever
// exists and the row falls into the no-match branch — unchanged
// from the pre-ADR-0047 contract.
func TestRejectVendorsStillReject(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "atomic",
		Version: "1.11.0",
		PURL:    "pkg:golang/go.uber.org/atomic@1.11.0",
	}}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	c := sbom.Components[0]
	if len(c.CPEs) != 0 {
		t.Errorf("rejected-vendor primary CPEs = %v, want empty", c.CPEs)
	}
	if got := c.Properties["astinus:cpe:exception-applied"]; got != "" {
		t.Errorf("exception-applied = %q on rejected-vendor row — exception widened", got)
	}
	if got := c.Properties["astinus:cpe:lookup"]; got != "no-match" {
		t.Errorf("astinus:cpe:lookup = %q, want no-match (rejected vendor produced no candidates)", got)
	}
}

// TestMatchesKeepPrimary pins the helper directly. Exact match
// (with or without version suffix), prefix glob (`pkg:golang/cmd/*`
// for future stdlib-toolchain coverage), and negative cases.
func TestMatchesKeepPrimary(t *testing.T) {
	patterns := []string{"pkg:golang/stdlib", "pkg:golang/cmd/*"}
	cases := []struct {
		purl string
		want bool
	}{
		{"pkg:golang/stdlib@1.25.9", true},
		{"pkg:golang/stdlib@go1.26.0", true},
		{"pkg:golang/stdlib", true},               // versionless
		{"pkg:golang/stdlib?qual=x", true},        // qualifier-only
		{"pkg:golang/stdlib@1.25.9?qual=x", true}, // version + qualifier
		{"pkg:golang/cmd/go@1.25.9", true},        // prefix glob
		{"pkg:golang/cmd/compile@1.25.9", true},
		// `pkg:golang/cmd@1.25.9` is OUTSIDE the `pkg:golang/cmd/*`
		// glob — the trailing `/` in the trimmed prefix means parent
		// directories don't match, only children. Intended.
		{"pkg:golang/cmd@1.25.9", false},
		{"pkg:golang/go.uber.org/atomic@1.11.0", false},
		{"pkg:golang/k8s.io/api@0.35.3", false},
		{"pkg:npm/lodash@4.17.21", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := matchesKeepPrimary(tc.purl, patterns); got != tc.want {
			t.Errorf("matchesKeepPrimary(%q) = %v, want %v", tc.purl, got, tc.want)
		}
	}
}

// TestMatchesKeepPrimary_EmptyPatterns — defensive: nil / empty
// pattern list short-circuits to false without iterating.
func TestMatchesKeepPrimary_EmptyPatterns(t *testing.T) {
	if matchesKeepPrimary("pkg:golang/stdlib@1.25.9", nil) {
		t.Error("nil pattern list should yield false")
	}
	if matchesKeepPrimary("pkg:golang/stdlib@1.25.9", []string{}) {
		t.Error("empty pattern list should yield false")
	}
	if matchesKeepPrimary("pkg:golang/stdlib@1.25.9", []string{""}) {
		t.Error("empty-string pattern entry should not match anything")
	}
}

// TestStdlibException_IsInDefaultPolicy is a smoke test against the
// bundled DefaultPolicies — if a future edit removes the stdlib
// entry by accident, this trips immediately.
func TestStdlibException_IsInDefaultPolicy(t *testing.T) {
	policies := DefaultPolicies()
	golang := policies["golang"]
	if golang == nil {
		t.Fatal("DefaultPolicies missing golang entry")
	}
	if !matchesKeepPrimary("pkg:golang/stdlib@1.25.9", golang.KeepPrimaryPurls) {
		t.Errorf("DefaultPolicies golang.KeepPrimaryPurls = %v, want at least pkg:golang/stdlib",
			golang.KeepPrimaryPurls)
	}
	if golang.KeepPrimaryRationale == "" {
		t.Error("DefaultPolicies golang.KeepPrimaryRationale must be non-empty for audit")
	}
}
