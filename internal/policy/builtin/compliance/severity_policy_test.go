package compliance

import (
	"testing"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestDefaultPolicy_NTIASupplier_NPM — the canonical S3-Task-2 fix:
// npm packages used to be stamped SeverityMedium for missing
// supplier; the new policy downgrades to SeverityInfo so security
// teams aren't drowned in noise.
func TestDefaultPolicy_NTIASupplier_NPM(t *testing.T) {
	p := DefaultSeverityPolicy()
	c := &model.Component{
		Name: "lodash",
		Type: model.ComponentTypeLibrary,
		PURL: "pkg:npm/lodash@4.17.21",
	}
	sev, _, ok := p.Severity("NTIA-SUPPLIER", c)
	if !ok {
		t.Fatal("no policy match for NTIA-SUPPLIER on npm; default rules broken")
	}
	if sev != policy.SeverityInfo {
		t.Errorf("npm NTIA-SUPPLIER severity = %v, want SeverityInfo", sev)
	}
}

// TestDefaultPolicy_NTIASupplier_FileType — files have no NTIA-
// supplier semantics; policy must yield SeverityIgnored so the
// finding never lands in output.
func TestDefaultPolicy_NTIASupplier_FileType(t *testing.T) {
	p := DefaultSeverityPolicy()
	c := &model.Component{
		Name: "/etc/passwd",
		Type: model.ComponentTypeFile,
	}
	sev, _, ok := p.Severity("NTIA-SUPPLIER", c)
	if !ok {
		t.Fatal("no policy match for file-type NTIA-SUPPLIER")
	}
	if sev != policy.SeverityIgnored {
		t.Errorf("file NTIA-SUPPLIER severity = %v, want SeverityIgnored", sev)
	}
}

// TestDefaultPolicy_NTIAVersion_Application — applications without
// version are unscannable, so the policy escalates them to critical.
func TestDefaultPolicy_NTIAVersion_Application(t *testing.T) {
	p := DefaultSeverityPolicy()
	c := &model.Component{
		Name: "myapp",
		Type: model.ComponentTypeApplication,
	}
	sev, _, ok := p.Severity("NTIA-VERSION", c)
	if !ok {
		t.Fatal("no policy match for application NTIA-VERSION")
	}
	if sev != policy.SeverityCritical {
		t.Errorf("application NTIA-VERSION severity = %v, want SeverityCritical", sev)
	}
}

// TestDefaultPolicy_PerEcosystemTable spot-checks the rest of the
// per-ecosystem severity matrix so a future edit to defaultRules()
// can't silently regress the noise reduction.
func TestDefaultPolicy_PerEcosystemTable(t *testing.T) {
	p := DefaultSeverityPolicy()
	cases := []struct {
		name      string
		ruleID    string
		comp      *model.Component
		wantSev   policy.Severity
		wantMatch bool
	}{
		{"pypi NTIA-SUPPLIER", "NTIA-SUPPLIER",
			&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:pypi/django@5.0"},
			policy.SeverityInfo, true},
		{"deb NTIA-SUPPLIER", "NTIA-SUPPLIER",
			&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:deb/debian/curl@8"},
			policy.SeverityInfo, true},
		{"maven NTIA-SUPPLIER", "NTIA-SUPPLIER",
			&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:maven/org.example/foo@1"},
			policy.SeverityLow, true},
		{"golang NTIA-SUPPLIER", "NTIA-SUPPLIER",
			&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:golang/github.com/x/y@v1"},
			policy.SeverityMedium, true},
		{"file NTIA-VERSION", "NTIA-VERSION",
			&model.Component{Type: model.ComponentTypeFile},
			policy.SeverityIgnored, true},
		{"file NTIA-IDENTIFIER", "NTIA-IDENTIFIER",
			&model.Component{Type: model.ComponentTypeFile},
			policy.SeverityIgnored, true},
		{"file SPDX-LICENSE-NOASSERTION", "SPDX-LICENSE-NOASSERTION",
			&model.Component{Type: model.ComponentTypeFile},
			policy.SeverityIgnored, true},
		{"app NTIA-SUPPLIER", "NTIA-SUPPLIER",
			&model.Component{Type: model.ComponentTypeApplication, PURL: "pkg:rare/whatever@1"},
			policy.SeverityHigh, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sev, _, ok := p.Severity(c.ruleID, c.comp)
			if ok != c.wantMatch {
				t.Errorf("matched = %v, want %v", ok, c.wantMatch)
			}
			if sev != c.wantSev {
				t.Errorf("severity = %v, want %v", sev, c.wantSev)
			}
		})
	}
}

// TestPolicy_UnknownRuleIDReturnsUnmatched — a custom validator with
// a RuleID the bundled policy doesn't know about MUST keep its
// caller-emitted severity. The policy returns matched=false so the
// compliance enricher leaves Severity untouched.
func TestPolicy_UnknownRuleIDReturnsUnmatched(t *testing.T) {
	p := DefaultSeverityPolicy()
	_, _, ok := p.Severity("CUSTOM-RULE-FROM-OPERATOR-VALIDATOR",
		&model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:npm/x@1"})
	if ok {
		t.Errorf("unknown RuleID should not match policy; preserves operator severity")
	}
}

// TestPolicy_NilComponent — SBOM-level findings have no Component;
// only RuleID-only rules match.
func TestPolicy_NilComponent(t *testing.T) {
	p := DefaultSeverityPolicy()
	sev, _, ok := p.Severity("NTIA-METADATA-AUTHOR", nil)
	if !ok {
		t.Fatal("metadata-level NTIA rule should match nil component")
	}
	if sev != policy.SeverityHigh {
		t.Errorf("severity = %v, want SeverityHigh", sev)
	}
}

// TestWithOverrides_BeatsDefault — operator override (last in the
// rule slice) wins over the bundled default.
func TestWithOverrides_BeatsDefault(t *testing.T) {
	p := DefaultSeverityPolicy().WithOverrides(SeverityRule{
		RuleID: "NTIA-SUPPLIER", Ecosystem: "npm",
		Severity: policy.SeverityLow,
		Reason:   "operator override for npm",
	})
	c := &model.Component{Type: model.ComponentTypeLibrary, PURL: "pkg:npm/lodash@1"}
	sev, reason, _ := p.Severity("NTIA-SUPPLIER", c)
	if sev != policy.SeverityLow {
		t.Errorf("override severity = %v, want SeverityLow", sev)
	}
	if reason != "operator override for npm" {
		t.Errorf("override reason = %q", reason)
	}
}

func TestEcosystemFromPURL(t *testing.T) {
	cases := map[string]string{
		"":                                   "",
		"not-a-purl":                         "",
		"pkg:npm/lodash@1":                   "npm",
		"pkg:NPM/lodash@1":                   "npm",
		"pkg:golang/github.com/x/y@v1":       "golang",
		"pkg:maven/org.example/foo@1?type=2": "maven",
		"pkg:deb":                            "deb",
	}
	for in, want := range cases {
		if got := ecosystemFromPURL(in); got != want {
			t.Errorf("ecosystemFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNilPolicy_ReturnsInfoUnmatched(t *testing.T) {
	var p *SeverityPolicy
	sev, _, ok := p.Severity("X", nil)
	if ok {
		t.Errorf("nil policy should report unmatched")
	}
	if sev != policy.SeverityInfo {
		t.Errorf("nil policy severity = %v", sev)
	}
}
