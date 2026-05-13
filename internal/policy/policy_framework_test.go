package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// makePolicy is a tiny builder so per-test fixtures stay concise.
func makePolicy(rules ...Rule) *Policy {
	return &Policy{Version: "1", Name: "test", Rules: rules}
}

// TestMatchComponent_PURLGlob exercises the glob-style purl_matches
// matcher. Empty PURL on the component fails any non-empty pattern.
func TestMatchComponent_PURLGlob(t *testing.T) {
	cases := []struct {
		pattern, purl string
		want          bool
	}{
		{"pkg:apk/alpine/*", "pkg:apk/alpine/curl", true},
		{"pkg:apk/alpine/*", "pkg:npm/express", false},
		{"pkg:npm/*", "pkg:npm/lodash", true},
		// `*` doesn't match across slashes in filepath.Match
		// semantics — operator-facing the convention is "use
		// multiple patterns or rely on prefix".
		{"pkg:apk/*", "pkg:apk/alpine/curl", false},
		{"", "pkg:apk/alpine/curl", true}, // empty pattern = no constraint
	}
	for _, c := range cases {
		got := matchComponent(&ComponentMatcher{PURLMatches: c.pattern},
			&Component{PURL: c.purl})
		if got != c.want {
			t.Errorf("matchComponent(purl=%q, pattern=%q) = %v, want %v",
				c.purl, c.pattern, got, c.want)
		}
	}
}

func TestMatchComponent_Ecosystem(t *testing.T) {
	cases := []struct {
		eco, purl string
		want      bool
	}{
		{"apk", "pkg:apk/alpine/curl", true},
		{"APK", "pkg:apk/alpine/curl", true}, // case-insensitive
		{"npm", "pkg:apk/alpine/curl", false},
		{"apk", "", false},
		{"apk", "not-a-purl", false},
	}
	for _, c := range cases {
		got := matchComponent(&ComponentMatcher{Ecosystem: c.eco},
			&Component{PURL: c.purl})
		if got != c.want {
			t.Errorf("matchComponent(eco=%q, purl=%q) = %v, want %v",
				c.eco, c.purl, got, c.want)
		}
	}
}

func TestMatchComponent_VersionBelow(t *testing.T) {
	cases := []struct {
		ceiling, version string
		want             bool
	}{
		{"2.0.0", "1.9.0", true},
		{"2.0.0", "2.0.0", false},
		{"2.0.0", "2.1.0", false},
		// Empty component version skips the check.
		{"2.0.0", "", true},
	}
	for _, c := range cases {
		got := matchComponent(&ComponentMatcher{VersionBelow: c.ceiling},
			&Component{Version: c.version})
		if got != c.want {
			t.Errorf("matchComponent(ceiling=%q, version=%q) = %v, want %v",
				c.ceiling, c.version, got, c.want)
		}
	}
}

func TestMatchComponent_HasProperty(t *testing.T) {
	got := matchComponent(
		&ComponentMatcher{HasProperty: &PropertyMatcher{
			Name: "astinus:origin", Value: "base",
		}},
		&Component{Properties: map[string]string{
			"astinus:origin": "base",
			"unrelated":      "x",
		}},
	)
	if !got {
		t.Error("matching property should pass")
	}
	got = matchComponent(
		&ComponentMatcher{HasProperty: &PropertyMatcher{
			Name: "astinus:origin", Value: "application",
		}},
		&Component{Properties: map[string]string{
			"astinus:origin": "base",
		}},
	)
	if got {
		t.Error("non-matching property should fail")
	}
	got = matchComponent(
		&ComponentMatcher{HasProperty: &PropertyMatcher{Name: "x", Value: "y"}},
		&Component{Properties: nil},
	)
	if got {
		t.Error("nil properties on component should fail HasProperty")
	}
}

func TestMatchFinding_IDPrefix(t *testing.T) {
	cases := []struct {
		prefix, ruleID string
		want           bool
	}{
		{"CVE-", "CVE-2024-12345", true},
		{"CVE-", "NTIA-VERSION", false},
		{"", "anything", true},
	}
	for _, c := range cases {
		got := matchFinding(&FindingMatcher{IDPrefix: c.prefix},
			&Finding{RuleID: c.ruleID})
		if got != c.want {
			t.Errorf("matchFinding(prefix=%q, ruleID=%q) = %v", c.prefix, c.ruleID, got)
		}
	}
}

func TestMatchFinding_Severity(t *testing.T) {
	got := matchFinding(&FindingMatcher{Severity: "high"},
		&Finding{Severity: SeverityHigh})
	if !got {
		t.Error("high vs high should match")
	}
	got = matchFinding(&FindingMatcher{Severity: "HIGH"},
		&Finding{Severity: SeverityHigh})
	if !got {
		t.Error("severity match should be case-insensitive")
	}
	got = matchFinding(&FindingMatcher{Severity: "high"},
		&Finding{Severity: SeverityMedium})
	if got {
		t.Error("severity mismatch should fail")
	}
}

func TestMatchWhen_Composition(t *testing.T) {
	c := &Component{PURL: "pkg:apk/alpine/curl", Version: "8.5.0"}
	w := &When{
		All: []When{
			{Component: &ComponentMatcher{Ecosystem: "apk"}},
			{Component: &ComponentMatcher{VersionBelow: "9.0.0"}},
		},
	}
	if !matchWhen(w, EvalContext{Component: c}) {
		t.Error("all-true composition should match")
	}

	w = &When{
		Any: []When{
			{Component: &ComponentMatcher{Ecosystem: "npm"}},
			{Component: &ComponentMatcher{Ecosystem: "apk"}},
		},
	}
	if !matchWhen(w, EvalContext{Component: c}) {
		t.Error("any-with-one-true composition should match")
	}

	w = &When{
		Not: &When{Component: &ComponentMatcher{Ecosystem: "npm"}},
	}
	if !matchWhen(w, EvalContext{Component: c}) {
		t.Error("not(npm) on apk component should match")
	}
}

func TestPolicy_Evaluate_DenyRule(t *testing.T) {
	p := makePolicy(Rule{
		ID: "deny-old-log4j",
		When: When{
			Component: &ComponentMatcher{
				PURLMatches:  "pkg:maven/org.apache.logging.log4j/log4j-core@*",
				VersionBelow: "2.17.0",
			},
		},
		Action: Action{Type: ActionDeny, Message: "log4j < 2.17.0 forbidden"},
	})
	c := &Component{
		PURL:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		Version: "2.14.1",
	}
	decisions := p.Evaluate(EvalContext{Component: c})
	if len(decisions) != 1 || decisions[0].Action != ActionDeny {
		t.Errorf("decisions = %+v, want one deny", decisions)
	}
	// Above the ceiling: no decision.
	c.Version = "2.18.0"
	if got := p.Evaluate(EvalContext{Component: c}); len(got) != 0 {
		t.Errorf("got %d decisions on safe version, want 0", len(got))
	}
}

func TestPolicy_Evaluate_AllowOnBaseOrigin(t *testing.T) {
	p := makePolicy(Rule{
		ID: "allow-base-critical",
		When: When{
			All: []When{
				{Finding: &FindingMatcher{IDPrefix: "CVE-", Severity: "critical"}},
				{Component: &ComponentMatcher{HasProperty: &PropertyMatcher{
					Name: "astinus:origin", Value: "base",
				}}},
			},
		},
		Action: Action{Type: ActionAllow, Message: "vendor responsibility"},
	})
	c := &Component{
		PURL: "pkg:apk/alpine/openssl",
		Properties: map[string]string{
			"astinus:origin": "base",
		},
	}
	f := &Finding{
		Severity: SeverityCritical,
		RuleID:   "CVE-2024-12345",
	}
	decisions := p.Evaluate(EvalContext{Component: c, Finding: f})
	if len(decisions) != 1 || decisions[0].Action != ActionAllow {
		t.Errorf("decisions = %+v, want one allow", decisions)
	}
}

func TestLoadFile_StrictRejectsUnknownKeys(t *testing.T) {
	body := `version: "1"
name: test
rules:
  - id: r1
    bogus_key: value  # unknown
    when: {}
    action: { type: deny }`
	path := writeTempYAML(t, body)
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error on unknown key, got nil")
	}
}

func TestLoadFile_RejectsInvalidAction(t *testing.T) {
	body := `version: "1"
name: test
rules:
  - id: r1
    when: {}
    action: { type: explode }`
	path := writeTempYAML(t, body)
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error on invalid action, got nil")
	}
}

func TestLoadFile_RejectsBadVersion(t *testing.T) {
	body := `version: "999"
name: test
rules: []`
	path := writeTempYAML(t, body)
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error on unsupported version")
	}
}

func TestLoadFile_RejectsDuplicateRuleID(t *testing.T) {
	body := `version: "1"
name: test
rules:
  - id: dup
    when: {}
    action: { type: deny }
  - id: dup
    when: {}
    action: { type: allow }`
	path := writeTempYAML(t, body)
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error on duplicate rule ID")
	}
}

func TestLoadFile_ValidPolicy(t *testing.T) {
	body := `version: "1"
name: "Test Policy"
description: "Sanity check"
rules:
  - id: deny-old-log4j
    when:
      component:
        purl_matches: "pkg:maven/org.apache.logging.log4j/log4j-core@*"
        version_below: "2.17.0"
    action:
      type: deny
      message: "log4j-core < 2.17.0 is denied"
  - id: allow-base-criticals
    when:
      all:
        - finding: { id_prefix: "CVE-", severity: "critical" }
        - component:
            has_property:
              name: "astinus:origin"
              value: "base"
    action:
      type: allow
      message: "vendor responsibility"`
	path := writeTempYAML(t, body)
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Name != "Test Policy" {
		t.Errorf("Name = %q", p.Name)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(p.Rules))
	}
	if p.SourcePath != path {
		t.Errorf("SourcePath = %q, want %q", p.SourcePath, path)
	}
}

func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
