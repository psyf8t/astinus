package pathclassifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultParses(t *testing.T) {
	rules, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("default rules are empty")
	}

	// Sanity: every default rule has a recognised action and a
	// non-empty pattern + name.
	for _, r := range rules {
		if r.Name == "" {
			t.Errorf("rule has no name: %+v", r)
		}
		if !knownAction(r.Action) {
			t.Errorf("rule %q has unknown action %q", r.Name, r.Action)
		}
		if len(r.Pattern.Values) == 0 {
			t.Errorf("rule %q has no pattern values", r.Name)
		}
	}
}

func TestLoadDefaultCompilesViaNew(t *testing.T) {
	rules, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(rules); err != nil {
		t.Fatalf("default rules failed to compile: %v", err)
	}
}

func TestLoadEmptyData(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Fatal("expected error for nil data")
	}
	if _, err := Load([]byte{}); err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	if _, err := Load([]byte("not: a: valid: yaml")); err == nil {
		t.Fatal("expected YAML parse error")
	}
}

func TestLoadUnsupportedVersion(t *testing.T) {
	if _, err := Load([]byte("version: 99\nrules: []")); err == nil {
		t.Fatal("expected unsupported-version error")
	}
}

func TestLoadDuplicateRuleName(t *testing.T) {
	body := []byte(`
version: 1
rules:
  - name: dup
    action: skip
    pattern: {type: prefix, values: [/a/]}
    rationale: a
  - name: dup
    action: skip
    pattern: {type: prefix, values: [/b/]}
    rationale: b
`)
	if _, err := Load(body); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

func TestLoadRuleWithoutName(t *testing.T) {
	body := []byte(`
version: 1
rules:
  - action: skip
    pattern: {type: prefix, values: [/a/]}
    rationale: r
`)
	if _, err := Load(body); err == nil {
		t.Fatal("expected no-name error")
	}
}

func TestLoadUnknownAction(t *testing.T) {
	body := []byte(`
version: 1
rules:
  - name: x
    action: explode
    pattern: {type: prefix, values: [/a/]}
    rationale: r
`)
	if _, err := Load(body); err == nil {
		t.Fatal("expected unknown-action error")
	}
}

func TestLoadFromPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	body := []byte(`
version: 1
rules:
  - name: test
    action: skip
    pattern: {type: prefix, values: [/x/]}
    rationale: r
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("LoadFromPath: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "test" {
		t.Errorf("unexpected rules: %+v", rules)
	}
}

func TestLoadFromPathMissingFile(t *testing.T) {
	if _, err := LoadFromPath("/no/such/file.yaml"); err == nil {
		t.Fatal("expected read error")
	}
}

// ─── Merge ─────────────────────────────────────────────────────────

func TestMergeOverridesByName(t *testing.T) {
	defaults := []Rule{
		{Name: "x11-locale", Action: ActionSkip,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/share/X11/locale/"}}},
		{Name: "zoneinfo", Action: ActionSkip,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/share/zoneinfo/"}}},
	}
	custom := []Rule{
		{Name: "x11-locale", Action: ActionMarkAsNoise,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/share/X11/locale/"}}},
		{Name: "custom-internal", Action: ActionSkip,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/opt/internal/"}}},
	}

	merged := Merge(defaults, custom)

	if len(merged) != 3 {
		t.Fatalf("len(merged) = %d, want 3", len(merged))
	}
	// x11-locale should be the custom one (overridden).
	if found := findRule(merged, "x11-locale"); found == nil {
		t.Fatal("x11-locale missing from merged")
	} else if found.Action != ActionMarkAsNoise {
		t.Errorf("x11-locale Action = %q, want mark_as_noise (custom override)", found.Action)
	}
	// zoneinfo should be unchanged.
	if findRule(merged, "zoneinfo") == nil {
		t.Error("zoneinfo missing from merged")
	}
	// custom-internal should be appended.
	if findRule(merged, "custom-internal") == nil {
		t.Error("custom-internal missing from merged")
	}
}

func TestMergeNoCustom(t *testing.T) {
	defaults := []Rule{{
		Name: "x", Action: ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: []string{"/x/"}},
	}}
	merged := Merge(defaults, nil)
	if len(merged) != 1 {
		t.Errorf("len(merged) = %d, want 1", len(merged))
	}
	// Mutate the returned slice and verify defaults isn't affected
	// (Merge must return a fresh allocation).
	merged[0].Name = "mutated"
	if defaults[0].Name == "mutated" {
		t.Error("Merge must return a fresh slice")
	}
}

func TestMergePreservesOrder(t *testing.T) {
	defaults := []Rule{
		{Name: "a", Action: ActionSkip, Pattern: Pattern{Type: PatternPrefix, Values: []string{"/a/"}}},
		{Name: "b", Action: ActionSkip, Pattern: Pattern{Type: PatternPrefix, Values: []string{"/b/"}}},
		{Name: "c", Action: ActionSkip, Pattern: Pattern{Type: PatternPrefix, Values: []string{"/c/"}}},
	}
	custom := []Rule{
		{Name: "b", Action: ActionMarkAsNoise, Pattern: Pattern{Type: PatternPrefix, Values: []string{"/b/"}}},
	}
	merged := Merge(defaults, custom)
	gotNames := make([]string, len(merged))
	for i, r := range merged {
		gotNames[i] = r.Name
	}
	if got := strings.Join(gotNames, ","); got != "a,b,c" {
		t.Errorf("order = %q, want a,b,c", got)
	}
}

// findRule is a test helper.
func findRule(rules []Rule, name string) *Rule {
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i]
		}
	}
	return nil
}

// ─── Golden corpus: real-world paths through default rules ──────────

func TestDefaultRulesGoldenCorpus(t *testing.T) {
	rules, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path       string
		wantAction Action
		wantRule   string
	}{
		{"/usr/share/X11/locale/en_US/Compose", ActionSkip, "x11-locale"},
		{"/usr/share/X11/locale/iso8859-1/XLC_LOCALE", ActionSkip, "x11-locale"},
		{"/usr/lib/aarch64-linux-gnu/perl-base/unicore/lib/Sc/Hira.pl",
			ActionSkip, "perl-unicore"},
		{"/etc/apt/apt.conf.d/01autoremove", ActionSkip, "apt-config"},
		{"/etc/pam.d/login", ActionSkip, "pam-config"},
		{"/var/lib/dpkg/info/foo.list", ActionSkip, "dpkg-state"},
		{"/usr/share/man/man1/ls.1.gz", ActionSkip, "man-pages"},
		{"/usr/share/doc/libssl/copyright", ActionSkip, "doc-dirs"},
		{"/usr/share/zoneinfo/America/New_York", ActionSkip, "zoneinfo"},
		{"/usr/share/locale/de/LC_MESSAGES/coreutils.mo", ActionSkip, "locale-data"},
		{"/path/to/LICENSE", ActionSkip, "package-metadata-files"},
		{"/usr/include/stdio.h", ActionSkip, "c-cpp-sources"},
		{"/build/foo.o", ActionSkip, "build-artifacts"},
		{"/usr/lib/python3/site-packages/x.pyc", ActionSkip, "python-bytecode"},
		// Use a basename WITHOUT `.test` so the cheap `test-suffix`
		// rule does not pre-empt the regex (first matching dispatch
		// step wins; suffix matching is cheaper than regex and runs
		// first). The `extracted-source-tests` rule still fires for
		// every file under tests/ that doesn't end in .test/.spec.
		{"/opt/extracted/sqlite-3.44/test/fixture.dat",
			ActionRedundantUnderArchive, "extracted-source-tests"},
		{"/usr/local/bin/myapp", "", ""}, // no rule should match
		{"/opt/myorg/server", "", ""},    // no rule should match
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			d := c.Classify(tc.path)
			if d.Action != tc.wantAction {
				t.Errorf("Action = %q, want %q (rule = %q)", d.Action, tc.wantAction, d.RuleName)
			}
			if tc.wantRule != "" && d.RuleName != tc.wantRule {
				t.Errorf("RuleName = %q, want %q", d.RuleName, tc.wantRule)
			}
		})
	}
}
