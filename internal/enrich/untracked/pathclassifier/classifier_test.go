package pathclassifier

import (
	"strings"
	"testing"
)

// ─── New / construction ─────────────────────────────────────────────

func TestNewEmptyRules(t *testing.T) {
	c, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if d := c.Classify("/usr/bin/foo"); d.Action != "" {
		t.Errorf("empty rule set must yield empty Decision, got %+v", d)
	}
}

func TestNewRejectsEmptyValues(t *testing.T) {
	_, err := New([]Rule{{
		Name:    "broken",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: nil},
	}})
	if err == nil {
		t.Fatal("expected error for empty pattern.values")
	}
}

func TestNewRejectsUnknownPatternType(t *testing.T) {
	_, err := New([]Rule{{
		Name:    "broken",
		Action:  ActionSkip,
		Pattern: Pattern{Type: "made-up", Values: []string{"x"}},
	}})
	if err == nil {
		t.Fatal("expected error for unknown pattern type")
	}
}

func TestNewRejectsBadRegex(t *testing.T) {
	_, err := New([]Rule{{
		Name:    "broken",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternRegex, Values: []string{"["}},
	}})
	if err == nil {
		t.Fatal("expected error for bad regex")
	}
}

func TestNewRejectsBadGlob(t *testing.T) {
	_, err := New([]Rule{{
		Name:    "broken",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternGlob, Values: []string{"a[b"}},
	}})
	if err == nil {
		t.Fatal("expected error for bad glob")
	}
}

func TestNewDefaultsConfidenceTo1(t *testing.T) {
	c, err := New([]Rule{{
		Name:    "x",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: []string{"/x/"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	d := c.Classify("/x/y")
	if d.Confidence != 1.0 {
		t.Errorf("Confidence = %v, want 1.0", d.Confidence)
	}
}

// ─── Per-pattern-type matching ──────────────────────────────────────

func TestClassifyPrefixMatch(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "zoneinfo",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/share/zoneinfo/"}},
	}})
	cases := []struct {
		path string
		hit  bool
	}{
		{"/usr/share/zoneinfo/America/New_York", true},
		{"/usr/share/zoneinfo/UTC", true},
		{"/usr/share/zoneinfo/", true},
		{"/usr/local/bin/foo", false},
		{"/usr/share/zoneinfo", false}, // no trailing slash → no match
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			d := c.Classify(tc.path)
			gotHit := d.Action != ""
			if gotHit != tc.hit {
				t.Errorf("hit = %v, want %v (decision: %+v)", gotHit, tc.hit, d)
			}
		})
	}
}

func TestClassifyPrefixLongestWins(t *testing.T) {
	rules := []Rule{
		{Name: "generic", Action: ActionSkip,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/"}}},
		{Name: "specific", Action: ActionMarkAsNoise,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/usr/share/locale/"}}},
	}
	c, _ := New(rules)
	d := c.Classify("/usr/share/locale/de/LC_MESSAGES/foo.mo")
	if d.RuleName != "specific" {
		t.Errorf("RuleName = %q, want specific (longest match wins)", d.RuleName)
	}
	if d.Action != ActionMarkAsNoise {
		t.Errorf("Action = %q, want mark_as_noise", d.Action)
	}
}

func TestClassifySuffixMatch(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "src",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternSuffix, Values: []string{".c", ".h"}},
	}})
	if c.Classify("/usr/include/stdio.h").Action == "" {
		t.Error("/usr/include/stdio.h should match .h")
	}
	if c.Classify("/src/foo.c").Action == "" {
		t.Error("/src/foo.c should match .c")
	}
	if c.Classify("/bin/bash").Action != "" {
		t.Error("/bin/bash should not match")
	}
}

func TestClassifyFilenameExact(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "metadata",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternFilenameExact, Values: []string{"LICENSE", "README"}},
	}})
	if c.Classify("/some/deep/path/LICENSE").Action == "" {
		t.Error("LICENSE basename should match")
	}
	if c.Classify("/path/README.md").Action != "" {
		t.Error("README.md is NOT exact-equal to README")
	}
}

func TestClassifyGlob(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "perl-uni",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternGlob, Values: []string{"*/perl/unicore/*"}},
	}})
	// path/filepath.Match does NOT do recursive ** — the rule must
	// match the literal segment count.
	if c.Classify("a/perl/unicore/Hira.pl").Action == "" {
		t.Error("a/perl/unicore/Hira.pl should match */perl/unicore/*")
	}
}

func TestClassifyRegex(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "tests-under-extracted",
		Action:  ActionRedundantUnderArchive,
		Pattern: Pattern{Type: PatternRegex, Values: []string{`^/?opt/extracted/[^/]+/tests?/`}},
	}})
	if c.Classify("/opt/extracted/sqlite-3.44/test/foo.test").Action != ActionRedundantUnderArchive {
		t.Error("should match regex for tests under extracted archive")
	}
	if c.Classify("/opt/extracted/sqlite-3.44/tests/bar").Action != ActionRedundantUnderArchive {
		t.Error("plural 'tests' should also match")
	}
	if c.Classify("/opt/normal/path/foo").Action != "" {
		t.Error("non-extracted path should not match")
	}
}

// ─── Dispatch order ─────────────────────────────────────────────────

func TestClassifyDispatchOrder(t *testing.T) {
	// filename_exact should win over prefix when both could match —
	// it runs first in the dispatch chain.
	rules := []Rule{
		{Name: "prefix-rule", Action: ActionSkip,
			Pattern: Pattern{Type: PatternPrefix, Values: []string{"/etc/"}}},
		{Name: "filename-rule", Action: ActionMarkAsNoise,
			Pattern: Pattern{Type: PatternFilenameExact, Values: []string{"hostname"}}},
	}
	c, _ := New(rules)
	d := c.Classify("/etc/hostname")
	if d.RuleName != "filename-rule" {
		t.Errorf("RuleName = %q, want filename-rule (filename_exact runs first)", d.RuleName)
	}
}

// ─── Edge cases ─────────────────────────────────────────────────────

func TestClassifyEmptyPath(t *testing.T) {
	c, _ := New([]Rule{{
		Name:    "x",
		Action:  ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: []string{"/"}},
	}})
	if d := c.Classify(""); d.Action != "" {
		t.Errorf("empty path must yield empty Decision, got %+v", d)
	}
}

func TestClassifyDecisionFields(t *testing.T) {
	c, _ := New([]Rule{{
		Name:       "rich",
		Action:     ActionSkip,
		Pattern:    Pattern{Type: PatternPrefix, Values: []string{"/x/"}},
		Rationale:  "test reason",
		Confidence: 0.7,
	}})
	d := c.Classify("/x/y")
	if d.Action != ActionSkip {
		t.Errorf("Action = %q, want skip", d.Action)
	}
	if d.RuleName != "rich" {
		t.Errorf("RuleName = %q", d.RuleName)
	}
	if d.Reason != "test reason" {
		t.Errorf("Reason = %q", d.Reason)
	}
	if d.Confidence != 0.7 {
		t.Errorf("Confidence = %v, want 0.7", d.Confidence)
	}
}

func TestRulesReturnsCopy(t *testing.T) {
	in := []Rule{{
		Name: "x", Action: ActionSkip,
		Pattern: Pattern{Type: PatternPrefix, Values: []string{"/x/"}},
	}}
	c, _ := New(in)
	out := c.Rules()
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	out[0].Name = "mutated"
	if c.Rules()[0].Name == "mutated" {
		t.Error("Rules should return a copy, but mutation leaked back")
	}
}

// ─── Trie ──────────────────────────────────────────────────────────

func TestTrieEmptyPatternIgnored(t *testing.T) {
	tr := newTrie()
	r := &Rule{Name: "x", Action: ActionSkip}
	tr.insert("", r)
	if tr.longestMatch("anything") != nil {
		t.Error("empty pattern must not match")
	}
}

func TestTrieFirstInsertWinsOnDuplicate(t *testing.T) {
	tr := newTrie()
	first := &Rule{Name: "first"}
	second := &Rule{Name: "second"}
	tr.insert("/x/", first)
	tr.insert("/x/", second)
	if got := tr.longestMatch("/x/y"); got != first {
		t.Errorf("got = %v, want first (first insertion wins)", got)
	}
}

func TestReversedString(t *testing.T) {
	cases := map[string]string{
		"":       "",
		"a":      "a",
		"abc":    "cba",
		"foo.so": "os.oof",
	}
	for in, want := range cases {
		if got := reversedString(in); got != want {
			t.Errorf("reversedString(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── Performance ────────────────────────────────────────────────────

func TestClassifyPerformanceUnder10MicrosPerPath(t *testing.T) {
	if raceDetectorEnabled {
		// Map operations under -race are instrumented and run ~10×
		// slower than the production code path. Asserting the 10 µs
		// budget would be testing the race detector, not the
		// classifier; skip with a note so CI under -race remains
		// clean and `go test ./...` (no race) still asserts the
		// real bound.
		t.Skip("perf assertion is skipped under -race; production target is 10 µs/path uninstrumented")
	}
	rules, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	c, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	paths := generateSyntheticFilesystem(10_000)

	// Warm caches.
	for _, p := range paths[:100] {
		c.Classify(p)
	}

	startNs := nowNs()
	for _, p := range paths {
		c.Classify(p)
	}
	elapsed := nowNs() - startNs
	perPath := elapsed / int64(len(paths))
	t.Logf("Classification: %d ns/path over %d paths (%d default rules)",
		perPath, len(paths), len(rules))
	if perPath > 10_000 {
		t.Errorf("classifier is %d ns/path, want < 10000 (10 µs)", perPath)
	}
}

// BenchmarkClassify is the long-form perf measure that benchmarking
// frameworks expect. `go test -bench=Classify` runs uninstrumented
// even when the regular suite runs under -race.
func BenchmarkClassify(b *testing.B) {
	rules, err := LoadDefault()
	if err != nil {
		b.Fatalf("LoadDefault: %v", err)
	}
	c, err := New(rules)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	paths := generateSyntheticFilesystem(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Classify(paths[i%len(paths)])
	}
}

// nowNs is a tiny indirection so the perf test does not pull
// time.Now into other helpers (and so the import is local).
func nowNs() int64 {
	return timeNowNs()
}

// generateSyntheticFilesystem returns a mix of paths covering the
// dominant default-rule categories plus a chunk of "no rule matches"
// paths (binaries under /usr/local).
func generateSyntheticFilesystem(n int) []string {
	templates := []string{
		"/usr/share/zoneinfo/Continent/City",
		"/usr/share/man/man1/foo.1.gz",
		"/usr/share/doc/libssl/copyright",
		"/usr/share/locale/de/LC_MESSAGES/coreutils.mo",
		"/etc/apt/apt.conf.d/01autoremove",
		"/etc/pam.d/login",
		"/var/lib/dpkg/info/foo.list",
		"/usr/share/X11/locale/en_US/Compose",
		"/usr/include/stdio.h",
		"/src/main.c",
		"/usr/lib/python3/site-packages/foo.pyc",
		"/path/to/LICENSE",
		"/path/to/README.md",
		"/usr/local/bin/myapp",
		"/opt/myorg/server",
		"/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, templates[i%len(templates)]+"/"+strings.Repeat("x", i%32))
	}
	return out
}
