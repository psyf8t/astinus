package untracked

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/fingerprint"
	"github.com/psyf8t/astinus/internal/fingerprint/matcher"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEnrichAddsExecutable(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/foo": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "foo" || c.Type != model.ComponentTypeApplication {
		t.Errorf("comp = %+v", c)
	}
	if c.Properties["astinus:untracked:category"] != "executable" {
		t.Errorf("category = %q", c.Properties["astinus:untracked:category"])
	}
	if c.Evidence == nil || c.Evidence.Method != "untracked-scan" {
		t.Errorf("evidence = %+v", c.Evidence)
	}
	if c.LayerInfo == nil {
		t.Errorf("LayerInfo should be populated")
	}
	if len(c.Hashes) == 0 || c.Hashes[0].Algorithm != model.HashAlgorithmSHA256 {
		t.Errorf("hashes = %+v", c.Hashes)
	}
}

func TestEnrichSkipsKnownPaths(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/known": {0x7f, 'E', 'L', 'F'},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "known",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "opt/bin/known"}},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("components = %d, want 1 (no untracked added)", len(sbom.Components))
	}
}

func TestEnrichSkipsKnownPathsWithLeadingSlash(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/bin/known": {0x7f, 'E', 'L', 'F'},
	})
	sbom := &model.SBOM{
		Components: []model.Component{{
			Name: "known",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{{Path: "/opt/bin/known"}},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("components = %d, want 1 (leading slash should normalize)", len(sbom.Components))
	}
}

func TestEnrichSkipsNoise(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"usr/share/man/man1/foo.1": []byte("man page"),
		"app/__pycache__/x.pyc":    []byte("\x00pyc\x00"),
		"opt/lib/libstatic.a":      []byte("ar archive"),
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("components = %d, want 0 (all noise)", len(sbom.Components))
	}
}

// TestEnrichPathClassifierSkipsRuleMatch — PRSD-Task-1: a file that
// matches a default classifier rule (here, /usr/share/zoneinfo/) is
// dropped before the magic-byte classifier runs. Without the rule
// the ELF magic at the front of the body would otherwise produce an
// executable component.
func TestEnrichPathClassifierSkipsRuleMatch(t *testing.T) {
	body := []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3}
	img := buildImage(t, map[string][]byte{
		"usr/share/zoneinfo/America/New_York": body,
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("components = %d, want 0 (zoneinfo rule must skip)", len(sbom.Components))
	}
}

// TestEnrichPathClassifierCustomRulesFile — operator's --rules-file
// can introduce a brand-new rule that drops a file the defaults
// would have admitted.
func TestEnrichPathClassifierCustomRulesFile(t *testing.T) {
	customRules, err := pathclassifier.Load([]byte(`
version: 1
rules:
  - name: vendor-internal
    action: skip
    pattern: {type: prefix, values: ["opt/internal/"]}
    rationale: internal vendor binaries
`))
	if err != nil {
		t.Fatalf("Load custom: %v", err)
	}
	defaults, _ := pathclassifier.LoadDefault()
	classifier, err := pathclassifier.New(pathclassifier.Merge(defaults, customRules))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	img := buildImage(t, map[string][]byte{
		"opt/internal/agent": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
		"opt/external/app":   {0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	e := NewWithOptions(Options{PathClassifier: classifier})
	if err := e.Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1 (only opt/external/app)", len(sbom.Components))
	}
	if sbom.Components[0].Evidence.Locations[0].Path != "opt/external/app" {
		t.Errorf("kept the wrong file: %+v", sbom.Components[0])
	}
}

// TestEnrichPathClassifierMarkAsNoiseStampsBypass — when the
// classifier returns ActionMarkAsNoise and Include.IncludeNoise is
// true, the file is recorded with `astinus:untracked:filter-bypass`
// = `noise:<rule-name>` so consumers can see why.
func TestEnrichPathClassifierMarkAsNoiseStampsBypass(t *testing.T) {
	rules, err := pathclassifier.Load([]byte(`
version: 1
rules:
  - name: marked-noise
    action: mark_as_noise
    pattern: {type: prefix, values: ["opt/marked/"]}
    rationale: t
`))
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := pathclassifier.New(rules)
	if err != nil {
		t.Fatal(err)
	}

	img := buildImage(t, map[string][]byte{
		"opt/marked/binary": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	e := NewWithOptions(Options{
		PathClassifier: classifier,
		Include:        IncludeMask{IncludeNoise: true},
	})
	if err := e.Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1 (mark_as_noise + IncludeNoise)", len(sbom.Components))
	}
	bypass := sbom.Components[0].Properties["astinus:untracked:filter-bypass"]
	if bypass != "noise:marked-noise" {
		t.Errorf("bypass = %q, want noise:marked-noise", bypass)
	}
}

// TestEnrichClusteringEmitsSingleComponent — PRSD-Task-3: an
// extracted npm package produces ONE cluster Component instead of
// per-file rows for each of its files.
func TestEnrichClusteringEmitsSingleComponent(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"app/node_modules/lodash/package.json":    []byte(`{"name":"lodash","version":"4.17.21"}`),
		"app/node_modules/lodash/index.js":        []byte("module.exports = {};"),
		"app/node_modules/lodash/lib/foo.js":      []byte("// foo"),
		"app/node_modules/lodash/lib/bar.js":      []byte("// bar"),
		"app/node_modules/lodash/lib/internal.so": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		names := make([]string, 0, len(sbom.Components))
		for _, c := range sbom.Components {
			names = append(names, c.Name)
		}
		t.Fatalf("components = %v, want exactly 1 (lodash cluster)", names)
	}
	c := sbom.Components[0]
	if c.Name != "lodash" {
		t.Errorf("Name = %q, want lodash", c.Name)
	}
	if c.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("PURL = %q", c.PURL)
	}
	if c.Properties["astinus:cluster:type"] != "npm" {
		t.Errorf("cluster:type = %q", c.Properties["astinus:cluster:type"])
	}
	if c.Properties["astinus:cluster:detection-method"] != "anchor:package.json" {
		t.Errorf("cluster:detection-method = %q",
			c.Properties["astinus:cluster:detection-method"])
	}
	if c.Properties["astinus:cluster:file-count"] == "0" ||
		c.Properties["astinus:cluster:file-count"] == "" {
		t.Errorf("cluster:file-count = %q, want > 0",
			c.Properties["astinus:cluster:file-count"])
	}
}

// TestEnrichClusteringDedupAgainstExistingSyftEntry — Syft already
// reported lodash in the input SBOM; the cluster pre-pass must NOT
// duplicate it.
func TestEnrichClusteringDedupAgainstExistingSyftEntry(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"app/node_modules/lodash/package.json": []byte(`{"name":"lodash","version":"4.17.21"}`),
		"app/node_modules/lodash/index.js":     []byte("module.exports = {};"),
	})
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "lodash",
		Version: "4.17.21",
		PURL:    "pkg:npm/lodash@4.17.21",
		Properties: map[string]string{
			"syft:location:0:path": "/app/node_modules/lodash/package.json",
		},
	}}}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("components = %d, want 1 (no duplicate)", len(sbom.Components))
	}
}

// TestEnrichClusteringDisabledViaOptions — DisableClustering=true
// preserves the pre-PRSD-Task-3 behaviour: every visible file
// surfaces (subject to the existing redundancy filter, which still
// drops them because of Syft's known-paths index).
func TestEnrichClusteringDisabledViaOptions(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"app/node_modules/lodash/package.json": []byte(`{"name":"lodash","version":"4.17.21"}`),
		"app/node_modules/lodash/main.go":      {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	e := NewWithOptions(Options{DisableClustering: true})
	if err := e.Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	for _, c := range sbom.Components {
		if c.Properties["astinus:cluster:type"] != "" {
			t.Errorf("cluster Component leaked when DisableClustering=true: %s", c.Name)
		}
	}
}

func TestEnrichRecognisesJAR(t *testing.T) {
	jar := buildJAR(t, "Bundle-SymbolicName: com.example.jar\r\nBundle-Version: 2.0.0\r\n\r\n")
	img := buildImage(t, map[string][]byte{"opt/app/lib.jar": jar})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "com.example.jar" || c.Version != "2.0.0" {
		t.Errorf("jar metadata not applied: %+v", c)
	}
	if c.Type != model.ComponentTypeLibrary {
		t.Errorf("jar type = %v, want library", c.Type)
	}
}

// countingMatcher records every Lookup call so tests can assert
// MatcherSkipUnknown / MatcherMinFileBytes really skip work.
type countingMatcher struct {
	calls int
	inner matcher.Matcher
}

func (c *countingMatcher) Name() string { return "counting" }
func (c *countingMatcher) Lookup(ctx context.Context, alg, digest string) (matcher.Match, error) {
	c.calls++
	return c.inner.Lookup(ctx, alg, digest)
}

// TestEnrichSkipsMatcherForUnknownCategory — Task 4: the matcher
// is skipped for CategoryUnknown files (overwhelmingly /etc/* configs
// that no public catalogue indexes). The default Options have
// MatcherIncludeUnknown=false, so a file that classifies as Unknown
// must NOT trigger a Lookup.
func TestEnrichSkipsMatcherForUnknownCategory(t *testing.T) {
	// Random bytes that don't match any magic → CategoryUnknown.
	body := append([]byte("not a binary"), bytes.Repeat([]byte{0xab}, 8192)...)
	img := buildImage(t, map[string][]byte{
		"opt/random.dat": body,
	})
	cm := &countingMatcher{inner: matcher.Null}
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{Matcher: cm}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if cm.calls != 0 {
		t.Errorf("matcher called %d times, want 0 (unknown skipped by default)", cm.calls)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d, want 1 (file still recorded)", len(sbom.Components))
	}
}

// TestEnrichIncludeUnknownReadmitsMatcher — operator opt-in for the
// slow path: when MatcherIncludeUnknown=true the matcher is queried
// for unknowns again.
func TestEnrichIncludeUnknownReadmitsMatcher(t *testing.T) {
	body := append([]byte("not a binary"), bytes.Repeat([]byte{0xab}, 8192)...)
	img := buildImage(t, map[string][]byte{
		"opt/random.dat": body,
	})
	cm := &countingMatcher{inner: matcher.Null}
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{
		Matcher:               cm,
		MatcherIncludeUnknown: true,
	}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if cm.calls != 1 {
		t.Errorf("matcher called %d times, want 1 (include-unknown=true)", cm.calls)
	}
}

// TestEnrichSkipsMatcherForTinyFiles — files under
// MatcherMinFileBytes are skipped (default 256). A 50-byte ELF blob
// is too small to be a real vendored binary worth fingerprinting.
func TestEnrichSkipsMatcherForTinyFiles(t *testing.T) {
	tiny := []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3} // 11 bytes
	img := buildImage(t, map[string][]byte{
		"opt/bin/tiny": tiny,
	})
	cm := &countingMatcher{inner: matcher.Null}
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{Matcher: cm}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if cm.calls != 0 {
		t.Errorf("matcher called %d times, want 0 (under MatcherMinFileBytes=256)", cm.calls)
	}
}

func TestEnrichAppliesMatcher(t *testing.T) {
	// Pad past the matcher MinFileBytes threshold (default 256) so
	// the post-Stage-13 hardening Task 4 size-skip does not bypass
	// the matcher for this test.
	body := append([]byte("\x7fELF jq fake bytes"), bytes.Repeat([]byte{0x90}, 8192)...)
	img := buildImage(t, map[string][]byte{
		"opt/bin/jq": body,
	})

	// Build the matcher BEFORE running Enrich; we need the file's
	// SHA-256 to register the lookup. Re-use Hasher to compute it.
	bytesIn := body
	digest := sha256Hex(t, bytesIn)

	local := matcher.NewLocalMatcher()
	local.Add(model.HashAlgorithmSHA256, digest, matcher.Match{
		Name: "jq", Version: "1.7.1", PURL: "pkg:generic/jq@1.7.1",
		CPEs:   []string{"cpe:2.3:a:jqlang:jq:1.7.1:*:*:*:*:*:*:*"},
		Source: "test-local",
	})

	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{Matcher: local}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components = %d", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "jq" || c.Version != "1.7.1" || c.PURL == "" {
		t.Errorf("matcher fields not applied: %+v", c)
	}
	if c.Evidence.Method != "fingerprint" {
		t.Errorf("evidence method = %q, want 'fingerprint'", c.Evidence.Method)
	}
	if c.Properties["astinus:untracked:matcher"] != "test-local" {
		t.Errorf("matcher source missing: %v", c.Properties)
	}
}

func TestEnrichRespectsMaxComponents(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		key := "opt/bin/" + string(rune('a'+i))
		files[key] = []byte{0x7f, 'E', 'L', 'F', byte(i)}
	}
	img := buildImage(t, files)
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)
	if err := NewWithOptions(Options{MaxComponents: 2}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("components = %d, want 2 (cap honoured)", len(sbom.Components))
	}
}

func TestEnrichRequiresImage(t *testing.T) {
	if err := New().Enrich(context.Background(), &model.SBOM{}, &image.Bundle{}); err == nil {
		t.Fatal("expected error when bundle.Image is nil")
	}
}

func TestEnricherName(t *testing.T) {
	if New().Name() != Name {
		t.Errorf("Name = %q", New().Name())
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────

// TestEnrichSkipsRedundantUnderSyftPackageRoot — end-to-end check that
// a Syft-produced component (locations in `syft:location:N:path`
// properties, NOT evidence.occurrences) suppresses every untracked
// scan of the same package directory. This is the root cause of the
// 9 302 → ~500 noise reduction reported in the post-Stage-13 hardening
// sprint Task 1.
func TestEnrichSkipsRedundantUnderSyftPackageRoot(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		// Real package files inside an "npm package" Syft already covers.
		"app/node_modules/lodash/package.json": []byte(`{"name":"lodash"}`),
		"app/node_modules/lodash/index.js":     []byte("module.exports = {};"),
		"app/node_modules/lodash/LICENSE":      []byte("MIT"),
		// File OUTSIDE the package — must remain untracked.
		"opt/yq": {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{Components: []model.Component{{
		Name:    "lodash",
		Version: "4.17.21",
		PURL:    "pkg:npm/lodash@4.17.21",
		Properties: map[string]string{
			"syft:location:0:path": "/app/node_modules/lodash/package.json",
		},
	}}}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	// Original lodash + only the executable should remain (NOT the
	// LICENSE, NOT index.js, NOT package.json).
	if len(sbom.Components) != 2 {
		got := make([]string, 0, len(sbom.Components))
		for _, c := range sbom.Components {
			got = append(got, c.Name)
		}
		t.Fatalf("components = %v, want [lodash, yq]", got)
	}
	for _, c := range sbom.Components {
		if c.Name == "LICENSE" || c.Name == "index.js" || c.Name == "package.json" {
			t.Errorf("redundant component leaked: %s", c.Name)
		}
	}
}

// TestEnrichSkipsLicenseAndDocFiles — files matching the noisy
// filename catalog are dropped without ever being hashed.
func TestEnrichSkipsLicenseAndDocFiles(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/foo/LICENSE":       []byte("MIT..."),
		"opt/foo/README.md":     []byte("# foo"),
		"opt/foo/CHANGELOG.txt": []byte("v1"),
		"opt/foo/COPYING":       []byte("GPL-2"),
		"opt/foo/source.h":      []byte("#define FOO"),
		"opt/foo/bundle.js.map": []byte("{}"),
		"opt/bin/myapp":         {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if len(sbom.Components) != 1 {
		got := make([]string, 0, len(sbom.Components))
		for _, c := range sbom.Components {
			got = append(got, c.Name)
		}
		t.Fatalf("components = %v, want [myapp]", got)
	}
	if sbom.Components[0].Name != "myapp" {
		t.Errorf("kept = %s, want myapp", sbom.Components[0].Name)
	}
}

// TestEnrichIncludeFlagsBypassFilters — --include-noise re-admits
// files filtered by the catalog pre-pass (LICENSE, COPYING, …) and
// stamps the bypass reason. Files that are ALSO filtered by the
// classifier (e.g. README.md → CategoryConfig because of .md) stay
// dropped; the include flag is for the catalog, not the classifier.
func TestEnrichIncludeFlagsBypassFilters(t *testing.T) {
	img := buildImage(t, map[string][]byte{
		"opt/foo/LICENSE": []byte("MIT"),
		"opt/foo/COPYING": []byte("GPL"),
		"opt/bin/myapp":   {0x7f, 'E', 'L', 'F', 0, 0, 0, 0, 1, 2, 3},
	})
	sbom := &model.SBOM{}
	bundle := image.NewBundle(mustTag(t), img, sbom)

	e := NewWithOptions(Options{
		Include: IncludeMask{IncludeNoise: true},
	})
	if err := e.Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	// myapp + LICENSE + COPYING. LICENSE/COPYING bypassed the noise
	// catalog; the classifier admits them as Unknown (no extension /
	// magic match).
	if len(sbom.Components) != 3 {
		got := make([]string, 0, len(sbom.Components))
		for _, c := range sbom.Components {
			got = append(got, c.Name)
		}
		t.Fatalf("components = %v, want [myapp, LICENSE, COPYING]", got)
	}
	bypassed := 0
	for _, c := range sbom.Components {
		if c.Properties["astinus:untracked:filter-bypass"] == "noise" {
			bypassed++
		}
	}
	if bypassed != 2 {
		t.Errorf("bypassed = %d, want 2 (LICENSE + COPYING)", bypassed)
	}
}

func buildImage(t *testing.T, files map[string][]byte) v1.Image {
	t.Helper()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buildTar(t, files))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func buildTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for path, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: path, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildJAR(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustTag(t *testing.T) name.Tag {
	t.Helper()
	tag, err := name.NewTag("test/x:1")
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func sha256Hex(t *testing.T, b []byte) string {
	t.Helper()
	hex, _, err := fingerprint.HashSHA256(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return hex
}
