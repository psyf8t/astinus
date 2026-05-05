package syftprefilter

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/untracked/pathclassifier"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// loadDefaultClassifier returns the bundled path-classifier the
// production CLI uses. Failing here is a build-time bug — the
// embedded default.yaml would have failed to parse.
func loadDefaultClassifier(t *testing.T) *pathclassifier.Classifier {
	t.Helper()
	rules, err := pathclassifier.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	c, err := pathclassifier.New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestEnrich_RemovesAptConfigFiles — the canonical S3-Task-3 fix:
// type=file Components for /etc/apt/... paths must be dropped from
// the SBOM (they're noise, not packages). Components of other types
// — application, library — pass through untouched.
func TestEnrich_RemovesAptConfigFiles(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{Name: "/etc/apt/apt.conf.d/01autoremove", Type: model.ComponentTypeFile},
			{Name: "/etc/apt/sources.list.d/debian.sources", Type: model.ComponentTypeFile},
			{Name: "/usr/local/bin/myapp", Type: model.ComponentTypeApplication},
			{Name: "lodash", Type: model.ComponentTypeLibrary, PURL: "pkg:npm/lodash@4.17.21"},
		},
	}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("kept %d components, want 2; got %v", len(sbom.Components), componentNames(sbom))
	}
	if !contains(componentNames(sbom), "/usr/local/bin/myapp") {
		t.Errorf("application removed; components = %v", componentNames(sbom))
	}
	if !contains(componentNames(sbom), "lodash") {
		t.Errorf("library removed; components = %v", componentNames(sbom))
	}
	for _, n := range componentNames(sbom) {
		if n == "/etc/apt/apt.conf.d/01autoremove" || n == "/etc/apt/sources.list.d/debian.sources" {
			t.Errorf("apt-config file %q was not removed", n)
		}
	}
}

// TestEnrich_PreservesNonFileTypes — a Component whose path matches
// a rule but whose Type is library / application MUST survive. The
// classifier's verdict applies only to type=file Syft baseline rows.
func TestEnrich_PreservesNonFileTypes(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		// This synthetic library at an apt-config path must NOT be
		// dropped — it's not a file row.
		{Name: "/etc/apt/strange.so", Type: model.ComponentTypeLibrary},
	}}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("library at %q was dropped (only type=file should be filtered)",
			"/etc/apt/strange.so")
	}
}

// TestEnrich_PathFromSyftLocationProperty — Syft sometimes puts the
// basename in Component.Name and the full path in
// Properties["syft:location:0:path"]. The pre-filter must consult
// the property when Name doesn't look like a path.
func TestEnrich_PathFromSyftLocationProperty(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "01autoremove", // basename only, no leading slash
		Type: model.ComponentTypeFile,
		Properties: map[string]string{
			"syft:location:0:path": "/etc/apt/apt.conf.d/01autoremove",
		},
	}}}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("component should have been removed via syft:location property; got %v",
			componentNames(sbom))
	}
}

// TestEnrich_PathFromEvidenceLocations — fallback path source: the
// CycloneDX Evidence.Locations array. Used when Syft serialised the
// location via the standard Evidence shape rather than its own
// `syft:location` properties.
func TestEnrich_PathFromEvidenceLocations(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		Name: "01autoremove",
		Type: model.ComponentTypeFile,
		Evidence: &model.Evidence{
			Locations: []model.EvidenceLocation{{Path: "/etc/apt/apt.conf.d/01autoremove"}},
		},
	}}}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("component not removed via Evidence.Locations; got %v", componentNames(sbom))
	}
}

// TestEnrich_PrunesOrphanedRelationships — removed Components must
// not leave dangling edges in sbom.Relationships. Both
// SourceRef-side and TargetRef-side references are pruned.
func TestEnrich_PrunesOrphanedRelationships(t *testing.T) {
	sbom := &model.SBOM{
		Components: []model.Component{
			{BOMRef: "config-1", Name: "/etc/apt/apt.conf.d/01autoremove", Type: model.ComponentTypeFile},
			{BOMRef: "myapp", Name: "myapp", Type: model.ComponentTypeApplication},
			{BOMRef: "other", Name: "other", Type: model.ComponentTypeLibrary, PURL: "pkg:npm/other@1"},
		},
		Relationships: []model.Relationship{
			{SourceRef: "myapp", TargetRef: "config-1", Type: model.RelationshipDependsOn},
			{SourceRef: "myapp", TargetRef: "other", Type: model.RelationshipDependsOn},
			{SourceRef: "config-1", TargetRef: "other", Type: model.RelationshipDependsOn},
		},
	}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	// Two of the three edges referenced config-1; only the
	// myapp→other edge should survive.
	if len(sbom.Relationships) != 1 {
		t.Errorf("relationships = %d, want 1; got %+v", len(sbom.Relationships), sbom.Relationships)
	}
	if len(sbom.Relationships) == 1 {
		r := sbom.Relationships[0]
		if r.SourceRef != "myapp" || r.TargetRef != "other" {
			t.Errorf("surviving edge = %+v, want myapp→other", r)
		}
	}
}

// TestEnrich_NilClassifierIsNoOp — passing nil classifier (the
// `--no-syft-prefilter` path) MUST leave the SBOM untouched.
func TestEnrich_NilClassifierIsNoOp(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "/etc/apt/apt.conf.d/01autoremove", Type: model.ComponentTypeFile},
	}}
	if err := New(nil).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("nil classifier should leave SBOM untouched; got %v", componentNames(sbom))
	}
}

// TestEnrich_NilSBOM returns an error rather than panicking.
func TestEnrich_NilSBOM(t *testing.T) {
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error on nil SBOM")
	}
}

// TestEnrich_KeepsFileWithoutPath — a type=file Component whose
// path can't be extracted from any of the three sources is preserved
// (we have nothing to classify against; default to "keep").
func TestEnrich_KeepsFileWithoutPath(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "no-path-file", Type: model.ComponentTypeFile},
	}}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("file without path should be kept; got %v", componentNames(sbom))
	}
}

// TestEnrich_UnmatchedFilePathPreserved — a type=file Component
// whose path does NOT match any rule (e.g. /usr/local/share/myapp/
// data.dat) MUST survive.
func TestEnrich_UnmatchedFilePathPreserved(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{Name: "/usr/local/share/myapp/data.dat", Type: model.ComponentTypeFile},
	}}
	if err := New(loadDefaultClassifier(t)).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("unmatched-path file should survive; got %v", componentNames(sbom))
	}
}

func TestEnricher_NameAndDependencies(t *testing.T) {
	e := New(nil)
	if e.Name() != Name {
		t.Errorf("Name = %q, want %q", e.Name(), Name)
	}
	if e.Dependencies() != nil {
		t.Errorf("Dependencies = %v, want nil (runs first)", e.Dependencies())
	}
}

func TestExtractPath(t *testing.T) {
	cases := []struct {
		name string
		c    model.Component
		want string
	}{
		{"name-as-absolute-path",
			model.Component{Name: "/etc/passwd", Type: model.ComponentTypeFile},
			"/etc/passwd"},
		{"syft-property",
			model.Component{Name: "passwd", Type: model.ComponentTypeFile,
				Properties: map[string]string{"syft:location:0:path": "/etc/passwd"}},
			"/etc/passwd"},
		{"evidence-locations",
			model.Component{Name: "passwd", Type: model.ComponentTypeFile,
				Evidence: &model.Evidence{Locations: []model.EvidenceLocation{{Path: "/etc/passwd"}}}},
			"/etc/passwd"},
		{"no-source",
			model.Component{Name: "passwd", Type: model.ComponentTypeFile},
			""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractPath(&c.c); got != c.want {
				t.Errorf("extractPath = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEnrich_MarkedAsNoiseStaysButGetsStamp — when a rule fires
// with action=mark_as_noise / mark_as_redundant, the Component MUST
// stay in the SBOM but pick up `astinus:noise=true` and the rule
// name. Today the bundled default.yaml has no mark_as_noise rules
// for paths, but the code path is critical for future rule
// additions; verified via a synthetic in-test classifier.
func TestEnrich_MarkedAsNoiseStaysButGetsStamp(t *testing.T) {
	customRules := []pathclassifier.Rule{{
		Name:        "test-mark",
		Description: "synthetic mark-only rule for the prefilter test",
		Action:      pathclassifier.ActionMarkAsNoise,
		Pattern: pathclassifier.Pattern{
			Type:   pathclassifier.PatternPrefix,
			Values: []string{"/var/cache/test/"},
		},
		Rationale: "test-only",
	}}
	c, err := pathclassifier.New(customRules)
	if err != nil {
		t.Fatalf("classifier: %v", err)
	}
	sbom := &model.SBOM{Components: []model.Component{
		{BOMRef: "marked", Name: "/var/cache/test/file.dat", Type: model.ComponentTypeFile},
	}}
	if err := New(c).Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("mark_as_noise should keep the component; got %d", len(sbom.Components))
	}
	got := sbom.Components[0]
	if got.Properties[PropertyNoise] != "true" {
		t.Errorf("noise stamp missing: %v", got.Properties)
	}
	if got.Properties[PropertyNoiseRule] != "test-mark" {
		t.Errorf("noise rule = %q, want test-mark", got.Properties[PropertyNoiseRule])
	}
}

// ─── helpers ──────────────────────────────────────────────────────

func componentNames(sbom *model.SBOM) []string {
	out := make([]string, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		out = append(out, c.Name)
	}
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
