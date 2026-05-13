package dedup

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestDedupName(t *testing.T) {
	if New().Name() != Name {
		t.Errorf("Name() = %q, want %q", New().Name(), Name)
	}
}

func TestDedupKey_PriorityOrder(t *testing.T) {
	cases := []struct {
		name string
		c    model.Component
		want string
	}{
		{
			name: "purl wins",
			c:    model.Component{PURL: "pkg:npm/lodash@4.17.21", CPEs: []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}},
			want: "purl:pkg:npm/lodash@4.17.21",
		},
		{
			name: "purl with qualifier canonicalised",
			c:    model.Component{PURL: "pkg:npm/lodash@4.17.21?package-id=abc"},
			want: "purl:pkg:npm/lodash@4.17.21",
		},
		{
			name: "cpe when no purl",
			c:    model.Component{CPEs: []string{"cpe:2.3:a:Express:Express:4.18.0:*:*:*:*:*:*:*"}},
			want: "cpe:cpe:2.3:a:express:express:4.18.0:*:*:*:*:*:*:*",
		},
		{
			name: "sha256 when no purl/cpe",
			c: model.Component{Hashes: []model.Hash{
				{Algorithm: model.HashAlgorithmSHA256, Value: "DEADBEEF"},
			}},
			want: "sha256:deadbeef",
		},
		{
			name: "name+version+type as last-resort",
			c:    model.Component{Name: "MyLib", Version: "1.2", Type: model.ComponentTypeLibrary},
			want: "nvt:library:mylib:1.2",
		},
		{
			name: "no signal returns empty (no dedup)",
			c:    model.Component{Name: "config.txt", Type: model.ComponentTypeFile},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dedupKey(&tc.c); got != tc.want {
				t.Errorf("dedupKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRun_MergesByPURL(t *testing.T) {
	in := []model.Component{
		{
			Name: "lodash", Version: "4.17.21",
			PURL:       "pkg:npm/lodash@4.17.21",
			Properties: map[string]string{"a": "1"},
		},
		{
			Name: "lodash", Version: "4.17.21",
			PURL:       "pkg:npm/lodash@4.17.21",
			Properties: map[string]string{"b": "2"},
		},
	}
	out, merged := Run(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if merged != 1 {
		t.Errorf("merged groups = %d, want 1", merged)
	}
	c := out[0]
	if c.Properties["a"] != "1" {
		t.Errorf("missing primary property a")
	}
	if c.Properties["b"] != "2" {
		t.Errorf("missing secondary property b")
	}
	if c.Properties["astinus:dedup:merged-count"] != "1" {
		t.Errorf("merged-count = %q, want 1", c.Properties["astinus:dedup:merged-count"])
	}
}

func TestRun_MergesPURLEvenWithDifferentQualifiers(t *testing.T) {
	in := []model.Component{
		{Name: "x", Version: "1", PURL: "pkg:npm/x@1?package-id=aaa"},
		{Name: "x", Version: "1", PURL: "pkg:npm/x@1?package-id=bbb"},
	}
	out, _ := Run(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (qualifiers ignored for dedup)", len(out))
	}
}

func TestRun_PreservesOccurrencesAcrossMerge(t *testing.T) {
	in := []model.Component{
		{
			PURL: "pkg:npm/x@1",
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{
				{Path: "/a/x"},
			}},
		},
		{
			PURL: "pkg:npm/x@1",
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{
				{Path: "/b/x"},
			}},
		},
	}
	out, _ := Run(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d", len(out))
	}
	locs := out[0].Evidence.Locations
	if len(locs) != 2 {
		t.Fatalf("locs = %v, want 2 (union)", locs)
	}
}

func TestRun_NoDedupForUnidentifiedComponents(t *testing.T) {
	in := []model.Component{
		{Name: "config.txt", Type: model.ComponentTypeFile},
		{Name: "config.txt", Type: model.ComponentTypeFile},
	}
	out, merged := Run(in)
	if len(out) != 2 {
		t.Errorf("len(out) = %d, want 2 (no signal → no dedup)", len(out))
	}
	if merged != 0 {
		t.Errorf("merged = %d, want 0", merged)
	}
}

func TestRun_PreservesOriginalOrder(t *testing.T) {
	in := []model.Component{
		{PURL: "pkg:npm/a@1", Name: "a"},
		{Name: "no-key1", Type: model.ComponentTypeFile},
		{PURL: "pkg:npm/b@1", Name: "b"},
		{PURL: "pkg:npm/a@1", Name: "a-dupe"}, // dupe of first
		{Name: "no-key2", Type: model.ComponentTypeFile},
	}
	out, _ := Run(in)
	wantNames := []string{"a", "no-key1", "b", "no-key2"}
	if len(out) != len(wantNames) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(wantNames))
	}
	for i, want := range wantNames {
		if out[i].Name != want {
			t.Errorf("out[%d].Name = %q, want %q", i, out[i].Name, want)
		}
	}
}

func TestRun_PicksHigherScorePrimary(t *testing.T) {
	in := []model.Component{
		// First seen: weak (no extra signal beyond the shared sha256).
		{Name: "weak", Hashes: []model.Hash{{Algorithm: "sha256", Value: "deadbeef"}}},
		// Second seen: strong (multiple Evidence.Locations).
		{
			Name:   "strong",
			Hashes: []model.Hash{{Algorithm: "sha256", Value: "deadbeef"}},
			Evidence: &model.Evidence{Locations: []model.EvidenceLocation{
				{Path: "/a"}, {Path: "/b"}, {Path: "/c"},
			}},
		},
	}
	// Key is sha256 (both share). Primary should be "strong" because
	// it scores higher (more Evidence.Locations).
	out, _ := Run(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].Name != "strong" {
		t.Errorf("primary name = %q, want strong", out[0].Name)
	}
}

func TestMergeHashes_Union(t *testing.T) {
	a := []model.Hash{{Algorithm: "sha256", Value: "AAA"}}
	b := []model.Hash{
		{Algorithm: "sha256", Value: "AAA"}, // dupe
		{Algorithm: "sha1", Value: "BBB"},
	}
	out := mergeHashes(a, b)
	if len(out) != 2 {
		t.Errorf("len = %d, want 2", len(out))
	}
}

func TestMergeCPEs_DedupCaseInsensitive(t *testing.T) {
	a := []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}
	b := []string{"cpe:2.3:a:X:Y:1:*:*:*:*:*:*:*"}
	out := mergeCPEs(a, b)
	if len(out) != 1 {
		t.Errorf("len = %d, want 1 (case-insensitive)", len(out))
	}
}

func TestMergeProperties_ConflictRecorded(t *testing.T) {
	a := map[string]string{"k": "v1"}
	b := map[string]string{"k": "v2"}
	out := mergeProperties(a, b)
	if out["k"] != "v1" {
		t.Errorf("k = %q, want v1 (primary wins)", out["k"])
	}
	if out["astinus:dedup:conflict:k"] != "v2" {
		t.Errorf("conflict breadcrumb missing")
	}
}

func TestEnrich_LogsCounts(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{
		{PURL: "pkg:npm/x@1"},
		{PURL: "pkg:npm/x@1"},
		{PURL: "pkg:npm/y@1"},
	}}
	if err := New().Enrich(context.Background(), sbom, nil); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("len = %d, want 2", len(sbom.Components))
	}
}

func TestEnrich_NilSBOMReturnsError(t *testing.T) {
	if err := New().Enrich(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error on nil sbom")
	}
}

// TestRun_GoBuildinfoBeatsSyftFileRowOnSamePURL — S4 Task 1. A
// buildinfo-grounded library row and a Syft `type=file` row land
// in the SBOM with the same Go module PURL. dedup must pick the
// identified row as primary and merge the file row's Properties on
// top of it, NOT the other way around — otherwise the surviving
// Component has Type=file and downstream scanners (Grype, OSV) skip
// it. The merged row keeps Type=library, evidence-level=identified,
// and absorbs the syft:location:* breadcrumbs.
func TestRun_GoBuildinfoBeatsSyftFileRowOnSamePURL(t *testing.T) {
	purl := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	in := []model.Component{
		// Syft `file`-typed row first (lower original index — would
		// win the tiebreak under the old scoring).
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "v1.9.3",
			PURL:    purl,
			Type:    model.ComponentTypeFile,
			Properties: map[string]string{
				"syft:location:0:path": "/usr/lib/grafana/bin/grafana",
			},
		},
		// Buildinfo-grounded row second.
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "1.9.3",
			PURL:    purl,
			Type:    model.ComponentTypeLibrary,
			Properties: map[string]string{
				model.PropertyEvidenceLevel: string(model.EvidenceLevelIdentified),
				"astinus:identified:source": "go-buildinfo",
			},
		},
	}
	out, merged := Run(in)
	if len(out) != 1 || merged != 1 {
		t.Fatalf("len(out)=%d merged=%d, want 1+1", len(out), merged)
	}
	got := out[0]
	if got.Type != model.ComponentTypeLibrary {
		t.Errorf("Type = %v, want library (file row must not win)", got.Type)
	}
	if got.Properties[model.PropertyEvidenceLevel] != string(model.EvidenceLevelIdentified) {
		t.Errorf("evidence-level = %q, want identified",
			got.Properties[model.PropertyEvidenceLevel])
	}
	if got.Properties["astinus:identified:source"] != "go-buildinfo" {
		t.Errorf("identified:source = %q, want go-buildinfo",
			got.Properties["astinus:identified:source"])
	}
	// The syft breadcrumb survives the merge.
	if got.Properties["syft:location:0:path"] == "" {
		t.Errorf("syft:location breadcrumb lost in merge: %v", got.Properties)
	}
}

// ─── S5 Task 3: buildinfo precedence for Go modules (ADR-0050) ───────

// TestPreferBuildinfo_DropsSyftRowAtDifferentVersion — the
// canonical S5-T3 case. Syft's go-mod-cataloger reports
// `pkg:golang/example/x@v1.0.0` from parsing go.mod; Astinus
// reads `debug/buildinfo` and emits the SAME module path at
// `@v1.2.3` (the version actually compiled). Pre-S5 Run admits
// both rows as distinct (different canonical PURLs) — Syft's
// v1.0.0 is then a precision FP. S5-T3 drops the Syft row when
// a buildinfo row exists at the same module path with a
// different version.
func TestPreferBuildinfo_DropsSyftRowAtDifferentVersion(t *testing.T) {
	in := []model.Component{
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "v1.0.0",
			PURL:    "pkg:golang/github.com/sirupsen/logrus@v1.0.0",
			Type:    model.ComponentTypeLibrary,
			// Syft-style row — no astinus:identified:source.
			Properties: map[string]string{
				"syft:location:0:path": "/src/go.mod",
			},
		},
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "v1.9.3",
			PURL:    "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
			Type:    model.ComponentTypeLibrary,
			Properties: map[string]string{
				model.PropertyEvidenceLevel: string(model.EvidenceLevelIdentified),
				"astinus:identified:source": "go-buildinfo",
			},
		},
	}
	out, _ := Run(in)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1 (buildinfo wins, syft row dropped); got %+v",
			len(out), out)
	}
	if out[0].Version != "v1.9.3" {
		t.Errorf("Version = %q, want v1.9.3 (buildinfo row)", out[0].Version)
	}
	if out[0].Properties["astinus:identified:source"] != "go-buildinfo" {
		t.Errorf("identified:source = %q, want go-buildinfo",
			out[0].Properties["astinus:identified:source"])
	}
}

// TestPreferBuildinfo_KeepsSyftRowAtSameVersion — when both rows
// have the same canonical PURL (same module, same version), the
// pre-S5 normal PURL-keyed merge handles them (S4-T1 contract).
// The buildinfo row wins primary, the Syft breadcrumb survives
// via the property merge. S5-T3 must NOT interfere with this
// path.
func TestPreferBuildinfo_KeepsSyftRowAtSameVersion(t *testing.T) {
	purl := "pkg:golang/github.com/sirupsen/logrus@v1.9.3"
	in := []model.Component{
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "v1.9.3",
			PURL:    purl,
			Type:    model.ComponentTypeFile,
			Properties: map[string]string{
				"syft:location:0:path": "/usr/lib/grafana/bin/grafana",
			},
		},
		{
			Name:    "github.com/sirupsen/logrus",
			Version: "v1.9.3",
			PURL:    purl,
			Type:    model.ComponentTypeLibrary,
			Properties: map[string]string{
				model.PropertyEvidenceLevel: string(model.EvidenceLevelIdentified),
				"astinus:identified:source": "go-buildinfo",
			},
		},
	}
	out, merged := Run(in)
	if len(out) != 1 || merged != 1 {
		t.Fatalf("len(out)=%d merged=%d, want 1+1 (PURL-keyed merge)", len(out), merged)
	}
	// S4-T1 contract: buildinfo row wins, syft breadcrumb survives.
	if out[0].Type != model.ComponentTypeLibrary {
		t.Errorf("Type = %v, want library", out[0].Type)
	}
	if out[0].Properties["syft:location:0:path"] == "" {
		t.Errorf("syft:location breadcrumb lost — S5-T3 must not break S4-T1 merge")
	}
}

// TestPreferBuildinfo_NoOpWithoutBuildinfo — when no buildinfo
// rows exist, the precedence pass is a no-op. Non-Go-buildinfo
// inherited rows pass through unchanged.
func TestPreferBuildinfo_NoOpWithoutBuildinfo(t *testing.T) {
	in := []model.Component{
		{
			Name: "github.com/foo/bar", Version: "v1.0.0",
			PURL: "pkg:golang/github.com/foo/bar@v1.0.0",
			Type: model.ComponentTypeLibrary,
		},
		{
			Name: "github.com/baz/qux", Version: "v2.0.0",
			PURL: "pkg:golang/github.com/baz/qux@v2.0.0",
			Type: model.ComponentTypeLibrary,
		},
	}
	out, _ := Run(in)
	if len(out) != 2 {
		t.Errorf("len(out) = %d, want 2 (no buildinfo → no drops)", len(out))
	}
}

// TestPreferBuildinfo_LeavesNonGolangRowsUntouched — the pass
// only operates on `pkg:golang/...` PURLs. npm / pypi / maven
// inherited rows alongside Go-buildinfo rows aren't affected.
func TestPreferBuildinfo_LeavesNonGolangRowsUntouched(t *testing.T) {
	in := []model.Component{
		{
			Name: "lodash", Version: "4.17.21",
			PURL: "pkg:npm/lodash@4.17.21",
			Type: model.ComponentTypeLibrary,
		},
		{
			Name: "github.com/foo/bar", Version: "v1.2.3",
			PURL: "pkg:golang/github.com/foo/bar@v1.2.3",
			Type: model.ComponentTypeLibrary,
			Properties: map[string]string{
				"astinus:identified:source": "go-buildinfo",
			},
		},
	}
	out, _ := Run(in)
	if len(out) != 2 {
		t.Errorf("len(out) = %d, want 2 (npm row preserved)", len(out))
	}
	var hasLodash bool
	for _, c := range out {
		if c.Name == "lodash" {
			hasLodash = true
		}
	}
	if !hasLodash {
		t.Errorf("npm lodash row dropped — golang-only pass widened")
	}
}

// TestGoModulePathFromPURL pins the canonical-coordinate helper —
// strips @version, ?qualifier, #subpath.
func TestGoModulePathFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:golang/github.com/foo/bar@v1.0.0":        "pkg:golang/github.com/foo/bar",
		"pkg:golang/github.com/foo/bar":               "pkg:golang/github.com/foo/bar",
		"pkg:golang/github.com/foo/bar?vcs_ref=devel": "pkg:golang/github.com/foo/bar",
		"pkg:golang/github.com/foo/bar@v1#sub":        "pkg:golang/github.com/foo/bar",
		"pkg:golang/github.com/foo/bar@v1?qual=x#sub": "pkg:golang/github.com/foo/bar",
		"pkg:npm/lodash@4.17.21":                      "", // non-golang
		"":                                            "",
	}
	for in, want := range cases {
		if got := goModulePathFromPURL(in); got != want {
			t.Errorf("goModulePathFromPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMergePair_FileTypeUpgradedFromSecondary — when both rows have
// the same dedup key but the primary's Type is `file` and the
// secondary's is a more-precise type, the merge lifts to the
// stronger type. S4 Task 1.
func TestMergePair_FileTypeUpgradedFromSecondary(t *testing.T) {
	primary := model.Component{
		Name: "x", PURL: "pkg:golang/x@v1", Type: model.ComponentTypeFile,
	}
	secondary := model.Component{
		Name: "x", PURL: "pkg:golang/x@v1", Type: model.ComponentTypeLibrary,
	}
	out := mergePair(primary, secondary)
	if out.Type != model.ComponentTypeLibrary {
		t.Errorf("Type = %v, want library", out.Type)
	}
}
