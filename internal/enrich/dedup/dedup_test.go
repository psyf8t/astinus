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
