package basediff

import (
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestClassifyApkByLayerIndex_BaseLayerZero — Sprint 7 Task 2.
// An apk component whose ONLY Syft path was /lib/apk/db/installed
// (filtered out by S6-T2's path-filter) falls through to the
// LayerIndex fallback. Layer 0 → OriginBaseImage. ADR-0059
// amendment.
func TestClassifyApkByLayerIndex_BaseLayerZero(t *testing.T) {
	c := &model.Component{
		Name: "musl",
		PURL: "pkg:apk/alpine/musl@1.2.5-r0",
		Properties: map[string]string{
			model.PropertyLayerSource: "apk-earliest-layer",
		},
		LayerInfo: &model.LayerInfo{LayerIndex: 0},
	}
	got, ok := classifyApkByLayerIndex(c)
	if !ok {
		t.Fatal("classifyApkByLayerIndex returned (_, false) — should fire on apk + apk-earliest stamp")
	}
	if got != model.OriginBaseImage {
		t.Errorf("layer 0 apk → %v, want OriginBaseImage", got)
	}
}

// TestClassifyApkByLayerIndex_LaterLayerIsApplication — apk
// components first appearing in layer > 0 came from a Dockerfile
// RUN apk add command. Classify as OriginApplication.
func TestClassifyApkByLayerIndex_LaterLayerIsApplication(t *testing.T) {
	c := &model.Component{
		Name: "curl",
		PURL: "pkg:apk/alpine/curl@8.5.0-r0",
		Properties: map[string]string{
			model.PropertyLayerSource: "apk-earliest-layer",
		},
		LayerInfo: &model.LayerInfo{LayerIndex: 2},
	}
	got, ok := classifyApkByLayerIndex(c)
	if !ok {
		t.Fatal("classifyApkByLayerIndex returned (_, false)")
	}
	if got != model.OriginApplication {
		t.Errorf("layer 2 apk → %v, want OriginApplication", got)
	}
}

// TestClassifyApkByLayerIndex_NonApkSkipped — non-apk components
// must NOT fire the layer-index fallback. Components attributed
// by other paths (filemap-last-touch, syft-location-property)
// have different "earliest" semantics.
func TestClassifyApkByLayerIndex_NonApkSkipped(t *testing.T) {
	cases := []*model.Component{
		// Non-apk PURL.
		{
			Name: "express", PURL: "pkg:npm/express@4.18.2",
			Properties: map[string]string{
				model.PropertyLayerSource: "apk-earliest-layer",
			},
			LayerInfo: &model.LayerInfo{LayerIndex: 0},
		},
		// Apk but stamped by a different path.
		{
			Name: "musl", PURL: "pkg:apk/alpine/musl@1.2.5-r0",
			Properties: map[string]string{
				model.PropertyLayerSource: "filemap-last-touch",
			},
			LayerInfo: &model.LayerInfo{LayerIndex: 0},
		},
		// Apk + apk-earliest stamp but no LayerInfo.
		{
			Name: "musl", PURL: "pkg:apk/alpine/musl@1.2.5-r0",
			Properties: map[string]string{
				model.PropertyLayerSource: "apk-earliest-layer",
			},
		},
		// Nil component — defensive case.
		nil,
	}
	for i, c := range cases {
		_, ok := classifyApkByLayerIndex(c)
		if ok {
			t.Errorf("case %d (%+v): fallback fired when it shouldn't", i, c)
		}
	}
}

// TestClassifyComponent_FallsBackToLayerIndexOnEmptyPaths — the
// integration pin: a content-strategy call with an apk component
// whose pathsForComponent is empty (only the filtered apk DB
// path was present) lands on the LayerIndex fallback, not on
// OriginUnknown. ADR-0059 amendment.
func TestClassifyComponent_FallsBackToLayerIndexOnEmptyPaths(t *testing.T) {
	c := &model.Component{
		Name: "curl",
		PURL: "pkg:apk/alpine/curl@8.5.0-r0",
		Properties: map[string]string{
			"syft:location:0:path":    "/lib/apk/db/installed", // filtered by pathsForComponent
			model.PropertyLayerSource: "apk-earliest-layer",
		},
		LayerInfo: &model.LayerInfo{LayerIndex: 1},
	}
	// Build a minimal Enricher + empty base set; the test exercises
	// the apk-layer-fallback branch specifically.
	e := &Enricher{}
	got := e.classifyComponent(c, nil, nil, &contentStats{})
	if got != model.OriginApplication {
		t.Errorf("classifyComponent on apk row with layer 1 = %v, want OriginApplication "+
			"(LayerIndex fallback should fire on empty paths)", got)
	}
}
