package attribution

import (
	"context"
	"testing"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/image/layer"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestApkEarliest_OverridesSyftLocation drives a 3-layer image where
// the apk DB grows across layers (alpine base + apk add curl + apk
// add jq). Syft would stamp every apk row at `/lib/apk/db/installed`
// (which lives in the LAST layer because each apk-add rewrites the
// DB), and the default stamper would pin every component to layer 2.
// The apk-earliest override must move each row to its actual
// introduction layer. ADR-0059.
func TestApkEarliest_OverridesSyftLocation(t *testing.T) {
	layer0 := "P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n"
	layer1 := layer0 + "\nP:curl\nV:8.5.0-r0\n"
	layer2 := layer1 + "\nP:jq\nV:1.7.1-r0\n"

	img := buildImage(t, []map[string]string{
		{layer.ApkInstalledPath: layer0},
		{layer.ApkInstalledPath: layer1},
		{layer.ApkInstalledPath: layer2},
	})

	sbom := &model.SBOM{
		Components: []model.Component{
			{
				BOMRef:  "comp-musl",
				Name:    "musl",
				Version: "1.2.5-r0",
				PURL:    "pkg:apk/alpine/musl@1.2.5-r0",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.ApkInstalledPath,
				},
			},
			{
				BOMRef:  "comp-curl",
				Name:    "curl",
				Version: "8.5.0-r0",
				PURL:    "pkg:apk/alpine/curl@8.5.0-r0",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.ApkInstalledPath,
				},
			},
			{
				BOMRef:  "comp-jq",
				Name:    "jq",
				Version: "1.7.1-r0",
				PURL:    "pkg:apk/alpine/jq@1.7.1-r0",
				Properties: map[string]string{
					"syft:location:0:path": "/" + layer.ApkInstalledPath,
				},
			},
			// Non-apk row — must NOT be touched by the override.
			{
				BOMRef:  "comp-app",
				Name:    "myapp",
				Version: "1.0",
				PURL:    "pkg:generic/myapp@1.0",
			},
		},
	}
	bundle := image.NewBundle(mustTag(t, "test/alpine:1"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	cases := []struct {
		name    string
		idx     int
		idxName int
	}{
		{"musl", 0, 0},
		{"curl", 1, 1},
		{"jq", 2, 2},
	}
	for _, c := range cases {
		comp := findByName(sbom, c.name)
		if comp == nil {
			t.Fatalf("%s missing from output", c.name)
		}
		if comp.LayerInfo == nil {
			t.Fatalf("%s LayerInfo nil — apk-earliest did not run", c.name)
		}
		if comp.LayerInfo.LayerIndex != c.idx {
			t.Errorf("%s LayerIndex = %d, want %d (apk-earliest override)",
				c.name, comp.LayerInfo.LayerIndex, c.idx)
		}
		if got := comp.Properties[model.PropertyLayerSource]; got != "apk-earliest-layer" {
			t.Errorf("%s astinus:layer:source = %q, want apk-earliest-layer",
				c.name, got)
		}
	}

	app := findByName(sbom, "myapp")
	if app == nil {
		t.Fatal("non-apk component myapp missing from output")
	}
	if app.Properties[model.PropertyLayerSource] == "apk-earliest-layer" {
		t.Error("non-apk component stamped with apk-earliest-layer — override widened past pkg:apk/")
	}
}

// TestApkEarliest_LeavesUnknownApkRowsAlone asserts the override is
// a no-op for apk rows whose (name, version) isn't in the FileMap's
// apk-earliest index (e.g. a Syft hallucination, or an apk package
// added at runtime via a tmpfs mount). Existing stamps (filemap-
// last-touch / syft-location-property) survive.
func TestApkEarliest_LeavesUnknownApkRowsAlone(t *testing.T) {
	layer0 := "P:musl\nV:1.2.5-r0\n"
	img := buildImage(t, []map[string]string{
		{
			layer.ApkInstalledPath: layer0,
			"usr/bin/some-binary":  "elf",
		},
	})

	sbom := &model.SBOM{
		Components: []model.Component{{
			BOMRef:  "comp-mystery",
			Name:    "mystery-pkg",
			Version: "9.9.9",
			PURL:    "pkg:apk/alpine/mystery-pkg@9.9.9",
			Evidence: &model.Evidence{
				Locations: []model.EvidenceLocation{
					{Path: "/usr/bin/some-binary"},
				},
			},
		}},
	}
	bundle := image.NewBundle(mustTag(t, "test/alpine:2"), img, sbom)

	if err := New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	comp := findByName(sbom, "mystery-pkg")
	if comp == nil {
		t.Fatal("mystery-pkg missing")
	}
	if comp.LayerInfo == nil {
		t.Fatal("mystery-pkg LayerInfo nil — filemap-last-touch must have stamped via Evidence.Locations")
	}
	if got := comp.Properties[model.PropertyLayerSource]; got != "filemap-last-touch" {
		t.Errorf("astinus:layer:source = %q, want filemap-last-touch (apk-earliest had nothing to override with)",
			got)
	}
}

func findByName(sbom *model.SBOM, name string) *model.Component {
	for i := range sbom.Components {
		if sbom.Components[i].Name == name {
			return &sbom.Components[i]
		}
	}
	return nil
}
