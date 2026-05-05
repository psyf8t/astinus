package layer

import (
	"context"
	"testing"
)

func TestComputeDiffPrefix(t *testing.T) {
	base := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "v1"}},
		{files: map[string]string{"etc/hostname": "h"}},
	})
	// Target = base + an extra app layer.
	target := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "v1"}},
		{files: map[string]string{"etc/hostname": "h"}},
		{files: map[string]string{"opt/app/main": "x"}},
	})

	d, err := ComputeDiff(context.Background(), target, base)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if d.Mode != DiffModePrefix {
		t.Errorf("Mode = %v, want Prefix", d.Mode)
	}
	// Target & base built from the same buffers, so the prefix
	// should match the base's full layer count.
	if d.BasePrefix != 2 {
		t.Errorf("BasePrefix = %d, want 2", d.BasePrefix)
	}
	if !d.IsBaseLayer(0) || !d.IsBaseLayer(1) {
		t.Error("layers 0 and 1 should be base")
	}
	if d.IsBaseLayer(2) {
		t.Error("layer 2 (app) should NOT be base")
	}
}

func TestComputeDiffFallbackOnPrefixMismatch(t *testing.T) {
	base := buildImage(t, []layerSpec{
		{files: map[string]string{"etc/baseonly": "1"}},
	})
	// Target with completely unrelated layers (random.Image
	// equivalent — distinct content => distinct digest).
	target := buildImage(t, []layerSpec{
		{files: map[string]string{"opt/app/main": "x"}},
		{files: map[string]string{"opt/app/lib": "y"}},
	})

	d, err := ComputeDiff(context.Background(), target, base)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if d.Mode != DiffModeFallback {
		t.Errorf("Mode = %v, want Fallback", d.Mode)
	}
	if !d.IsBasePath("etc/baseonly") {
		t.Error("etc/baseonly should be in BasePaths")
	}
	if d.IsBasePath("opt/app/main") {
		t.Error("opt/app/main should NOT be in BasePaths")
	}
}

func TestComputeDiffFallbackPathNormalization(t *testing.T) {
	base := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/foo": "1"}},
	})
	target := buildImage(t, []layerSpec{
		{files: map[string]string{"opt/app/x": "y"}},
	})
	d, _ := ComputeDiff(context.Background(), target, base)
	if !d.IsBasePath("/usr/bin/foo") {
		t.Error("leading slash should normalize")
	}
	if !d.IsBasePath("./usr/bin/foo") {
		t.Error("leading ./ should normalize")
	}
}

func TestComputeDiffEmptyBase(t *testing.T) {
	base := buildImage(t, nil)
	target := buildImage(t, []layerSpec{
		{files: map[string]string{"opt/app/main": "x"}},
	})
	d, err := ComputeDiff(context.Background(), target, base)
	if err != nil {
		t.Fatalf("ComputeDiff: %v", err)
	}
	if d.Mode != DiffModePrefix {
		t.Errorf("Mode = %v, want Prefix (empty base)", d.Mode)
	}
	if d.BasePrefix != 0 {
		t.Errorf("BasePrefix = %d, want 0", d.BasePrefix)
	}
	// Every target layer should be "app".
	for i := 0; i < 1; i++ {
		if d.IsBaseLayer(i) {
			t.Errorf("layer %d should NOT be base when prefix=0", i)
		}
	}
}

func TestComputeDiffNilArgs(t *testing.T) {
	if _, err := ComputeDiff(context.Background(), nil, nil); err == nil {
		t.Error("expected error on nil target")
	}
	img := buildImage(t, nil)
	if _, err := ComputeDiff(context.Background(), img, nil); err == nil {
		t.Error("expected error on nil base")
	}
}

func TestNilDiffSafe(t *testing.T) {
	var d *Diff
	if d.IsBaseLayer(0) || d.IsBasePath("anything") {
		t.Error("nil Diff predicates must be false")
	}
}
