package layer

import (
	"context"
	"testing"
)

// TestWalk_ApkEarliestLayer drives a synthetic 3-layer image whose
// `/lib/apk/db/installed` body grows across layers (apk add events).
// The earliest-layer index must point at the FIRST layer that listed
// each package, not the LAST. ADR-0059.
//
// Layer 0 (alpine base):     musl, busybox
// Layer 1 (RUN apk add curl): musl, busybox, curl
// Layer 2 (RUN apk add jq):   musl, busybox, curl, jq
//
// Expected ApkEarliestLayer:
//
//	musl@1.2.5-r0    → 0
//	busybox@1.36.1   → 0
//	curl@8.5.0-r0    → 1
//	jq@1.7.1-r0      → 2
func TestWalk_ApkEarliestLayer(t *testing.T) {
	layer0 := "P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n"
	layer1 := "P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r29\n\nP:curl\nV:8.5.0-r0\n"
	layer2 := layer1 + "\nP:jq\nV:1.7.1-r0\n"

	img := buildImage(t, []layerSpec{
		{files: map[string]string{ApkInstalledPath: layer0}},
		{files: map[string]string{ApkInstalledPath: layer1}},
		{files: map[string]string{ApkInstalledPath: layer2}},
	})

	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	cases := []struct {
		name, version string
		wantIdx       int
	}{
		{"musl", "1.2.5-r0", 0},
		{"busybox", "1.36.1-r29", 0},
		{"curl", "8.5.0-r0", 1},
		{"jq", "1.7.1-r0", 2},
	}
	for _, c := range cases {
		info, ok := m.ApkEarliestLayer(c.name, c.version)
		if !ok {
			t.Errorf("ApkEarliestLayer(%q, %q) miss — expected layer %d",
				c.name, c.version, c.wantIdx)
			continue
		}
		if info.Index != c.wantIdx {
			t.Errorf("ApkEarliestLayer(%q, %q) = layer %d, want %d",
				c.name, c.version, info.Index, c.wantIdx)
		}
	}

	if _, ok := m.ApkEarliestLayer("missing-pkg", "1.0"); ok {
		t.Errorf("missing-pkg should return false")
	}
}

// TestWalk_NoApkDB asserts an image without `/lib/apk/db/installed`
// produces a FileMap with an empty apk-earliest index — query
// returns false rather than panicking on nil map. Distroless /
// scratch-based images go through this path.
func TestWalk_NoApkDB(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/app": "binary"}},
	})

	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if _, ok := m.ApkEarliestLayer("anything", "1.0"); ok {
		t.Errorf("ApkEarliestLayer on non-Alpine image should return false")
	}
}

// TestWalk_ApkEarliestUnchangedOnRewrite asserts that subsequent
// layers that rewrite the DB without adding new packages don't move
// the existing entries. Mirrors the production case where `apk del`
// in a later layer would shrink the DB; existing entries' earliest
// index is fixed.
func TestWalk_ApkEarliestUnchangedOnRewrite(t *testing.T) {
	layer0 := "P:musl\nV:1.2.5-r0\n"
	// Layer 1 rewrites the DB with the same musl entry — should
	// NOT bump musl's earliest index from 0 to 1.
	layer1 := "P:musl\nV:1.2.5-r0\n"

	img := buildImage(t, []layerSpec{
		{files: map[string]string{ApkInstalledPath: layer0}},
		{files: map[string]string{ApkInstalledPath: layer1}},
	})

	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	info, ok := m.ApkEarliestLayer("musl", "1.2.5-r0")
	if !ok {
		t.Fatal("musl missing")
	}
	if info.Index != 0 {
		t.Errorf("musl earliest = layer %d, want 0 (rewrite must not move earliest)",
			info.Index)
	}
}
