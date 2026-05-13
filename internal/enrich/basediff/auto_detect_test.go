package basediff

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ─── parseOSRelease ───────────────────────────────────────────────────

func TestParseOSRelease_KeyValueFormat(t *testing.T) {
	body := `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.23.3
PRETTY_NAME="Alpine Linux v3.23"
HOME_URL="https://alpinelinux.org/"
`
	rel, err := parseOSRelease(strings.NewReader(body), "etc/os-release")
	if err != nil {
		t.Fatalf("parseOSRelease: %v", err)
	}
	if rel.ID != "alpine" {
		t.Errorf("ID = %q, want alpine", rel.ID)
	}
	if rel.VersionID != "3.23.3" {
		t.Errorf("VersionID = %q, want 3.23.3", rel.VersionID)
	}
	if rel.PrettyName != "Alpine Linux v3.23" {
		t.Errorf("PrettyName = %q", rel.PrettyName)
	}
	if rel.Raw["HOME_URL"] != "https://alpinelinux.org/" {
		t.Errorf("Raw[HOME_URL] = %q", rel.Raw["HOME_URL"])
	}
}

func TestParseOSRelease_AlpineReleaseFormat(t *testing.T) {
	rel, err := parseOSRelease(strings.NewReader("3.20.6\n"), "etc/alpine-release")
	if err != nil {
		t.Fatalf("parseOSRelease: %v", err)
	}
	if rel.ID != "alpine" || rel.VersionID != "3.20.6" {
		t.Errorf("got id=%q version=%q, want alpine/3.20.6", rel.ID, rel.VersionID)
	}
}

func TestParseOSRelease_IgnoresCommentsAndBlanks(t *testing.T) {
	body := `
# top comment
ID=debian
VERSION_ID="12"

PRETTY_NAME=Debian
`
	rel, _ := parseOSRelease(strings.NewReader(body), "etc/os-release")
	if rel.ID != "debian" || rel.VersionID != "12" {
		t.Errorf("got id=%q version=%q, want debian/12", rel.ID, rel.VersionID)
	}
}

// ─── readFileFromImage + readOSReleaseFromImage ───────────────────────

func TestReadFileFromImage_FoundAndShortCircuits(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("etc/os-release", `ID=alpine
VERSION_ID=3.20`))
	body, info, err := readFileFromImage(context.Background(), img, "etc/os-release")
	if err != nil {
		t.Fatalf("readFileFromImage: %v", err)
	}
	if !strings.Contains(string(body), "ID=alpine") {
		t.Errorf("body = %q", string(body))
	}
	if info.Index != 0 {
		t.Errorf("info.Index = %d, want 0", info.Index)
	}
}

func TestReadFileFromImage_NotFound(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("opt/something", "x"))
	_, _, err := readFileFromImage(context.Background(), img, "etc/os-release")
	if err == nil {
		t.Fatal("expected fs_ErrNotExist, got nil")
	}
}

func TestReadOSReleaseFromImage_HappyPath(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("etc/os-release",
		`ID=alpine
VERSION_ID=3.20`))
	rel, err := readOSReleaseFromImage(context.Background(), img)
	if err != nil {
		t.Fatalf("readOSReleaseFromImage: %v", err)
	}
	if rel == nil || rel.ID != "alpine" || rel.VersionID != "3.20" {
		t.Errorf("rel = %+v", rel)
	}
	if rel.SourcePath != "etc/os-release" {
		t.Errorf("SourcePath = %q", rel.SourcePath)
	}
}

func TestReadOSReleaseFromImage_AlpineReleaseFallback(t *testing.T) {
	// No /etc/os-release; only /etc/alpine-release with bare version.
	img := buildImageWithLayers(t, layerOf("etc/alpine-release", "3.18.4\n"))
	rel, err := readOSReleaseFromImage(context.Background(), img)
	if err != nil {
		t.Fatalf("readOSReleaseFromImage: %v", err)
	}
	if rel == nil || rel.ID != "alpine" || rel.VersionID != "3.18.4" {
		t.Errorf("rel = %+v", rel)
	}
}

func TestReadOSReleaseFromImage_ScratchReturnsSentinel(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("usr/local/bin/app", "binary"))
	rel, err := readOSReleaseFromImage(context.Background(), img)
	if rel != nil {
		t.Errorf("rel = %+v, want nil (scratch-like image)", rel)
	}
	if !errors.Is(err, errNoOSRelease) {
		t.Errorf("err = %v, want errNoOSRelease", err)
	}
}

// ─── KnownBases ───────────────────────────────────────────────────────

func TestLoadBundledKnownBases_HasMinimumCoverage(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	entries := k.Entries()
	if len(entries) < 10 {
		t.Errorf("bundled known-bases catalogue has %d entries, want >= 10", len(entries))
	}
	wantIDs := map[string]bool{"alpine": false, "debian": false, "ubuntu": false}
	for _, e := range entries {
		wantIDs[e.ID] = true
	}
	for id, present := range wantIDs {
		if !present {
			t.Errorf("known-bases missing entry for %s", id)
		}
	}
}

func TestKnownBases_LookupByOSRelease(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	cases := []struct {
		id, version string
		wantCount   int
	}{
		{"alpine", "3.20", 1},
		{"alpine", "3.20.6", 1}, // prefix-matches
		{"alpine", "99.0", 0},
		// debian:12 entries: debian:12-slim, debian:bookworm-slim,
		// gcr.io/distroless/base-debian12, python:3.12-slim-bookworm,
		// python:3.13-slim-bookworm. S6 Task 3 added the two
		// python:slim entries; S6 Task 4 added debian:bookworm-slim
		// (parent target for python:slim's parent_base link).
		{"debian", "12", 5},
		{"debian", "12.5", 5},
		// S6 Task 3 added debian 13 (trixie): debian:13-slim,
		// debian:trixie-slim, python:3.13-slim-trixie.
		{"debian", "13", 3},
		{"debian", "13.8", 3}, // prefix-matches
		{"ubuntu", "22.04", 1},
		{"unknown", "1", 0},
	}
	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.version, func(t *testing.T) {
			got := k.LookupByOSRelease(&OSRelease{ID: tc.id, VersionID: tc.version})
			if len(got) != tc.wantCount {
				t.Errorf("LookupByOSRelease(%s, %s) = %d entries, want %d (got %+v)",
					tc.id, tc.version, len(got), tc.wantCount, got)
			}
		})
	}
}

func TestKnownBases_LookupRejectsNilInputs(t *testing.T) {
	k, _ := LoadBundledKnownBases()
	if got := k.LookupByOSRelease(nil); len(got) != 0 {
		t.Errorf("nil OSRelease should yield 0 entries; got %v", got)
	}
	if got := k.LookupByOSRelease(&OSRelease{}); len(got) != 0 {
		t.Errorf("empty OSRelease should yield 0 entries; got %v", got)
	}
	var nilK *KnownBases
	if got := nilK.LookupByOSRelease(&OSRelease{ID: "alpine"}); len(got) != 0 {
		t.Errorf("nil KnownBases must be safe to call; got %v", got)
	}
}

func TestVersionMatches(t *testing.T) {
	cases := []struct {
		known, target string
		want          bool
	}{
		{"3.23.3", "3.23.3", true},
		{"3.20", "3.20.6", true},
		{"3.20", "3.21.0", false},
		{"12", "12.5", true},
		{"12", "13.0", false},
		{"", "12", false}, // both must be non-empty to match
		{"12", "", false},
		{"22.04", "22.04", true},
	}
	for _, tc := range cases {
		if got := versionMatches(tc.known, tc.target); got != tc.want {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", tc.known, tc.target, got, tc.want)
		}
	}
}

// ─── AutoDetector ─────────────────────────────────────────────────────

func TestAutoDetect_AlpineFromOSRelease(t *testing.T) {
	img := buildImageWithLayers(t,
		map[string]string{
			"etc/os-release": `ID=alpine
VERSION_ID=3.20.6`,
			"etc/alpine-release":   "3.20.6\n",
			"etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n",
			"lib/apk/db/installed": "P:musl\nV:1.2.5\n",
		})

	k, _ := LoadBundledKnownBases()
	d := NewAutoDetector(k, 0.70)

	r, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if r.BaseImageRef != "alpine:3.20" {
		t.Errorf("BaseImageRef = %q, want alpine:3.20", r.BaseImageRef)
	}
	if r.Method != "os-release+known-bases" {
		t.Errorf("Method = %q, want os-release+known-bases", r.Method)
	}
	if r.Confidence < 0.70 {
		t.Errorf("Confidence = %.2f, want >= 0.70", r.Confidence)
	}
	if r.OSReleaseID != "alpine" || r.OSReleaseVersionID != "3.20.6" {
		t.Errorf("os-release id/version = %q/%q", r.OSReleaseID, r.OSReleaseVersionID)
	}
}

func TestAutoDetect_ScratchFallsBack(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("usr/local/bin/app", "binary"))
	k, _ := LoadBundledKnownBases()
	d := NewAutoDetector(k, 0.70)
	r, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if r.BaseImageRef != "" {
		t.Errorf("expected no base on scratch; got %q", r.BaseImageRef)
	}
	if !strings.Contains(r.FallbackReason, "os-release") {
		t.Errorf("FallbackReason = %q, want mention of os-release", r.FallbackReason)
	}
}

func TestAutoDetect_UnknownDistroFallsBack(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("etc/os-release",
		`ID=customdistro
VERSION_ID=1`))
	k, _ := LoadBundledKnownBases()
	d := NewAutoDetector(k, 0.70)
	r, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if r.BaseImageRef != "" {
		t.Errorf("expected no base on unknown distro; got %q", r.BaseImageRef)
	}
	if !strings.Contains(r.FallbackReason, "no known base") {
		t.Errorf("FallbackReason = %q, want 'no known base'", r.FallbackReason)
	}
	if r.OSReleaseID != "customdistro" {
		t.Errorf("os-release ID stamp = %q", r.OSReleaseID)
	}
}

func TestAutoDetect_BelowConfidenceFallsBack(t *testing.T) {
	// Only os-release present — sample-file presence = 0/4 in the
	// catalogue, so score = 0.50 base + 0 presence = 0.50 < threshold.
	img := buildImageWithLayers(t, layerOf("etc/os-release",
		`ID=alpine
VERSION_ID=3.20`))
	k, _ := LoadBundledKnownBases()
	d := NewAutoDetector(k, 0.70)
	r, err := d.Detect(context.Background(), img)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if r.BaseImageRef != "" {
		t.Errorf("expected no base when below threshold; got %q (conf=%.2f)",
			r.BaseImageRef, r.Confidence)
	}
	if !strings.Contains(r.FallbackReason, "below threshold") {
		t.Errorf("FallbackReason = %q", r.FallbackReason)
	}
}

// ─── Enricher integration: stampDetectionMetadata via resolveBaseRef ──

func TestEnrich_AutoStampsDetectionMetadata(t *testing.T) {
	img := buildImageWithLayers(t,
		map[string]string{
			"etc/os-release": `ID=alpine
VERSION_ID=3.20`,
			"etc/alpine-release":   "3.20\n",
			"etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n",
			"lib/apk/db/installed": "P:musl\n",
		})
	sbom := sampleSBOM()
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := NewWithOptions(Options{Mode: ModeAuto}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	got := sbom.Metadata.Properties["astinus:basediff:detection-method"]
	if got != "os-release+known-bases" {
		t.Errorf("detection-method = %q, want os-release+known-bases", got)
	}
	if base := sbom.Metadata.Properties["astinus:basediff:detected-base"]; base != "alpine:3.20" {
		t.Errorf("detected-base = %q, want alpine:3.20", base)
	}
	if id := sbom.Metadata.Properties["astinus:basediff:os-release-id"]; id != "alpine" {
		t.Errorf("os-release-id = %q, want alpine", id)
	}
}

func TestEnrich_AutoStampsFallbackReasonOnScratch(t *testing.T) {
	img := buildImageWithLayers(t, layerOf("usr/local/bin/app", "binary"))
	sbom := sampleSBOM()
	bundle := image.NewBundle(mustTag(t), img, sbom)

	if err := NewWithOptions(Options{Mode: ModeAuto}).Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if base := sbom.Metadata.Properties["astinus:basediff:detected-base"]; base != "" {
		t.Errorf("detected-base = %q, want empty on scratch", base)
	}
	if reason := sbom.Metadata.Properties["astinus:basediff:detection-fallback-reason"]; reason == "" {
		t.Errorf("detection-fallback-reason missing on scratch")
	}
}

// ensure model is imported even when an indirect helper changes.
var _ = model.OriginUnknown
