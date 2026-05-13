package basediff

import (
	"strings"
	"testing"
)

// TestKnownBases_ContainsTrixie pins the S6-T3 catalogue refresh.
// `debian:13-slim` (Debian trixie) ships in the bundled snapshot;
// LookupByOSRelease for a trixie image must return both the
// `13-slim` entry and the `trixie-slim` floating tag. Run #4 driver:
// postgres:17 is based on debian:trixie-slim, pre-S6 0 % origin
// coverage. ADR-0060.
func TestKnownBases_ContainsTrixie(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}

	entries := k.LookupByOSRelease(&OSRelease{
		ID:        "debian",
		VersionID: "13",
	})
	if len(entries) == 0 {
		t.Fatalf("no debian:13 entries — catalogue refresh missed trixie")
	}

	var hasSlim, hasFloating bool
	for _, e := range entries {
		switch e.ImageRef {
		case "debian:13-slim":
			hasSlim = true
		case "debian:trixie-slim":
			hasFloating = true
		}
	}
	if !hasSlim {
		t.Errorf("missing debian:13-slim in catalogue (got entries %+v)", entries)
	}
	if !hasFloating {
		t.Errorf("missing debian:trixie-slim in catalogue (got entries %+v)", entries)
	}
}

// TestKnownBases_ContainsPythonSlimVariants asserts the Python
// :slim layered intermediate bases land in the catalogue. Sprint 6
// Task 4 will use these for layered base detection on B-airflow
// (python:3.13-slim-bookworm). ADR-0060 ships the data; Task 4
// wires the detection logic.
func TestKnownBases_ContainsPythonSlimVariants(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	want := []string{
		"python:3.12-slim-bookworm",
		"python:3.13-slim-bookworm",
		"python:3.13-slim-trixie",
	}
	have := map[string]bool{}
	for _, e := range k.Entries() {
		have[e.ImageRef] = true
	}
	for _, ref := range want {
		if !have[ref] {
			t.Errorf("missing python:slim entry %q", ref)
		}
	}
}

// TestKnownBases_UniqueDistroIDs pins the deduplication + sort
// contract that the FallbackReason builder relies on. Order is
// alphabetical so the operator-visible diagnostic is stable across
// runs. S6 Task 3.
func TestKnownBases_UniqueDistroIDs(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	got := k.UniqueDistroIDs()
	if len(got) == 0 {
		t.Fatal("UniqueDistroIDs returned empty")
	}
	// Spot-check: every entry must appear in the catalogue. Order
	// must be sorted alphabetical.
	want := []string{"almalinux", "alpine", "debian", "rhel", "rocky", "ubuntu"}
	for _, distro := range want {
		found := false
		for _, g := range got {
			if g == distro {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("UniqueDistroIDs missing %q (got %v)", distro, got)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("UniqueDistroIDs not sorted: %v", got)
			break
		}
	}
}

// TestKnownBases_VersionsForDistro pins the per-distro version
// listing that the FallbackReason builder uses to tell operators
// "we know debian, but only versions 11, 12, 13 — not 14".
// S6 Task 3.
func TestKnownBases_VersionsForDistro(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	versions := k.VersionsForDistro("debian")
	want := []string{"11", "12", "13"}
	for _, w := range want {
		found := false
		for _, v := range versions {
			if v == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("VersionsForDistro(debian) missing %q (got %v)", w, versions)
		}
	}

	// Case-insensitive distro ID lookup.
	if got := k.VersionsForDistro("DEBIAN"); len(got) == 0 {
		t.Errorf("VersionsForDistro is case-sensitive; should match DEBIAN")
	}
	// Unknown distro → empty slice (NOT nil) — so downstream
	// `strings.Join(versions, ", ")` doesn't render `<nil>`.
	if got := k.VersionsForDistro("does-not-exist"); len(got) != 0 {
		t.Errorf("VersionsForDistro(does-not-exist) = %v, want empty", got)
	}
}

// TestAutoDetect_NoKnownBaseProducesActionableReason — S6 Task 3
// extended the FallbackReason path. An image whose os-release names
// a distro NOT in the catalogue must surface the known-distro list
// + remediation hint, not just a generic "no known base for X Y"
// blurb. ADR-0060.
func TestAutoDetect_NoKnownBaseProducesActionableReason(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	d := NewAutoDetector(k, 0.70)
	got := d.buildNoKnownBaseReason(&OSRelease{ID: "obscure-distro", VersionID: "1.0"})

	for _, want := range []string{
		"obscure-distro",
		"1.0",
		"Known distros",
		"refresh",
		"--base",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FallbackReason missing %q\nfull reason: %s", want, got)
		}
	}
}

// TestAutoDetect_NoKnownVersionReportsVersionsForKnownDistro asserts
// the reason includes per-distro version list when the distro IS
// known but the requested VersionID isn't. Run-#4 driver: pre-S6
// snapshot listed debian 11 + 12 but not 13 (trixie); operators on
// postgres:17 saw just "no known base for debian 13" with no
// indication that debian was actually known + which versions were.
// S6-T3 closes this — though after the refresh, debian:13 is in
// the catalogue, the FallbackReason path still must work for a
// future debian:14 scenario.
func TestAutoDetect_NoKnownVersionReportsVersionsForKnownDistro(t *testing.T) {
	k, err := LoadBundledKnownBases()
	if err != nil {
		t.Fatalf("LoadBundledKnownBases: %v", err)
	}
	d := NewAutoDetector(k, 0.70)
	got := d.buildNoKnownBaseReason(&OSRelease{ID: "debian", VersionID: "999"})

	for _, want := range []string{
		"debian", "999",
		"Known versions for debian",
		"11", "12", "13",
		"refresh",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FallbackReason missing %q\nfull reason: %s", want, got)
		}
	}
}

// TestAutoDetect_NoKnownBaseReason_NilKnownBases — defensive: a
// detector built with nil KnownBases (testing edge case) must
// still produce a non-empty string rather than panicking.
func TestAutoDetect_NoKnownBaseReason_NilKnownBases(t *testing.T) {
	d := &AutoDetector{}
	got := d.buildNoKnownBaseReason(&OSRelease{ID: "anything", VersionID: "1"})
	if got == "" {
		t.Error("nil KnownBases produced empty FallbackReason")
	}
	if !strings.Contains(got, "catalogue unavailable") {
		t.Errorf("FallbackReason = %q, want mention of catalogue unavailable", got)
	}
}
