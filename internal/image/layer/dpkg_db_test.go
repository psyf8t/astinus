package layer

import (
	"context"
	"strings"
	"testing"
)

const sampleDpkgStatus = `Package: libc6
Status: install ok installed
Priority: required
Section: libs
Version: 2.41-12+deb13u2
Architecture: arm64
Multi-Arch: same
Depends: libgcc-s1

Package: zlib1g
Status: install ok installed
Version: 1:1.3.dfsg+really1.3.1-1+b1
Architecture: arm64

Package: libssl3
Status: install ok installed
Version: 3.5.5-r0
Architecture: arm64
`

func TestParseDpkgStatus(t *testing.T) {
	got := parseDpkgStatus(strings.NewReader(sampleDpkgStatus))
	want := []dpkgRecord{
		{Name: "libc6", Version: "2.41-12+deb13u2"},
		{Name: "zlib1g", Version: "1:1.3.dfsg+really1.3.1-1+b1"},
		{Name: "libssl3", Version: "3.5.5-r0"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("record %d = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseDpkgStatus_TrailingRecordWithoutBlankLine(t *testing.T) {
	body := `Package: libc6
Version: 2.41-12+deb13u2`
	got := parseDpkgStatus(strings.NewReader(body))
	if len(got) != 1 || got[0].Name != "libc6" || got[0].Version != "2.41-12+deb13u2" {
		t.Errorf("got %+v, want [libc6/2.41-12+deb13u2]", got)
	}
}

func TestParseDpkgStatus_IgnoresContinuationLines(t *testing.T) {
	body := `Package: libc6
Version: 2.41-12+deb13u2
Description: GNU C Library: shared libraries
 This package contains the standard library used by
 most programs.
Maintainer: Aurelien Jarno <aurel32@debian.org>
`
	got := parseDpkgStatus(strings.NewReader(body))
	if len(got) != 1 || got[0].Version != "2.41-12+deb13u2" {
		t.Errorf("multi-line continuation broke parser: got %+v", got)
	}
}

func TestParseDpkgStatus_EmptyInput(t *testing.T) {
	if got := parseDpkgStatus(strings.NewReader("")); len(got) != 0 {
		t.Errorf("empty input → %d records, want 0", len(got))
	}
	if got := parseDpkgStatus(nil); got != nil {
		t.Errorf("nil reader → %v, want nil", got)
	}
}

func TestDpkgRecordKey(t *testing.T) {
	cases := []struct{ name, ver, want string }{
		{"libc6", "2.41-12+deb13u2", "libc6@2.41-12+deb13u2"},
		{"zlib1g", "", "zlib1g"},
		{"", "1.0", ""},
	}
	for _, c := range cases {
		if got := dpkgRecordKey(c.name, c.ver); got != c.want {
			t.Errorf("dpkgRecordKey(%q, %q) = %q, want %q", c.name, c.ver, got, c.want)
		}
	}
}

func TestSplitDpkgLine(t *testing.T) {
	cases := []struct {
		in   string
		k, v string
		want bool
	}{
		{"Package: libc6", "Package", "libc6", true},
		{"Version:2.41-12", "Version", "2.41-12", true}, // no space after colon
		{"no-colon", "", "", false},
		{":empty-key", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		k, v, ok := splitDpkgLine(c.in)
		if ok != c.want || k != c.k || v != c.v {
			t.Errorf("splitDpkgLine(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, k, v, ok, c.k, c.v, c.want)
		}
	}
}

// TestWalk_DpkgEarliestLayer drives a 3-layer image whose
// `/var/lib/dpkg/status` body grows across layers (apt-install
// events). The earliest-layer index must point at the FIRST
// layer that listed each package. S7 Task 3 / ADR-0060
// amendment.
func TestWalk_DpkgEarliestLayer(t *testing.T) {
	layer0 := "Package: libc6\nVersion: 2.41-12+deb13u2\n\nPackage: bash\nVersion: 5.2.21-2\n"
	layer1 := layer0 + "\nPackage: libpq5\nVersion: 17.0-1\n"
	layer2 := layer1 + "\nPackage: postgresql-17\nVersion: 17.0-1\n"

	img := buildImage(t, []layerSpec{
		{files: map[string]string{DpkgStatusPath: layer0}},
		{files: map[string]string{DpkgStatusPath: layer1}},
		{files: map[string]string{DpkgStatusPath: layer2}},
	})

	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	cases := []struct {
		name, version string
		wantIdx       int
	}{
		{"libc6", "2.41-12+deb13u2", 0},
		{"bash", "5.2.21-2", 0},
		{"libpq5", "17.0-1", 1},
		{"postgresql-17", "17.0-1", 2},
	}
	for _, c := range cases {
		info, ok := m.DpkgEarliestLayer(c.name, c.version)
		if !ok {
			t.Errorf("DpkgEarliestLayer(%q, %q) miss — expected layer %d",
				c.name, c.version, c.wantIdx)
			continue
		}
		if info.Index != c.wantIdx {
			t.Errorf("DpkgEarliestLayer(%q, %q) = layer %d, want %d",
				c.name, c.version, info.Index, c.wantIdx)
		}
	}

	if _, ok := m.DpkgEarliestLayer("missing-pkg", "1.0"); ok {
		t.Errorf("missing-pkg should return false")
	}
}

// TestWalk_NoDpkgStatus asserts an image without
// /var/lib/dpkg/status returns false for any query — Alpine
// images, scratch-based, etc.
func TestWalk_NoDpkgStatus(t *testing.T) {
	img := buildImage(t, []layerSpec{
		{files: map[string]string{"usr/bin/app": "binary"}},
	})

	m, err := Walk(context.Background(), img)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if _, ok := m.DpkgEarliestLayer("anything", "1.0"); ok {
		t.Errorf("DpkgEarliestLayer on non-debian image should return false")
	}
}
