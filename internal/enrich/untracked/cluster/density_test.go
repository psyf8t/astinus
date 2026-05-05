package cluster

import "testing"

func TestParseNameVersionFromDirNamePatterns(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
		ok       bool
	}{
		{"sqlite-version-3.44.0", "sqlite", "3.44.0", true},
		{"bootstrap-5.3.2", "bootstrap", "5.3.2", true},
		{"linux_4.19.0", "linux", "4.19.0", true},
		{"yq-v4.40.5", "yq", "4.40.5", true},
		{"rust-1.75.0", "rust", "1.75.0", true},
		{"jq-1.7", "jq", "1.7", true},
		{"libsodium-1.0.18", "libsodium", "1.0.18", true},
		// Negatives
		{"random-folder", "", "", false},
		{"etc", "", "", false},
		{"node_modules", "", "", false},
		// Edge: numbers-only basename — not a recognised package name
		{"3.44.0", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			gotName, gotVer, gotOk := parseNameVersionFromDirName(tc.in)
			if gotOk != tc.ok {
				t.Errorf("ok = %v, want %v", gotOk, tc.ok)
			}
			if tc.ok && (gotName != tc.wantName || gotVer != tc.wantVer) {
				t.Errorf("name/version = (%q,%q), want (%q,%q)",
					gotName, gotVer, tc.wantName, tc.wantVer)
			}
		})
	}
}

func TestScoreDirectoryAutotools(t *testing.T) {
	children := []string{"Makefile", "configure", "src", "include", "README", "LICENSE", "test"}
	sig, score := scoreDirectory("opt/extracted/sqlite-3.44.0", children, 1500)
	// 5 (autotools) + 5 (versionInName) + 3 (src+include) + 2 (test) + 2 (license+readme) + 1 (>100) + 2 (>1000) = 20
	if score < densityScoreThreshold {
		t.Errorf("score = %d, want ≥ %d", score, densityScoreThreshold)
	}
	if sig.versionInDirName != "3.44.0" {
		t.Errorf("versionInDirName = %q", sig.versionInDirName)
	}
	if !sig.hasMakefile || !sig.hasConfigure {
		t.Errorf("autotools signal not detected: %+v", sig)
	}
}

func TestScoreDirectoryRandomEtcDoesNotCluster(t *testing.T) {
	children := []string{"hostname", "passwd", "foo.conf"}
	_, score := scoreDirectory("etc", children, 3)
	if score >= densityScoreThreshold {
		t.Errorf("score = %d, want < %d for /etc/ shape", score, densityScoreThreshold)
	}
}

func TestDensityIdentityVersionInName(t *testing.T) {
	sig := signature{versionInDirName: "3.44.0", dirNameStripped: "sqlite", fileCount: 1500}
	id, ok := densityIdentity("opt/extracted/sqlite-3.44.0", sig, 12)
	if !ok {
		t.Fatal("densityIdentity returned !ok")
	}
	if id.Name != "sqlite" || id.Version != "3.44.0" {
		t.Errorf("identity = %+v", id)
	}
	if id.Type != "generic" {
		t.Errorf("Type = %q", id.Type)
	}
	if id.Confidence < 0.7 {
		t.Errorf("Confidence = %v, want ≥ 0.7", id.Confidence)
	}
	if id.PURL == "" {
		t.Error("PURL should be populated")
	}
}

func TestDensityIdentityNoVersionFallsBackToBasename(t *testing.T) {
	sig := signature{fileCount: 200} // versionInDirName empty
	id, ok := densityIdentity("opt/myapp", sig, 9)
	if !ok {
		t.Fatal("densityIdentity returned !ok")
	}
	if id.Name != "myapp" {
		t.Errorf("Name = %q, want myapp (basename fallback)", id.Name)
	}
	if id.Version != "" {
		t.Errorf("Version = %q, want empty", id.Version)
	}
}

func TestDensityIdentityRejectsRootDir(t *testing.T) {
	sig := signature{}
	if _, ok := densityIdentity("", sig, 8); ok {
		t.Error("densityIdentity should reject empty dir")
	}
}
