package untracked

import "testing"

func TestClassifyNoiseByPath(t *testing.T) {
	cases := []string{
		"usr/share/man/man1/curl.1.gz",
		"/usr/share/doc/something",
		"usr/share/locale/en/LC_MESSAGES",
		"usr/share/zoneinfo/Asia/Tokyo",
		"var/cache/apt/foo",
		"tmp/scratch",
	}
	for _, p := range cases {
		if got := Classify(p, []byte{0x7f, 'E', 'L', 'F'}); got.Category != CategoryNoise {
			t.Errorf("Classify(%q) = %v, want noise", p, got)
		}
	}
}

func TestClassifyNoiseByExtension(t *testing.T) {
	cases := []string{
		"app/main.pyc",
		"libfoo.la",
		"strings.gmo",
		"locale/en.mo",
		"binary.dwarf",
	}
	for _, p := range cases {
		if got := Classify(p, nil); got.Category != CategoryNoise {
			t.Errorf("Classify(%q) = %v, want noise", p, got)
		}
	}
}

func TestClassifyNoiseByPathContains(t *testing.T) {
	for _, p := range []string{"app/__pycache__/foo.cpython-310.pyc", "home/u/.cache/pip"} {
		if got := Classify(p, nil); got.Category != CategoryNoise {
			t.Errorf("Classify(%q) = %v, want noise", p, got)
		}
	}
}

func TestClassifyStaticArchive(t *testing.T) {
	if Classify("usr/lib/libfoo.a", nil).Category != CategoryStaticArchive {
		t.Error("expected static-archive category")
	}
}

func TestClassifyLibraryByExtension(t *testing.T) {
	for _, p := range []string{"lib/libfoo.so", "Frameworks/X.dylib", "win/foo.dll"} {
		if got := Classify(p, nil); got.Category != CategoryLibrary {
			t.Errorf("Classify(%q) = %v, want library", p, got)
		}
	}
}

func TestClassifyArchiveByExtension(t *testing.T) {
	for _, p := range []string{"app/lib.jar", "app/web.war", "app/x.ear"} {
		if got := Classify(p, []byte{'P', 'K', 0x03, 0x04}); got.Category != CategoryArchive {
			t.Errorf("Classify(%q) = %v, want archive", p, got)
		}
	}
}

func TestClassifyExecutableByMagic(t *testing.T) {
	cases := map[string][]byte{
		"opt/bin/foo":     {0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
		"opt/bin/foo.exe": {'M', 'Z', 0x90},
		"opt/bin/foo-mac": {0xfe, 0xed, 0xfa, 0xcf},
	}
	for p, magic := range cases {
		if got := Classify(p, magic); got.Category != CategoryExecutable {
			t.Errorf("Classify(%q) = %v, want executable", p, got)
		}
	}
}

func TestClassifyArchiveByMagic(t *testing.T) {
	if got := Classify("opt/foo.bin", []byte{'P', 'K', 0x03, 0x04}); got.Category != CategoryArchive {
		t.Errorf("Classify zip-by-magic = %v", got)
	}
}

func TestClassifyScript(t *testing.T) {
	if got := Classify("opt/bin/run", []byte("#!/bin/sh")); got.Category != CategoryScript {
		t.Errorf("Classify shebang = %v", got)
	}
}

func TestClassifyConfig(t *testing.T) {
	for _, p := range []string{"etc/app.yaml", "etc/app.json", "etc/app.toml", "certs/server.crt", "README.md"} {
		if got := Classify(p, nil); got.Category != CategoryConfig {
			t.Errorf("Classify(%q) = %v, want config", p, got)
		}
	}
}

func TestClassifyUnknown(t *testing.T) {
	if got := Classify("opt/data/blob", []byte{0xab, 0xcd}); got.Category != CategoryUnknown {
		t.Errorf("Classify unknown bytes = %v", got)
	}
}

func TestCategoryString(t *testing.T) {
	want := map[Category]string{
		CategoryExecutable:    "executable",
		CategoryArchive:       "archive",
		CategoryLibrary:       "library",
		CategoryScript:        "script",
		CategoryConfig:        "config",
		CategoryStaticArchive: "static-archive",
		CategoryNoise:         "noise",
		CategoryUnknown:       "unknown",
	}
	for c, s := range want {
		if got := categoryString(c); got != s {
			t.Errorf("categoryString(%d) = %q, want %q", c, got, s)
		}
	}
}
