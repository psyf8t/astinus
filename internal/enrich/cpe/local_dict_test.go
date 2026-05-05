package cpe

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalDictResolverByPurl(t *testing.T) {
	dir := t.TempDir()
	cpeDir := filepath.Join(dir, "cpe", "by-purl")
	if err := os.MkdirAll(cpeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(localCPEEntry{Vendor: "expressjs", Product: "express"})
	// File name = percent-encoded canonical PURL. Operators use the
	// inverse mapping when populating the catalogue.
	purl := "pkg:npm/express@4.18.2"
	encoded := "pkg%3Anpm%2Fexpress%404.18.2"
	if err := os.WriteFile(filepath.Join(cpeDir, encoded+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewLocalDictionaryResolver()
	if err := r.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	t.Logf("dictionary loaded %d entries; byPurl=%v", r.Len(), r.byPurl)
	p, _ := ParsePURL(purl)
	t.Logf("parsed PURL canonical = %q", p.String())
	matches := r.Resolve(p)
	if len(matches) != 1 {
		t.Fatalf("matches = %v", matches)
	}
	if matches[0].Source != SourceLocalDict || matches[0].Confidence != ConfidenceHigh {
		t.Errorf("got %+v", matches[0])
	}
	if matches[0].CPE != "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q", matches[0].CPE)
	}
}

func TestLocalDictResolverByName(t *testing.T) {
	dir := t.TempDir()
	nameDir := filepath.Join(dir, "cpe", "by-name", "npm")
	if err := os.MkdirAll(nameDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(localCPEEntry{Vendor: "internalcorp", Product: "thing"})
	if err := os.WriteFile(filepath.Join(nameDir, "thing.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewLocalDictionaryResolver()
	if err := r.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	p, _ := ParsePURL("pkg:npm/thing@2.0")
	matches := r.Resolve(p)
	if len(matches) != 1 {
		t.Fatalf("matches = %v", matches)
	}
	if matches[0].CPE != "cpe:2.3:a:internalcorp:thing:2.0:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q", matches[0].CPE)
	}
}

func TestLocalDictResolverMissDirNoOp(t *testing.T) {
	r := NewLocalDictionaryResolver()
	if err := r.LoadFromDir("/no/such/dir"); err != nil {
		t.Errorf("missing dir should be a no-op, got %v", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d", r.Len())
	}
}

func TestLocalDictResolverNoMatch(t *testing.T) {
	r := NewLocalDictionaryResolver()
	p, _ := ParsePURL("pkg:gem/whatever@1")
	if got := r.Resolve(p); len(got) != 0 {
		t.Errorf("want no matches, got %v", got)
	}
}

func TestChainWithLocalEmptyPathReturnsDefault(t *testing.T) {
	c, err := ChainWithLocal("")
	if err != nil {
		t.Fatalf("ChainWithLocal: %v", err)
	}
	if c == nil {
		t.Fatal("nil chain")
	}
}

func TestChainWithLocalSlotsBetweenBundledAndHeuristic(t *testing.T) {
	dir := t.TempDir()
	nameDir := filepath.Join(dir, "cpe", "by-name", "pypi")
	if err := os.MkdirAll(nameDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(localCPEEntry{Vendor: "myco", Product: "myproj"})
	if err := os.WriteFile(filepath.Join(nameDir, "myproj.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	chain, err := ChainWithLocal(dir)
	if err != nil {
		t.Fatalf("ChainWithLocal: %v", err)
	}

	// pypi/myproj has no bundled entry, so the chain should fall
	// through to the local resolver (NOT the heuristic).
	p, _ := ParsePURL("pkg:pypi/myproj@1.0")
	matches := chain.Resolve(p)
	if len(matches) != 1 {
		t.Fatalf("matches = %v", matches)
	}
	want := "cpe:2.3:a:myco:myproj:1.0:*:*:*:*:*:*:*"
	if matches[0].CPE != want {
		t.Errorf("CPE = %q, want %q (local should beat heuristic)", matches[0].CPE, want)
	}
}

func TestPurlFromFileBaseEmpty(t *testing.T) {
	if _, err := purlFromFileBase(""); err == nil {
		t.Error("expected error for empty base")
	}
}

// TestLoadFromDirSkipsCorruptEntriesWithWarn — corrupt JSON / bad
// names must not abort the whole load, but they MUST emit warn
// records via the configured logger. post-stage-13 review F-010.
func TestLoadFromDirSkipsCorruptEntriesWithWarn(t *testing.T) {
	dir := t.TempDir()
	purlDir := filepath.Join(dir, "cpe", "by-purl")
	if err := os.MkdirAll(purlDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// One good entry.
	good, _ := json.Marshal(localCPEEntry{Vendor: "co", Product: "good"})
	if err := os.WriteFile(filepath.Join(purlDir, "pkg%3Anpm%2Fgood%401.json"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	// One corrupt entry (not JSON).
	if err := os.WriteFile(filepath.Join(purlDir, "pkg%3Anpm%2Fbad%401.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// One unparseable name (invalid percent-escape at the very end).
	if err := os.WriteFile(filepath.Join(purlDir, "abc%ZZ.json"), good, 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture log records by handing the resolver a logger that
	// writes JSON to a buffer.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	r := NewLocalDictionaryResolver()
	r.SetLogger(logger)
	if err := r.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}

	// Expect: 1 good entry loaded, 2 skipped.
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"cpe.local.skip"`) {
		t.Error("expected at least one cpe.local.skip warn record")
	}
	if !strings.Contains(out, `"msg":"cpe.local.loaded"`) {
		t.Error("expected cpe.local.loaded summary record")
	}
	if !strings.Contains(out, `"skipped":2`) {
		t.Errorf("expected skipped:2 in summary; got: %s", out)
	}
}
