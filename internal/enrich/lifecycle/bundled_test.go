package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundled_EmbeddedSnapshotParses(t *testing.T) {
	b, err := LoadBundled()
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	if b.ProductCount() < 10 {
		t.Errorf("embedded snapshot has %d products, want >= 10 popular ones",
			b.ProductCount())
	}
	for _, want := range []string{"nodejs", "python", "go", "openjdk", "debian", "ubuntu", "alpine", "postgresql", "mysql", "redis", "kubernetes"} {
		if !b.HasProduct(want) {
			t.Errorf("embedded snapshot missing %q", want)
		}
	}
}

func TestBundledSource_FetchKnownCycle(t *testing.T) {
	b, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := b.Fetch(context.Background(), "nodejs", "20")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if lc.Cycle != "20" {
		t.Errorf("cycle = %q, want 20", lc.Cycle)
	}
	if lc.EOL.Format("2006-01-02") != "2026-04-30" {
		t.Errorf("EOL = %v, want 2026-04-30", lc.EOL)
	}
}

func TestBundledSource_UnknownProductReturnsNotFound(t *testing.T) {
	b, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Fetch(context.Background(), "totally-not-real", "1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestBundledSource_UnknownCycleReturnsNotFound(t *testing.T) {
	b, err := LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Fetch(context.Background(), "nodejs", "999")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadBundledFromFile_OperatorOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	body := []byte(`{
  "_": "test",
  "myproduct": [
    {"cycle": "1", "releaseDate": "2024-01-01", "eol": "2026-12-31", "lts": true}
  ]
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundledFromFile(path)
	if err != nil {
		t.Fatalf("LoadBundledFromFile: %v", err)
	}
	if !b.HasProduct("myproduct") {
		t.Errorf("custom product missing")
	}
	if b.HasProduct("nodejs") {
		t.Errorf("operator-supplied snapshot should NOT include the embedded seed's nodejs")
	}
	if b.Name() != "snapshot:"+path {
		t.Errorf("Name = %q, want snapshot:%s", b.Name(), path)
	}
}

func TestLoadBundledFromFile_MissingFileErrors(t *testing.T) {
	_, err := LoadBundledFromFile("/no/such/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadBundledFromFile_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBundledFromFile(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestBundledSource_NameDefault(t *testing.T) {
	b := NewBundled()
	if b.Name() != "bundled" {
		t.Errorf("Name = %q, want bundled", b.Name())
	}
	if b.RequiresNetwork() {
		t.Error("bundled source must not require network")
	}
}

func TestBundledSource_NilSafe(t *testing.T) {
	var b *BundledSource
	if b.HasProduct("nodejs") {
		t.Error("nil should not have any product")
	}
	_, err := b.Fetch(context.Background(), "nodejs", "20")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("nil Fetch err = %v, want ErrNotFound", err)
	}
}
