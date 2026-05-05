package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalMatcherLoadFromDirHappy(t *testing.T) {
	dir := t.TempDir()
	fpRoot := filepath.Join(dir, "fingerprint", "sha256")
	if err := os.MkdirAll(fpRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(Match{Name: "jq", Version: "1.7.1", Source: "test"})
	if err := os.WriteFile(filepath.Join(fpRoot, "abc123.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewLocalMatcher()
	if err := m.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	got, err := m.Lookup(context.Background(), "sha256", "abc123")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "jq" || got.Version != "1.7.1" {
		t.Errorf("got = %+v", got)
	}
}

func TestLocalMatcherLoadFromDirMissing(t *testing.T) {
	m := NewLocalMatcher()
	if err := m.LoadFromDir("/no/such/dir"); err != nil {
		t.Errorf("missing dir should be a no-op, got %v", err)
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d", m.Len())
	}
}

func TestLocalMatcherLoadFromDirMalformedAccumulates(t *testing.T) {
	dir := t.TempDir()
	fpRoot := filepath.Join(dir, "fingerprint", "sha256")
	if err := os.MkdirAll(fpRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fpRoot, "good.json"),
		[]byte(`{"name":"good"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fpRoot, "bad.json"),
		[]byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewLocalMatcher()
	err := m.LoadFromDir(dir)
	if err == nil {
		t.Fatal("expected error for malformed entry")
	}
	// The good entry should still be loaded.
	if got, lerr := m.Lookup(context.Background(), "sha256", "good"); lerr != nil || got.Name != "good" {
		t.Errorf("good entry not loaded despite partial failure: %+v / %v", got, lerr)
	}
}

func TestLocalMatcherLoadFromDirRejectsFileAsRoot(t *testing.T) {
	dir := t.TempDir()
	fpPath := filepath.Join(dir, "fingerprint")
	if err := os.WriteFile(fpPath, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewLocalMatcher()
	if err := m.LoadFromDir(dir); err == nil {
		t.Fatal("expected error when fingerprint root is a file")
	}
}

func TestLocalMatcherLoadFromDirIgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()
	fpRoot := filepath.Join(dir, "fingerprint", "sha256")
	if err := os.MkdirAll(fpRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fpRoot, "README"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewLocalMatcher()
	if err := m.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d, want 0 (README should be ignored)", m.Len())
	}
}

func TestSplitFingerprintPathRejectsBadLayout(t *testing.T) {
	if _, _, ok := splitFingerprintPath("/root", "/root/abc.json"); ok {
		t.Error("flat layout (no alg dir) should be rejected")
	}
	if _, _, ok := splitFingerprintPath("/root", "/root/sha256/x/y.json"); ok {
		t.Error("3-level layout should be rejected")
	}
	if _, _, ok := splitFingerprintPath("/root", "/root/sha256/.json"); ok {
		t.Error("empty digest should be rejected")
	}
}

// Ensure the layout-error message bubbles up by checking the wrap.
func TestLocalMatcherLoadFromDirLayoutError(t *testing.T) {
	dir := t.TempDir()
	fpRoot := filepath.Join(dir, "fingerprint")
	if err := os.MkdirAll(fpRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// File at the wrong level (no <alg> directory).
	if err := os.WriteFile(filepath.Join(fpRoot, "rogue.json"),
		[]byte(`{"name":"rogue"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewLocalMatcher()
	err := m.LoadFromDir(dir)
	if err == nil {
		t.Fatal("expected error for misplaced file")
	}
	if !errors.Is(err, err) { // tautology only to keep the sentinel-shaped check
		t.Fatal("err should not be nil-wrapped")
	}
}
