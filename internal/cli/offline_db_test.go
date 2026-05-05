package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineDBBuildCreatesLayout(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "offline-db")

	root := newRootCommand(&rootOptions{})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"offline-db", "build", "--output", out, "--notes", "test build"})
	root.SetContext(context.Background())

	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	for _, sub := range []string{
		"manifest.json",
		"cpe/by-purl",
		"cpe/by-name",
		"fingerprint/sha256",
	} {
		if _, err := os.Stat(filepath.Join(out, sub)); err != nil {
			t.Errorf("missing %s: %v", sub, err)
		}
	}

	body, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m offlineDBManifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != offlineDBManifestVersion {
		t.Errorf("manifest version = %d", m.Version)
	}
	if m.Notes != "test build" {
		t.Errorf("notes = %q", m.Notes)
	}
	if !strings.HasPrefix(m.BuiltBy, "astinus-") {
		t.Errorf("builtBy = %q", m.BuiltBy)
	}
}

func TestOfflineDBBuildPrintsIncludeWarning(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "db")
	var buf bytes.Buffer

	root := newRootCommand(&rootOptions{})
	root.SetOut(&buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"offline-db", "build", "--output", out, "--include-nvd-cpe"})
	root.SetContext(context.Background())

	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), "not yet wired") {
		t.Errorf("output missing Stage-13 warning:\n%s", buf.String())
	}
}

func TestOfflineDBInfo(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "db")

	build := newRootCommand(&rootOptions{})
	build.SetOut(io.Discard)
	build.SetErr(io.Discard)
	build.SetArgs([]string{"offline-db", "build", "--output", out})
	if err := build.Execute(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	info := newRootCommand(&rootOptions{})
	info.SetOut(&buf)
	info.SetErr(io.Discard)
	info.SetArgs([]string{"offline-db", "info", "--path", out})
	if err := info.Execute(); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{"Path:", "Version: 1", "Built:", "Entries: cpe=0  fingerprint=0"} {
		if !strings.Contains(got, want) {
			t.Errorf("info missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestEnrichNoNetworkRefusesRegistryRef(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(sbomPath,
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCommand(&rootOptions{})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"enrich",
		"--sbom", sbomPath,
		"--image", "ghcr.io/foo:latest",
		"--no-network",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for --no-network + registry ref")
	}
	var exitErr *exitError
	if !asExitError(err, &exitErr) {
		t.Fatalf("err type = %T (%v)", err, err)
	}
	if exitErr.code != ExitNoNetwork {
		t.Errorf("exit code = %d, want %d", exitErr.code, ExitNoNetwork)
	}
}

func TestRefRequiresNetwork(t *testing.T) {
	cases := map[string]bool{
		"":                     false,
		"ghcr.io/foo:latest":   true,
		"docker.io/library/x":  true,
		"archive:///tmp/x.tar": false,
		"oci:///path/layout":   false,
		"docker-daemon://x:1":  false,
		"podman-daemon://x:1":  false,
	}
	for ref, want := range cases {
		if got := refRequiresNetwork(ref); got != want {
			t.Errorf("refRequiresNetwork(%q) = %v, want %v", ref, got, want)
		}
	}
}

// satisfy errors import for the test build (used in deeper assertions)
var _ = errors.Is
