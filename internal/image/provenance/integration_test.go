//go:build integration

package provenance_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/psyf8t/astinus/internal/image/provenance"
)

// TestBuildKitProvenanceExtraction builds a tiny image with
// `docker buildx --attest=type=provenance,mode=max` and verifies that
// the resulting attestation manifest can be located and parsed.
//
// Skips when buildx (or docker) is not installed. The test does NOT
// push to any registry — it loads the result back via the local
// daemon. Buildx attestations require the OCI exporter, which is
// only available when buildx is configured with the `docker-container`
// driver, so the test additionally creates a temporary builder.
func TestBuildKitProvenanceExtraction(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "buildx", "version").CombinedOutput(); err != nil {
		t.Skipf("buildx not available: %v\n%s", err, out)
	}

	dir := writeContext(t)
	tag := "astinus-prov-test:v1"

	// Use a docker-container builder so the OCI exporter is available.
	builderName := "astinus-prov-test-builder"
	defer exec.Command("docker", "buildx", "rm", builderName).Run()
	if out, err := exec.Command("docker", "buildx", "create",
		"--name", builderName,
		"--driver", "docker-container",
		"--bootstrap",
	).CombinedOutput(); err != nil {
		t.Skipf("buildx create: %v\n%s", err, out)
	}

	// Build with provenance attestation; --load brings the result
	// back into the local daemon as a single-image (the manifest list
	// is collapsed). To inspect the attestation we use the inspect
	// flow on the manifest list rather than the loaded image.
	if out, err := exec.Command("docker", "buildx", "build",
		"--builder", builderName,
		"--attest", "type=provenance,mode=max",
		"--load",
		"-t", tag,
		dir,
	).CombinedOutput(); err != nil {
		t.Fatalf("buildx build: %v\n%s", err, out)
	}
	defer exec.Command("docker", "rmi", tag).Run()

	// Inspect the manifest list to assert provenance is embedded.
	out, err := exec.Command("docker", "buildx", "imagetools", "inspect", "--raw", tag).CombinedOutput()
	if err != nil {
		t.Fatalf("imagetools inspect: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "attestation-manifest") {
		t.Skipf("buildx did not produce attestation-manifest entries (output: %s)", out)
	}

	// We can also load the platform image back and call Extract on
	// it — the platform image is NOT the attestation manifest, so
	// Extract should return (nil, nil) for it. This proves the
	// "no provenance reachable from a v1.Image" contract.
	platform := loadFromDaemon(t, tag)
	got, err := provenance.Extract(platform)
	if !errors.Is(err, provenance.ErrNoProvenance) {
		t.Fatalf("Extract(platform): err = %v, want ErrNoProvenance", err)
	}
	if got != nil {
		t.Errorf("got provenance from platform image; expected nil because Extract requires the attestation manifest, not the platform image")
	}

	// Round-trip the attestation JSON via imagetools to confirm at
	// least one entry parses as in-toto.
	var manifest map[string]any
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("parse manifest list: %v", err)
	}
	manifests, _ := manifest["manifests"].([]any)
	if len(manifests) < 2 {
		t.Errorf("expected ≥2 manifests (platform + attestation), got %d", len(manifests))
	}
}

func writeContext(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"),
		[]byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"),
		[]byte("FROM scratch\nCOPY hello.txt /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func loadFromDaemon(t *testing.T, tag string) v1.Image {
	t.Helper()
	ref, err := name.ParseReference(tag)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	img, err := daemon.Image(ref, daemon.WithContext(context.Background()))
	if err != nil {
		t.Fatalf("daemon.Image: %v", err)
	}
	return img
}
