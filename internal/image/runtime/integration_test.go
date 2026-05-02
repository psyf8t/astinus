//go:build integration

package runtime_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	imgruntime "github.com/psyf8t/astinus/internal/image/runtime"
)

// TestRuntimeDetectionAllSupported builds a tiny image with each
// available runtime and checks that runtime.Detect classifies it
// correctly.
//
// Builds run via the host's actual docker / podman / buildah binaries;
// each sub-test skips when the binary is missing. Kaniko runs as a
// container (it ships only as an image), so the kaniko sub-test
// needs both Docker and an image pull.
//
// All builds use a tiny self-contained Dockerfile written to a
// temporary directory — no external repository is touched.
func TestRuntimeDetectionAllSupported(t *testing.T) {
	cases := []struct {
		name    string
		builder func(t *testing.T, dockerfileDir string) v1.Image
		want    imgruntime.Runtime
	}{
		{"docker", buildWithDocker, imgruntime.RuntimeDocker},
		{"buildx", buildWithBuildx, imgruntime.RuntimeBuildKit},
		{"podman", buildWithPodman, imgruntime.RuntimePodman},
		{"buildah", buildWithBuildah, imgruntime.RuntimeBuildah},
		{"kaniko", buildWithKaniko, imgruntime.RuntimeKaniko},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeMinimalDockerfile(t)
			img := tc.builder(t, dir)
			got, evidence, err := imgruntime.Detect(img)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got != tc.want {
				t.Errorf("Detect = %q, want %q (evidence: %+v)", got, tc.want, evidence)
			}
			if got != imgruntime.RuntimeDocker && len(evidence) == 0 {
				// Docker is the documented fallback (no evidence
				// expected); every other runtime must yield at least
				// one piece of evidence.
				t.Errorf("evidence is empty for %s; classification reasoning is opaque", tc.name)
			}
		})
	}
}

// writeMinimalDockerfile produces a tiny self-contained build
// context. We deliberately use `scratch` and a small COPY so the
// build is fast and does not need network in the dispatched runtime.
func writeMinimalDockerfile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"),
		[]byte("hello from astinus runtime detection test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"),
		[]byte("FROM scratch\nCOPY hello.txt /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ─── per-runtime builders ────────────────────────────────────────────────

func buildWithDocker(t *testing.T, dir string) v1.Image {
	t.Helper()
	if !commandAvailable("docker") {
		t.Skip("docker not available")
	}
	tag := "astinus-rt-test/docker:latest"
	// DOCKER_BUILDKIT=0 forces the legacy builder so this case is
	// classified as Docker, not BuildKit.
	cmd := exec.Command("docker", "build", "-t", tag, dir)
	cmd.Env = append(cmd.Environ(), "DOCKER_BUILDKIT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	defer dockerRmi(tag)
	return loadFromDockerDaemon(t, tag)
}

func buildWithBuildx(t *testing.T, dir string) v1.Image {
	t.Helper()
	if !commandAvailable("docker") {
		t.Skip("docker not available")
	}
	tag := "astinus-rt-test/buildx:latest"
	cmd := exec.Command("docker", "buildx", "build", "--load", "-t", tag, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker buildx build: %v\n%s", err, out)
	}
	defer dockerRmi(tag)
	return loadFromDockerDaemon(t, tag)
}

func buildWithPodman(t *testing.T, dir string) v1.Image {
	t.Helper()
	if !commandAvailable("podman") {
		t.Skip("podman not available")
	}
	tag := "astinus-rt-test/podman:latest"
	if out, err := exec.Command("podman", "build", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("podman build: %v\n%s", err, out)
	}
	defer exec.Command("podman", "rmi", tag).Run()

	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command("podman", "save", "-o", tarPath, tag).CombinedOutput(); err != nil {
		t.Fatalf("podman save: %v\n%s", err, out)
	}
	return loadTarball(t, tarPath, tag)
}

func buildWithBuildah(t *testing.T, dir string) v1.Image {
	t.Helper()
	if !commandAvailable("buildah") {
		t.Skip("buildah not available")
	}
	tag := "astinus-rt-test/buildah:latest"
	if out, err := exec.Command("buildah", "bud", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("buildah bud: %v\n%s", err, out)
	}
	defer exec.Command("buildah", "rmi", tag).Run()

	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command("buildah", "push", tag, "docker-archive:"+tarPath+":"+tag).CombinedOutput(); err != nil {
		t.Fatalf("buildah push: %v\n%s", err, out)
	}
	return loadTarball(t, tarPath, tag)
}

func buildWithKaniko(t *testing.T, dir string) v1.Image {
	t.Helper()
	if !commandAvailable("docker") {
		t.Skip("docker not available (needed to run Kaniko's executor image)")
	}
	tag := "astinus-rt-test/kaniko:latest"
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	cmd := exec.Command("docker", "run", "--rm",
		"-v", dir+":/workspace",
		"-v", filepath.Dir(tarPath)+":/out",
		"gcr.io/kaniko-project/executor:latest",
		"--dockerfile=/workspace/Dockerfile",
		"--context=dir:///workspace",
		"--no-push",
		"--tarPath=/out/"+filepath.Base(tarPath),
		"--destination="+tag,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kaniko: %v\n%s", err, out)
	}
	return loadTarball(t, tarPath, tag)
}

// ─── helpers ─────────────────────────────────────────────────────────────

func commandAvailable(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func dockerRmi(tag string) {
	_ = exec.Command("docker", "rmi", tag).Run()
}

func loadFromDockerDaemon(t *testing.T, tag string) v1.Image {
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

func loadTarball(t *testing.T, path, tag string) v1.Image {
	t.Helper()
	ref, err := name.NewTag(strings.TrimSpace(tag))
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	img, err := tarball.ImageFromPath(path, &ref)
	if err != nil {
		t.Fatalf("tarball.ImageFromPath: %v", err)
	}
	return img
}
