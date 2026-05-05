package helpers

import (
	"context"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BuildWithDocker is the canonical-runtime build path used by the
// 5-runtime matrix.
func BuildWithDocker(t TB, dockerfile string) string {
	t.Helper()
	prev := os.Getenv("DOCKER_BUILDKIT")
	_ = os.Setenv("DOCKER_BUILDKIT", "0") // force the classic builder
	t.Cleanup(func() { _ = os.Setenv("DOCKER_BUILDKIT", prev) })
	return BuildImage(t, dockerfile, nil)
}

// BuildWithBuildKit forces the modern BuildKit builder via buildx,
// so the image carries OCI provenance attestations.
func BuildWithBuildKit(t TB, dockerfile string) string {
	t.Helper()
	if !CanRunBuildKit() {
		t.Skipf("buildx unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	tag := dockerfileTag("buildkit", dockerfile)
	RunOK(t, "docker", "buildx", "build",
		"--load", "--provenance=true",
		"-t", tag, dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = RunCleanup(ctx, "docker", "rmi", "-f", tag)
	})
	return tag
}

// BuildWithPodman delegates to `podman build` and returns the local
// reference. Podman's image store is independent from docker's;
// callers wanting Astinus to read the image will typically use
// PodmanSaveTar to materialise it into an archive.
func BuildWithPodman(t TB, dockerfile string) string {
	t.Helper()
	if !CanRunPodman() {
		t.Skipf("podman unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	tag := dockerfileTag("podman", dockerfile)
	RunOK(t, "podman", "build", "-t", tag, dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = RunCleanup(ctx, "podman", "rmi", "-f", tag)
	})
	return tag
}

// BuildWithBuildah builds an image using the buildah CLI. Buildah
// produces OCI bundles natively — Astinus's OCI layout source can
// read the result directly via `oci://` after a `buildah push`.
func BuildWithBuildah(t TB, dockerfile string) string {
	t.Helper()
	if !CanRunBuildah() {
		t.Skipf("buildah unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	tag := dockerfileTag("buildah", dockerfile)
	RunOK(t, "buildah", "bud", "-t", tag, dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = RunCleanup(ctx, "buildah", "rmi", "-f", tag)
	})
	return tag
}

// BuildWithKaniko runs Kaniko's `executor` against an in-tree build
// context. Kaniko writes a tarball (via --tarPath) which the test
// then loads into the local docker daemon (and the path is also
// returned so tests can pass it via `archive://` to Astinus).
func BuildWithKaniko(t TB, dockerfile string) string {
	t.Helper()
	if !CanRunKaniko() {
		t.Skipf("kaniko (executor binary) unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	tag := dockerfileTag("kaniko", dockerfile)
	tar := filepath.Join(dir, "kaniko.tar")
	RunOK(t, "executor",
		"--dockerfile", filepath.Join(dir, "Dockerfile"),
		"--context", dir,
		"--no-push",
		"--tarPath", tar,
		"--destination", tag,
	)
	if CanRunPodman() || canExec("docker") {
		_, _ = Run("docker", "load", "-i", tar)
	}
	t.Cleanup(func() {
		_ = os.Remove(tar)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = RunCleanup(ctx, "docker", "rmi", "-f", tag)
	})
	return tag
}

// SimpleDockerfile is the minimal "alpine + curl" image the
// runtime-matrix tests share. Kept here so the matrix table stays
// terse.
const SimpleDockerfile = `FROM alpine:3.19
RUN apk add --no-cache curl
`

func dockerfileTag(runtime, dockerfile string) string {
	sum := sha1.Sum([]byte(runtime + ":" + dockerfile)) //nolint:gosec
	return fmt.Sprintf("astinus-acceptance-%s:%s", runtime, hex.EncodeToString(sum[:6]))
}
