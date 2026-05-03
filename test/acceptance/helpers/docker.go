package helpers

import (
	"context"
	"crypto/sha1" //nolint:gosec // used as a stable, short tag suffix, not for security
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BuildImage writes dockerfile to a temp dir alongside any files
// declared in extras and runs `docker build`, returning the image
// reference (`astinus-acceptance:<digest>`). The image is removed
// via t.Cleanup on test exit.
//
// Caller is responsible for ensuring docker is available
// (RequireDockerDaemon).
func BuildImage(t TB, dockerfile string, extras map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	for name, body := range extras {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}

	tag := newImageTag(dockerfile)
	RunOK(t, "docker", "build", "--quiet", "-t", tag, dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = RunCleanup(ctx, "docker", "rmi", "-f", tag)
	})
	return tag
}

// BuildImageWithBuildKit forces BUILDKIT=1 so the resulting image
// carries BuildKit-style provenance attestations.
func BuildImageWithBuildKit(t TB, dockerfile string, extras map[string][]byte) string {
	t.Helper()
	prev := os.Getenv("DOCKER_BUILDKIT")
	_ = os.Setenv("DOCKER_BUILDKIT", "1")
	t.Cleanup(func() { _ = os.Setenv("DOCKER_BUILDKIT", prev) })
	return BuildImage(t, dockerfile, extras)
}

// SaveDockerImage exports a docker image to a temp .tar and returns
// the path. Useful for running Astinus against the archive form
// (avoids depending on a daemon connection from inside Astinus).
func SaveDockerImage(t TB, ref string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "image.tar")
	RunOK(t, "docker", "save", "-o", out, ref)
	return out
}

// RunCleanup is RunOK without t.Fatalf — used in t.Cleanup hooks
// where a failure must not panic the test runner.
func RunCleanup(ctx context.Context, name string, args ...string) ([]byte, error) {
	return RunContext(ctx, name, args...)
}

// newImageTag returns a deterministic per-Dockerfile tag so multiple
// test runs of the same dockerfile reuse the docker layer cache,
// while distinct dockerfiles get distinct tags.
func newImageTag(dockerfile string) string {
	sum := sha1.Sum([]byte(dockerfile)) //nolint:gosec
	return fmt.Sprintf("astinus-acceptance:%s", hex.EncodeToString(sum[:6]))
}

// CanRunPodman reports whether `podman` is on PATH AND `podman info`
// reaches a working backend.
func CanRunPodman() bool { return canExecOK("podman", "info") }

// CanRunBuildah reports whether `buildah` is on PATH and reachable.
func CanRunBuildah() bool { return canExecOK("buildah", "version") }

// CanRunKaniko reports whether the `executor` binary (Kaniko's CLI)
// is on PATH. Kaniko is normally run inside a container — operators
// mounting the binary on the host can use this directly.
func CanRunKaniko() bool { return canExec("executor") }

// CanRunBuildKit reports whether `docker buildx version` succeeds —
// the modern form of "BuildKit is available".
func CanRunBuildKit() bool { return canExecOK("docker", "buildx", "version") }

// canExec checks whether name is on PATH (no execution).
func canExec(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// canExecOK runs name with the given args and reports whether the
// command exited cleanly within 5 seconds. Callers use this to
// gate "is the runtime actually reachable" checks.
func canExecOK(name string, args ...string) bool {
	if !canExec(name) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run() == nil
}

// JoinExtraFiles renders a "name=<sha1prefix>" tag suffix for image
// builds that need extra layers — used by tests that mutate the
// dockerfile across iterations.
func JoinExtraFiles(extras map[string][]byte) string {
	if len(extras) == 0 {
		return ""
	}
	keys := make([]string, 0, len(extras))
	for k := range extras {
		keys = append(keys, k)
	}
	return strings.Join(keys, ",")
}
