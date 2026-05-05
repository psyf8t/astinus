//go:build integration

package source

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestFactory_AutoDetect_PrefersDaemonOverRegistry — when the local
// Docker daemon owns a freshly built image, FromReference must return
// a daemonSource even though the tag is also a syntactically valid
// registry reference.
func TestFactory_AutoDetect_PrefersDaemonOverRegistry(t *testing.T) {
	requireDockerDaemon(t)

	tag := buildEmptyLocalImage(t)
	defer removeLocalImage(t, tag)

	src, err := FromReference(context.Background(), tag)
	if err != nil {
		t.Fatalf("FromReference(%q): %v", tag, err)
	}
	defer src.Close()

	if _, ok := src.(*daemonSource); !ok {
		t.Fatalf("source = %T, want *daemonSource", src)
	}
}

// TestFactory_LocalOnlyImageNotInRegistry_UsesDaemon is the regression
// test: a tag that provably does not exist in any registry must NOT
// produce a registry pull attempt; the daemon source must answer.
func TestFactory_LocalOnlyImageNotInRegistry_UsesDaemon(t *testing.T) {
	requireDockerDaemon(t)

	tag := buildEmptyLocalImage(t)
	defer removeLocalImage(t, tag)

	src, err := FromReference(context.Background(), tag)
	if err != nil {
		t.Fatalf("regression: local-only image must not trigger registry pull: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*daemonSource); !ok {
		t.Fatalf("source = %T, want *daemonSource for local-only image", src)
	}

	// And we must be able to load the image without a 401.
	img, err := src.Image(context.Background())
	if err != nil {
		t.Fatalf("Image() on local-only image: %v", err)
	}
	if img == nil {
		t.Fatal("Image() returned nil")
	}
}

// TestFactory_AutoDetect_FallsBackToRegistryWhenAbsent — when a tag
// is NOT present in any local daemon, FromReference must return a
// registrySource. Uses a name that would never collide with a
// freshly-built test image.
func TestFactory_AutoDetect_FallsBackToRegistryWhenAbsent(t *testing.T) {
	requireDockerDaemon(t)

	// Fixed name that we explicitly confirm is absent from the
	// daemon — never built, so the prober returns false and the
	// factory falls through to registry.
	tag := fmt.Sprintf("astinus-fallback-absent-%d:never", time.Now().UnixNano())

	src, err := FromReference(context.Background(), tag)
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*registrySource); !ok {
		t.Fatalf("source = %T, want *registrySource (fallback)", src)
	}
}

// requireDockerDaemon skips the test when `docker info` does not
// succeed. We do not stat the socket here: a working `docker`
// command is the same gate the production prober ultimately depends
// on.
func requireDockerDaemon(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not on PATH; skipping integration test")
	}
	cmd := exec.Command("docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker daemon not reachable; skipping (%v)\n%s", err, out)
	}
}

// buildEmptyLocalImage builds a tiny self-contained image with a
// uniquely-suffixed tag and returns the tag. The image is `FROM
// scratch` so there is no network pull during the build itself.
func buildEmptyLocalImage(t *testing.T) string {
	t.Helper()
	tag := fmt.Sprintf("astinus-source-test-%d:v1", time.Now().UnixNano())

	dockerfile := "FROM scratch\n"
	cmd := exec.Command("docker", "build", "-t", tag, "-")
	cmd.Stdin = strings.NewReader(dockerfile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	return tag
}

// removeLocalImage best-effort deletes the test image so the daemon
// doesn't accumulate untagged layers across test runs.
func removeLocalImage(t *testing.T, tag string) {
	t.Helper()
	cmd := exec.Command("docker", "rmi", "-f", tag)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("docker rmi %s: %v\n%s (non-fatal)", tag, err, out)
	}
}
