package source

import (
	"testing"
)

func TestNewDaemonSourceParse(t *testing.T) {
	src, err := newDaemonSource("nginx:1.27", DaemonDocker)
	if err != nil {
		t.Fatalf("newDaemonSource: %v", err)
	}
	defer src.Close()
	if src.kind != DaemonDocker {
		t.Errorf("kind = %v, want DaemonDocker", src.kind)
	}
	if got := src.Reference().Name(); got != "index.docker.io/library/nginx:1.27" {
		t.Errorf("Reference = %q", got)
	}
}

func TestNewDaemonSourceBadRef(t *testing.T) {
	if _, err := newDaemonSource(":::not a ref", DaemonDocker); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestKindName(t *testing.T) {
	if kindName(DaemonDocker) != "docker" {
		t.Error("DaemonDocker name")
	}
	if kindName(DaemonPodman) != "podman" {
		t.Error("DaemonPodman name")
	}
}

func TestEnsurePodmanHostPreservesExisting(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///custom/socket")
	restore := ensurePodmanHost()
	restore()
	if got := getEnv("DOCKER_HOST"); got != "unix:///custom/socket" {
		t.Errorf("DOCKER_HOST changed despite being preset: %q", got)
	}
}

func TestPodmanSocketCandidatesIncludesXDG(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	got := podmanSocketCandidates()
	if len(got) == 0 || got[0] != "/run/user/1000/podman/podman.sock" {
		t.Errorf("first candidate = %v, want XDG-derived", got)
	}
}

// getEnv is a tiny shim around os.Getenv so the test reads obvious
// without importing os in every test.
func getEnv(k string) string {
	return getenv(k)
}
