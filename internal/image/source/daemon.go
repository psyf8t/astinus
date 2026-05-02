package source

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
)

// DaemonKind tells the source which container daemon to talk to.
//
// Docker and Podman both speak the Docker Engine API, so the
// implementation is one code path; the kind only matters for the
// helpful error message and for the Podman-socket fallback.
type DaemonKind int

const (
	// DaemonDocker reads from the Docker daemon (default DOCKER_HOST
	// or unix:///var/run/docker.sock).
	DaemonDocker DaemonKind = iota
	// DaemonPodman reads from the Podman daemon (default
	// $XDG_RUNTIME_DIR/podman/podman.sock or
	// /run/podman/podman.sock).
	DaemonPodman
)

// daemonSource pulls images from a container daemon via
// pkg/v1/daemon. The daemon Engine API is accessed lazily on Image().
type daemonSource struct {
	ref  name.Reference
	kind DaemonKind

	once    sync.Once
	image   v1.Image
	loadErr error
}

// newDaemonSource validates ref and returns a lazy source.
func newDaemonSource(ref string, kind DaemonKind) (*daemonSource, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("daemon: parse %q: %w", ref, err)
	}
	return &daemonSource{ref: parsed, kind: kind}, nil
}

// Reference implements ImageSource.
func (d *daemonSource) Reference() name.Reference { return d.ref }

// Image implements ImageSource.
func (d *daemonSource) Image(ctx context.Context) (v1.Image, error) {
	d.once.Do(func() {
		// For Podman, point DOCKER_HOST at the canonical Podman
		// socket if the operator hasn't set one. Docker keeps its
		// own default behaviour.
		restore := func() {}
		if d.kind == DaemonPodman {
			restore = ensurePodmanHost()
		}
		defer restore()

		opts := []daemon.Option{
			daemon.WithContext(ctx),
			daemon.WithBufferedOpener(),
		}

		img, err := daemon.Image(d.ref, opts...)
		if err != nil {
			d.loadErr = fmt.Errorf("daemon: pull %q from %s: %w",
				d.ref, kindName(d.kind), err)
			return
		}
		d.image = img
	})
	return d.image, d.loadErr
}

// Close implements ImageSource. Nothing persistent to release.
func (d *daemonSource) Close() error { return nil }

// kindName returns a human-readable label for log lines.
func kindName(k DaemonKind) string {
	switch k {
	case DaemonPodman:
		return "podman"
	default:
		return "docker"
	}
}

// ensurePodmanHost sets DOCKER_HOST to a Podman socket when nothing
// is currently configured. Returns a restore function the caller
// MUST defer to undo the change so concurrent docker-daemon calls
// from the same process aren't silently redirected.
func ensurePodmanHost() func() {
	if os.Getenv("DOCKER_HOST") != "" {
		return func() {}
	}
	for _, path := range podmanSocketCandidates() {
		if _, err := os.Stat(path); err == nil {
			old := os.Getenv("DOCKER_HOST")
			_ = os.Setenv("DOCKER_HOST", "unix://"+path)
			return func() {
				if old == "" {
					_ = os.Unsetenv("DOCKER_HOST")
				} else {
					_ = os.Setenv("DOCKER_HOST", old)
				}
			}
		}
	}
	return func() {}
}

// podmanSocketCandidates returns the well-known Podman socket paths
// in the order they should be probed.
func podmanSocketCandidates() []string {
	var out []string
	if r := os.Getenv("XDG_RUNTIME_DIR"); r != "" {
		out = append(out, r+"/podman/podman.sock")
	}
	out = append(out,
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	)
	return out
}
