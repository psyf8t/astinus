package source

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
)

// daemonProbeTimeout caps how long auto-detection will wait for a
// container daemon to answer. Long enough to absorb a slow socket
// handshake; short enough that auto-detection never blocks the user
// when no daemon is running.
const daemonProbeTimeout = 2 * time.Second

// daemonProber reports whether a container daemon currently has the
// image identified by ref. Returning false means the caller should
// fall through to the next auto-detection step.
//
// The interface is a test seam — the production implementation talks
// to a real daemon and must not be exercised by unit tests, which run
// in environments without one.
type daemonProber interface {
	HasImage(ctx context.Context, ref name.Reference, kind DaemonKind) bool
	Name(kind DaemonKind) string
}

// realDaemonProber is the production probe. It delegates to the same
// `pkg/v1/daemon` API the daemon source uses, so probe and load see
// the same daemon.
type realDaemonProber struct{}

// HasImage queries the daemon for ref. Any error is treated as
// "image not here" — the daemon package does not expose a typed
// "not found" sentinel, and for auto-detection both "no daemon" and
// "no image" mean the same thing: try the next source.
func (realDaemonProber) HasImage(ctx context.Context, ref name.Reference, kind DaemonKind) bool {
	probeCtx, cancel := context.WithTimeout(ctx, daemonProbeTimeout)
	defer cancel()

	restore := func() {}
	if kind == DaemonPodman {
		restore = ensurePodmanHost()
	}
	defer restore()

	_, err := daemon.Image(ref, daemon.WithContext(probeCtx))
	return err == nil
}

// Name implements daemonProber.
func (realDaemonProber) Name(kind DaemonKind) string { return kindName(kind) }

// daemonAvailable returns true when the kind's daemon socket appears
// reachable. Used to skip the (slower) image probe when there is no
// daemon at all — saves up to daemonProbeTimeout per source select.
func daemonAvailable(kind DaemonKind) bool {
	switch kind {
	case DaemonDocker:
		return dockerSocketReachable()
	case DaemonPodman:
		return podmanSocketReachable()
	default:
		return false
	}
}

// dockerSocketReachable checks whether DOCKER_HOST (or the unix-socket
// default) points at a path that exists. Stat-only — a fast existence
// check is enough to decide whether to spend the 2 s probe budget.
func dockerSocketReachable() bool {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return socketLooksUsable(h)
	}
	_, err := os.Stat("/var/run/docker.sock")
	return err == nil
}

// podmanSocketReachable does the same for the well-known Podman
// candidates. Honours DOCKER_HOST when set so a user who points it
// at Podman is still detected.
func podmanSocketReachable() bool {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return socketLooksUsable(h)
	}
	for _, path := range podmanSocketCandidates() {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// socketLooksUsable accepts `unix://` (stat the path) and `tcp://`
// (trust the operator — connecting would defeat the point of the
// cheap pre-probe). Anything else returns false.
func socketLooksUsable(host string) bool {
	switch {
	case strings.HasPrefix(host, "unix://"):
		// G703 (gosec): DOCKER_HOST is the documented Docker
		// configuration env var; honouring its path is the
		// expected behaviour, not a vulnerability. We stat only —
		// no open, no read, no exec.
		path := strings.TrimPrefix(host, "unix://")
		_, err := os.Stat(path) //nolint:gosec // DOCKER_HOST honoured by design
		return err == nil
	case strings.HasPrefix(host, "tcp://"):
		return true
	default:
		return false
	}
}
