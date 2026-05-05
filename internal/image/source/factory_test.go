package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// fakeProber is a daemonProber for unit tests. answers[kind] decides
// whether the named daemon "owns" any ref it is asked about. calls
// records every probe so tests can assert ordering.
type fakeProber struct {
	answers map[DaemonKind]bool
	calls   []DaemonKind
}

func (f *fakeProber) HasImage(_ context.Context, _ name.Reference, kind DaemonKind) bool {
	f.calls = append(f.calls, kind)
	return f.answers[kind]
}

func (*fakeProber) Name(kind DaemonKind) string { return kindName(kind) }

// withFakeProberAndSocket forces daemonAvailable() to return true for
// both kinds (so the prober is consulted) by pointing DOCKER_HOST at
// an existing path. Returns the option to install the fake.
func withFakeProberAndSocket(t *testing.T, p *fakeProber) Option {
	t.Helper()
	dummySocket := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(dummySocket, nil, 0o600); err != nil {
		t.Fatalf("write dummy socket: %v", err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+dummySocket)
	return withDaemonProber(p)
}

func TestFromReferenceEmpty(t *testing.T) {
	if _, err := FromReference(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty reference")
	}
}

func TestFromReferenceLayoutSchemeMissingDir(t *testing.T) {
	// `oci://` requires a real layout dir; missing directory is
	// surfaced as ErrNotFound.
	_, err := FromReference(context.Background(), "oci:///no/such/layout")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFromReferenceDaemonSchemes(t *testing.T) {
	// docker-daemon:// and podman-daemon:// always return a source
	// (lazy); the underlying daemon call only happens on Image().
	for _, ref := range []string{"docker-daemon://nginx:latest", "podman-daemon://nginx:latest"} {
		t.Run(ref, func(t *testing.T) {
			src, err := FromReference(context.Background(), ref)
			if err != nil {
				t.Fatalf("FromReference(%q): %v", ref, err)
			}
			defer src.Close()
			if _, ok := src.(*daemonSource); !ok {
				t.Errorf("source = %T, want *daemonSource", src)
			}
		})
	}
}

func TestFromReferenceUnknownScheme(t *testing.T) {
	_, err := FromReference(context.Background(), "myproto://anything")
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("err = %v, want ErrUnsupportedScheme", err)
	}
}

func TestFromReferenceArchiveSchemeMissingFile(t *testing.T) {
	_, err := FromReference(context.Background(), "archive:///no/such/image.tar")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFromReferenceAutoDetectArchive(t *testing.T) {
	// Any regular file is treated as a tar; the archive source is
	// returned without parsing the bytes.
	dir := t.TempDir()
	path := filepath.Join(dir, "image.tar")
	if err := os.WriteFile(path, []byte("not a real tar"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	src, err := FromReference(context.Background(), path)
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*archiveSource); !ok {
		t.Errorf("source = %T, want *archiveSource", src)
	}
}

func TestFromReferenceAutoDetectRegistry(t *testing.T) {
	src, err := FromReference(context.Background(), "ghcr.io/foo/bar:latest")
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*registrySource); !ok {
		t.Errorf("source = %T, want *registrySource", src)
	}
	if got := src.Reference().String(); got != "ghcr.io/foo/bar:latest" {
		t.Errorf("Reference = %q", got)
	}
}

func TestFromReferenceDirectoryNotOCILayout(t *testing.T) {
	dir := t.TempDir()
	_, err := FromReference(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for plain directory")
	}
}

func TestFromReferenceOCILayoutDirectoryAutoDetect(t *testing.T) {
	dir := buildLayoutDir(t)
	src, err := FromReference(context.Background(), dir)
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*layoutSource); !ok {
		t.Errorf("source = %T, want *layoutSource", src)
	}
}

// TestFromReferenceAutoDetectExplicitSchemes pins that every URI
// scheme bypasses auto-detection and instantiates the matching source
// without consulting the daemon prober.
func TestFromReferenceAutoDetectExplicitSchemes(t *testing.T) {
	cases := []struct {
		ref      string
		wantType string
	}{
		{"docker-daemon://app:v1", "*source.daemonSource"},
		{"podman-daemon://app:v1", "*source.daemonSource"},
		{"registry://ghcr.io/foo:v1", "*source.registrySource"},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			// Fail loudly if the prober is consulted for an explicit
			// scheme — that would mean autoDetect ran when it
			// shouldn't.
			fp := &fakeProber{answers: map[DaemonKind]bool{}}
			src, err := FromReference(context.Background(), tc.ref, withDaemonProber(fp))
			if err != nil {
				t.Fatalf("FromReference(%q): %v", tc.ref, err)
			}
			defer src.Close()
			if got := typeOf(src); got != tc.wantType {
				t.Errorf("source = %s, want %s", got, tc.wantType)
			}
			if len(fp.calls) != 0 {
				t.Errorf("prober consulted for explicit scheme: %v", fp.calls)
			}
		})
	}
}

// TestFromReferenceAutoDetectPrefersDaemon — when the Docker daemon
// reports ownership, we must NOT fall through to registry.
func TestFromReferenceAutoDetectPrefersDaemon(t *testing.T) {
	fp := &fakeProber{answers: map[DaemonKind]bool{DaemonDocker: true}}
	src, err := FromReference(context.Background(), "alpine:3.19",
		withFakeProberAndSocket(t, fp))
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*daemonSource); !ok {
		t.Errorf("source = %T, want *daemonSource", src)
	}
	if len(fp.calls) == 0 || fp.calls[0] != DaemonDocker {
		t.Errorf("calls = %v, want Docker first", fp.calls)
	}
}

// TestFromReferenceAutoDetectPodmanFallback — Docker probe says no,
// Podman probe says yes; podman wins (still daemon, not registry).
func TestFromReferenceAutoDetectPodmanFallback(t *testing.T) {
	fp := &fakeProber{answers: map[DaemonKind]bool{
		DaemonDocker: false,
		DaemonPodman: true,
	}}
	src, err := FromReference(context.Background(), "alpine:3.19",
		withFakeProberAndSocket(t, fp))
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*daemonSource); !ok {
		t.Fatalf("source = %T, want *daemonSource", src)
	}
	if len(fp.calls) != 2 || fp.calls[0] != DaemonDocker || fp.calls[1] != DaemonPodman {
		t.Errorf("calls = %v, want [Docker, Podman]", fp.calls)
	}
}

// TestFromReferenceAutoDetectRegistryFallback — neither daemon owns
// the ref; registry source must be returned and the probe consulted
// exactly twice.
func TestFromReferenceAutoDetectRegistryFallback(t *testing.T) {
	fp := &fakeProber{answers: map[DaemonKind]bool{}}
	src, err := FromReference(context.Background(), "ghcr.io/foo/bar:v1",
		withFakeProberAndSocket(t, fp))
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*registrySource); !ok {
		t.Errorf("source = %T, want *registrySource", src)
	}
	if len(fp.calls) != 2 {
		t.Errorf("prober calls = %d, want 2 (Docker then Podman)", len(fp.calls))
	}
}

// TestFromReferenceDaemonProbeSkippedWhenNoSocket — when DOCKER_HOST
// points at a path that doesn't exist (and no real daemon socket is
// at the default location), the prober must NOT be called: the
// cheap socket-existence check short-circuits.
func TestFromReferenceDaemonProbeSkippedWhenNoSocket(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///definitely/does/not/exist.sock")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "no-podman"))

	fp := &fakeProber{answers: map[DaemonKind]bool{}}
	src, err := FromReference(context.Background(), "ghcr.io/foo/bar:v1",
		withDaemonProber(fp))
	if err != nil {
		t.Fatalf("FromReference: %v", err)
	}
	defer src.Close()
	if _, ok := src.(*registrySource); !ok {
		t.Errorf("source = %T, want *registrySource", src)
	}
	if len(fp.calls) != 0 {
		t.Errorf("prober calls = %v, want 0 (no socket reachable)", fp.calls)
	}
}

// TestRealDaemonProberRespectsTimeout — the production prober must
// not block longer than daemonProbeTimeout when DOCKER_HOST points
// at a non-existent socket. Unit-safe because it never reaches the
// daemon API (the socket is missing).
func TestRealDaemonProberRespectsTimeout(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///definitely/does/not/exist.sock")

	ref, err := name.ParseReference("alpine:3.19")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	prober := realDaemonProber{}

	start := time.Now()
	got := prober.HasImage(context.Background(), ref, DaemonDocker)
	elapsed := time.Since(start)

	if got {
		t.Error("HasImage = true against missing socket; want false")
	}
	// The timeout is 2 s; allow a generous ceiling so this test stays
	// stable on slow CI runners but still fails if the probe ignores
	// the deadline entirely.
	if elapsed > 5*time.Second {
		t.Errorf("HasImage took %v; want < 5s", elapsed)
	}
}

// TestFromReferenceUnparseableRefIsClearError — a ref that is neither
// a path nor a valid image reference must surface a clear error
// (instead of silently going to registry and failing later).
func TestFromReferenceUnparseableRefIsClearError(t *testing.T) {
	_, err := FromReference(context.Background(), "::not-a-thing::")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errors.Unwrap(err)) {
		// Just confirms it wraps something; no sentinel claim.
		t.Errorf("err = %v should wrap parse error", err)
	}
}

// typeOf returns "*source.<typeName>" so test cases above can compare
// against a stable string literal.
func typeOf(v any) string { return fmt.Sprintf("%T", v) }

func TestSplitScheme(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		body   string
		ok     bool
	}{
		{"docker-daemon://x", "docker-daemon", "x", true},
		{"archive:///path", "archive", "/path", true},
		{"myproto://body", "myproto", "body", true},
		{"ghcr.io/foo:latest", "", "", false},
		{"://no-scheme", "", "", false},
		{"PROTO://upper", "", "", false}, // schemes are lowercase only
	}
	for _, c := range cases {
		s, b, ok := splitScheme(c.in)
		if s != c.scheme || b != c.body || ok != c.ok {
			t.Errorf("splitScheme(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, s, b, ok, c.scheme, c.body, c.ok)
		}
	}
}
