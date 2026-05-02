package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Scheme prefixes the factory recognises.
const (
	SchemeRegistry     = "registry://"
	SchemeArchive      = "archive://"
	SchemeOCILayout    = "oci://"
	SchemeDockerDaemon = "docker-daemon://"
	SchemePodmanDaemon = "podman-daemon://"
	schemeSeparator    = "://"
)

// FromReference parses ref and returns the matching ImageSource.
//
// See the package doc comment for the reference shapes accepted.
//
// The returned source is *not* loaded — its Image() call drives
// the actual pull / read so the caller controls timing via context.
func FromReference(ctx context.Context, ref string, opts ...Option) (ImageSource, error) {
	if ref == "" {
		return nil, fmt.Errorf("source: empty reference")
	}
	options := applyOptions(opts)

	if scheme, body, ok := splitScheme(ref); ok {
		return fromExplicit(ctx, scheme, body, options)
	}
	return autoDetect(ctx, ref, options)
}

// fromExplicit handles refs with a known scheme prefix.
func fromExplicit(_ context.Context, scheme, body string, opts Options) (ImageSource, error) {
	switch scheme {
	case "registry":
		return newRegistrySource(body, opts)
	case "archive":
		return newArchiveSource(body, "")
	case "oci":
		return newLayoutSource(body, opts)
	case "docker-daemon":
		return newDaemonSource(body, DaemonDocker)
	case "podman-daemon":
		return newDaemonSource(body, DaemonPodman)
	default:
		return nil, fmt.Errorf("source: unknown scheme %q: %w", scheme, ErrUnsupportedScheme)
	}
}

// autoDetect runs the auto-detection rules from the package doc.
//
// Order:
//
//  1. Existing tar file → archive source.
//  2. Existing directory with index.json + oci-layout → OCI layout
//     source.
//  3. Reference parses as an image ref AND the local Docker daemon
//     has it → docker-daemon source. (ADR-0017)
//  4. Reference parses as an image ref AND the local Podman daemon
//     has it → podman-daemon source. (ADR-0017)
//  5. Reference parses as an image ref → registry source (fallback).
//
// Step 1/2 cover the "I have a file on disk" workflow. Steps 3–5
// cover the "I have a name" workflow; daemon comes first because the
// most common case is a freshly built local image whose tag does not
// resolve in any registry.
func autoDetect(ctx context.Context, ref string, opts Options) (ImageSource, error) {
	if src, ok, err := autoDetectFile(ref, opts); ok || err != nil {
		if err == nil {
			logSelected(opts, src, ref, "file")
		}
		return src, err
	}

	parsed, parseErr := name.ParseReference(ref)
	if parseErr != nil {
		// Not a path, not an image reference — surface a clear error
		// rather than guessing.
		return nil, fmt.Errorf("source: %q is not a path nor a valid image reference: %w", ref, parseErr)
	}

	if src, ok := autoDetectDaemon(ctx, parsed, opts); ok {
		logSelected(opts, src, ref, "daemon")
		return src, nil
	}

	src, err := newRegistrySource(ref, opts)
	if err != nil {
		return nil, err
	}
	logSelected(opts, src, ref, "registry")
	return src, nil
}

// autoDetectFile handles steps 1 and 2 (file-on-disk shapes).
// Returns (src, true, nil) on a hit, (nil, false, nil) when ref is
// not a file at all, or (nil, true, err) when ref is a file we
// recognise but failed to open.
func autoDetectFile(ref string, opts Options) (ImageSource, bool, error) {
	info, err := os.Stat(ref)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, true, fmt.Errorf("source: stat %q: %w", ref, err)
	case info.IsDir():
		if isOCILayout(ref) {
			src, err := newLayoutSource(ref, opts)
			return src, true, err
		}
		return nil, true, fmt.Errorf("source: directory %q is not a recognised image source", ref)
	default:
		// Treat any regular file as a tar archive — the tarball
		// loader will give a clear error if the bytes are wrong.
		src, err := newArchiveSource(ref, "")
		return src, true, err
	}
}

// autoDetectDaemon probes Docker first, then Podman. Each probe
// is gated by a cheap socket-existence check so we never spend the
// 2 s probe budget when no daemon is running.
//
// Returns (src, true) on the first hit; (nil, false) when neither
// daemon owns ref.
func autoDetectDaemon(ctx context.Context, ref name.Reference, opts Options) (ImageSource, bool) {
	for _, kind := range []DaemonKind{DaemonDocker, DaemonPodman} {
		name := opts.daemonProber.Name(kind)
		if !daemonAvailable(kind) {
			opts.Logger.Debug("source.autodetect.daemon.skip",
				"daemon", name, "reason", "socket-not-reachable")
			continue
		}
		opts.Logger.Debug("source.autodetect.daemon.probe",
			"daemon", name, "ref", ref.String())
		if !opts.daemonProber.HasImage(ctx, ref, kind) {
			opts.Logger.Debug("source.autodetect.daemon.miss",
				"daemon", name, "ref", ref.String())
			continue
		}
		opts.Logger.Debug("source.autodetect.daemon.hit",
			"daemon", name, "ref", ref.String())
		src, err := newDaemonSource(ref.String(), kind)
		if err != nil {
			// The probe just succeeded with this ref, so a parse
			// failure here is genuinely surprising — log and fall
			// through to registry.
			opts.Logger.Debug("source.autodetect.daemon.construct-failed",
				"daemon", name, "ref", ref.String(), "err", err.Error())
			continue
		}
		return src, true
	}
	return nil, false
}

// logSelected emits the one info-level line per FromReference call
// that the spec asks for: which source ended up serving the ref.
func logSelected(opts Options, src ImageSource, ref, kind string) {
	if src == nil {
		return
	}
	opts.Logger.Info("source.selected",
		"kind", kind, "ref", ref, "type", fmt.Sprintf("%T", src))
}

// splitScheme returns scheme (without "://"), body, and whether ref
// started with a "<scheme>://" prefix.
func splitScheme(ref string) (string, string, bool) {
	idx := strings.Index(ref, schemeSeparator)
	if idx <= 0 {
		return "", "", false
	}
	scheme := ref[:idx]
	// Schemes are simple identifiers — guard against accidental
	// matches like "https://github.com/...".
	for _, ch := range scheme {
		if ch != '-' && (ch < 'a' || ch > 'z') {
			return "", "", false
		}
	}
	return scheme, ref[idx+len(schemeSeparator):], true
}

// isOCILayout reports whether dir looks like an OCI image layout
// (per the spec: an `index.json` and an `oci-layout` marker).
func isOCILayout(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "oci-layout"))
	return err == nil
}
