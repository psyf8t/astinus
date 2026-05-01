package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
		return nil, fmt.Errorf("source: oci layout (%q) lands in Stage 8: %w", body, ErrUnsupportedScheme)
	case "docker-daemon", "podman-daemon":
		return nil, fmt.Errorf("source: %s daemon (%q) lands in Stage 8: %w", scheme, body, ErrUnsupportedScheme)
	default:
		return nil, fmt.Errorf("source: unknown scheme %q: %w", scheme, ErrUnsupportedScheme)
	}
}

// autoDetect runs the auto-detection rules from the package doc.
func autoDetect(_ context.Context, ref string, opts Options) (ImageSource, error) {
	// File on disk?
	if info, err := os.Stat(ref); err == nil {
		switch {
		case info.IsDir():
			if isOCILayout(ref) {
				return nil, fmt.Errorf("source: oci layout (%q) lands in Stage 8: %w", ref, ErrUnsupportedScheme)
			}
			// Could still be the path of a registry pulled into a
			// directory; better to surface a clear error than to
			// guess wrong.
			return nil, fmt.Errorf("source: directory %q is not a recognised image source", ref)
		default:
			// Treat any regular file as a tar archive — tarball will
			// give a clear error if the bytes are wrong.
			return newArchiveSource(ref, "")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("source: stat %q: %w", ref, err)
	}

	// Default: treat as a registry reference.
	return newRegistrySource(ref, opts)
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
