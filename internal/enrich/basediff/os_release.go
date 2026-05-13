package basediff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/psyf8t/astinus/internal/image/layer"
)

// OSRelease is the parsed form of /etc/os-release (or one of its
// distro-specific cousins like /etc/alpine-release). S4 Task 6
// introduced the type for content-based base-image detection — when
// the target image carries no `org.opencontainers.image.base.*`
// labels (the majority of public Docker Hub images), reading the
// os-release file gives us the distro identity we can match against
// the bundled known-bases catalogue.
type OSRelease struct {
	// ID is the distro short identifier ("alpine", "debian",
	// "ubuntu", "rhel", "almalinux", "rocky", "fedora", …).
	ID string

	// VersionID is the distro version ("3.20.6", "12", "22.04", …).
	// For Alpine-style minimal files this is the only data.
	VersionID string

	// PrettyName is the human-readable name when /etc/os-release
	// supplies one. Empty for /etc/alpine-release-only images.
	PrettyName string

	// Raw is every key=value pair we parsed (uppercase). Lets future
	// callers consume non-standard keys without re-parsing.
	Raw map[string]string

	// SourcePath records which file produced this OSRelease
	// ("/etc/os-release", "/etc/alpine-release", …).
	SourcePath string

	// LayerIndex is the 0-based layer index the file lived in. For
	// multi-stage builds where a later stage rewrites os-release the
	// FileMap's latest-layer-wins rule means we see the final
	// version; future work may walk earlier layers to detect the
	// original base. S4 Task 6 takes the latest as-is.
	LayerIndex int
}

// osReleaseCandidates are the in-image paths we probe in order. The
// list is intentionally short — every distro that ships os-release
// uses one of these three locations.
var osReleaseCandidates = []string{
	"etc/os-release",
	"usr/lib/os-release",
	"etc/alpine-release",
}

// readOSReleaseFromImage walks the image once and returns the first
// os-release-shaped file it finds (probing the candidate paths in
// order). Returns (nil, nil) when no candidate file exists in the
// image — that's the "scratch / custom" case, not an error. S4
// Task 6.
func readOSReleaseFromImage(ctx context.Context, img v1.Image) (*OSRelease, error) {
	for _, p := range osReleaseCandidates {
		body, info, err := readFileFromImage(ctx, img, p)
		if errors.Is(err, errFileNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		rel, err := parseOSRelease(bytes.NewReader(body), p)
		if err != nil {
			continue
		}
		rel.SourcePath = p
		rel.LayerIndex = info.Index
		return rel, nil
	}
	return nil, errNoOSRelease
}

// parseOSRelease handles both the KEY=VALUE format (`/etc/os-release`,
// `/usr/lib/os-release`) and the bare-version-string format
// (`/etc/alpine-release`). The path argument disambiguates the two
// shapes. Returns an error only on unreadable input; an empty
// os-release file produces an OSRelease with empty ID / VersionID
// (the caller decides whether that's usable).
func parseOSRelease(r io.Reader, path string) (*OSRelease, error) {
	if strings.HasSuffix(path, "/alpine-release") || strings.HasSuffix(path, "alpine-release") {
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		version := strings.TrimSpace(string(b))
		if version == "" {
			return &OSRelease{Raw: map[string]string{}}, nil
		}
		return &OSRelease{
			ID:         "alpine",
			VersionID:  version,
			PrettyName: "Alpine Linux v" + version,
			Raw:        map[string]string{},
		}, nil
	}

	rel := &OSRelease{Raw: map[string]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"`)
		rel.Raw[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rel.ID = rel.Raw["ID"]
	rel.VersionID = rel.Raw["VERSION_ID"]
	rel.PrettyName = rel.Raw["PRETTY_NAME"]
	return rel, nil
}

// errFileNotFound is the sentinel readFileFromImage returns when
// the requested path isn't present in the image. Local to the
// package so we don't pull in os/fs just for one symbol.
var errFileNotFound = errors.New("basediff: file not found in image")

// errNoOSRelease is returned by readOSReleaseFromImage when none of
// the os-release candidate paths is present. S4 Task 6 — the
// scratch / custom-base case. Distinct from a real I/O failure so
// callers can branch.
var errNoOSRelease = errors.New("basediff: no os-release file in image")

// errFoundFile is the internal sentinel readFileFromImage returns to
// stop the WalkFiles walk once the target path's bytes are captured.
// errors.Is on the wrapped error from WalkFiles handles the unwrap.
var errFoundFile = errors.New("basediff: file found")

// readFileFromImage walks the image once and returns the bytes of
// the file at targetPath (path-normalised: no leading slash).
// Returns errFileNotFound when the path isn't in the image. Stops
// the walk as soon as the file is captured.
func readFileFromImage(ctx context.Context, img v1.Image, targetPath string) ([]byte, layer.Info, error) {
	want := strings.TrimPrefix(targetPath, "/")
	var (
		captured []byte
		info     layer.Info
	)
	err := layer.WalkFiles(ctx, img, func(_ context.Context, fe layer.FileEntry, body io.Reader) error {
		if fe.Path != want {
			return nil
		}
		b, readErr := io.ReadAll(body)
		if readErr != nil {
			return readErr
		}
		captured = b
		info = fe.Layer
		return errFoundFile
	})
	if err != nil && !errors.Is(err, errFoundFile) {
		return nil, layer.Info{}, err
	}
	if captured == nil {
		return nil, layer.Info{}, errFileNotFound
	}
	return captured, info, nil
}
