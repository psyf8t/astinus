package extractor

import (
	"bytes"
	"context"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// GoExtractor recovers Go module identity from a binary's embedded
// build info. It wraps `fingerprint.ReadGoBuildInfo` (which itself
// wraps stdlib `debug/buildinfo`) and projects the result onto an
// Identity, lifting every direct + indirect dependency into
// SubComponents so a single binary scan recovers the full module
// graph.
type GoExtractor struct{}

// Name implements Extractor.
func (*GoExtractor) Name() string { return "go" }

// Confidence — Go buildinfo is exact metadata produced by the
// toolchain; treat it as the strongest non-perfect signal.
func (*GoExtractor) Confidence() float64 { return 0.95 }

// Match accepts every binary-shaped file. The actual buildinfo read
// is cheap (one section probe) so we don't bother with a stricter
// pre-filter; stripped non-Go binaries bail out in microseconds.
func (*GoExtractor) Match(_ context.Context, file File) bool {
	return looksLikeBinary(file.Body)
}

// Extract reads the buildinfo and assembles the Identity.
//
// A non-Go binary returns (empty, nil) — buildinfo.Read errors out
// when the .go.buildinfo section is absent, and we map that to "no
// match" rather than a hard failure.
func (*GoExtractor) Extract(_ context.Context, file File) (Identity, error) {
	bi, err := fingerprint.ReadGoBuildInfo(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // missing buildinfo section is not an error from the registry's POV
	}
	if bi == nil || bi.Main.Path == "" || bi.Main.Path == "command-line-arguments" {
		return Identity{}, nil
	}

	id := Identity{
		Name:    bi.Main.Path,
		Version: bi.Main.Version,
		PURL:    purlGolang(bi.Main.Path, bi.Main.Version),
		Properties: map[string]string{
			"go.compiler":     bi.GoVersion,
			"go.main.path":    bi.Main.Path,
			"go.main.version": bi.Main.Version,
		},
	}
	for _, dep := range bi.Deps {
		if dep.Path == "" {
			continue
		}
		id.SubComponents = append(id.SubComponents, Identity{
			Name:    dep.Path,
			Version: dep.Version,
			PURL:    purlGolang(dep.Path, dep.Version),
		})
	}
	return id, nil
}

// purlGolang renders a Go module PURL with the conventional fallback:
// missing version → `@unknown` so consumers don't see a bare `pkg:`
// prefix.
func purlGolang(modulePath, version string) string {
	if modulePath == "" {
		return ""
	}
	v := version
	if v == "" {
		v = "unknown"
	}
	return "pkg:golang/" + modulePath + "@" + v
}

// looksLikeBinary reports whether body's first bytes match a known
// executable / library magic. Used as the cheap-pre-filter for the
// Go / Rust / ELF / PE extractors.
func looksLikeBinary(body []byte) bool {
	return fingerprint.IsELF(body) ||
		fingerprint.IsPE(body) ||
		fingerprint.IsMachO(body)
}
