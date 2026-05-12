package extractor

import (
	"bytes"
	"context"
	"strings"

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
//
// S4 Task 1: version handling is now version-aware:
//   - `(devel)` is preserved verbatim on the Component (real Go
//     toolchain marker for an in-tree build) and rendered as
//     `?vcs_ref=devel` PURL qualifier so vulnerability scanners
//     skip the row instead of treating it as version "(devel)".
//   - the leading `v` is stripped from the Component's Version field
//     to keep CycloneDX downstream consumers consistent with how
//     they treat other ecosystems; the PURL keeps the `v` because
//     the Go module proxy and the purl-spec golang type require it
//     (pkg:golang/<path>@v1.2.3).
//   - `+incompatible` suffixes are preserved (they're part of the
//     module version per the Go module conventions).
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
		Version: cleanGoVersion(bi.Main.Version),
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
			Version: cleanGoVersion(dep.Version),
			PURL:    purlGolang(dep.Path, dep.Version),
		})
	}
	return id, nil
}

// cleanGoVersion projects a Go-toolchain version string to the form
// CycloneDX consumers expect on the Component.Version field. S4
// Task 1:
//   - "(devel)"   → "(devel)"    preserved marker
//   - ""          → ""           caller's choice (we never invent one)
//   - "v1.2.3"    → "1.2.3"      strip the leading v
//   - "v0.0.0-20231212003515-deadbeefcafe"
//     → "0.0.0-20231212003515-deadbeefcafe"   pseudo-version
//   - "v1.2.3+incompatible"
//     → "1.2.3+incompatible"  suffix preserved
func cleanGoVersion(v string) string {
	if v == "(devel)" || v == "" {
		return v
	}
	return strings.TrimPrefix(v, "v")
}

// purlGolang renders a Go module PURL. The `pkg:golang/` type per
// the purl-spec keeps the `v` prefix on tagged releases and the full
// `0.0.0-<timestamp>-<sha>` pseudo-version; we only intervene on the
// `(devel)` marker (no resolvable version → carry the signal in a
// `?vcs_ref=devel` qualifier so vulnerability scanners skip the row)
// and on empty version (`@unknown` fallback so consumers don't see a
// bare `pkg:golang/<path>` shape they can't parse).
//
// Module paths can contain `/` separators (`github.com/spf13/cobra`)
// which the purl-spec preserves literally — no escaping needed.
func purlGolang(modulePath, version string) string {
	if modulePath == "" {
		return ""
	}
	switch version {
	case "":
		return "pkg:golang/" + modulePath + "@unknown"
	case "(devel)":
		return "pkg:golang/" + modulePath + "?vcs_ref=devel"
	default:
		return "pkg:golang/" + modulePath + "@" + version
	}
}

// looksLikeBinary reports whether body's first bytes match a known
// executable / library magic. Used as the cheap-pre-filter for the
// Go / Rust / ELF / PE extractors.
func looksLikeBinary(body []byte) bool {
	return fingerprint.IsELF(body) ||
		fingerprint.IsPE(body) ||
		fingerprint.IsMachO(body)
}
