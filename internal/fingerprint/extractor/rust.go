package extractor

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// RustExtractor recovers Cargo identity from binaries compiled with
// `cargo auditable` (Rust's official "embed the dep tree" tool).
//
// The auditable section is `.dep-v0`: a zlib-compressed JSON
// document listing every package linked into the binary plus a
// `root: true` flag on the binary itself.
type RustExtractor struct{}

// Name implements Extractor.
func (*RustExtractor) Name() string { return "rust" }

// Confidence — the auditable section is exact metadata baked in by
// the toolchain; same precision tier as Go buildinfo.
func (*RustExtractor) Confidence() float64 { return 0.95 }

// Match — `.dep-v0` is ELF-specific (auditable doesn't yet support
// PE / Mach-O), so we gate on ELF magic.
func (*RustExtractor) Match(_ context.Context, file File) bool {
	return fingerprint.IsELF(file.Body)
}

// rustAuditableMaxBytes caps how much of the decompressed JSON we
// will read. Even the biggest Rust binaries' auditable manifests
// stay under a few MiB; the cap defends against zlib-bomb inputs.
const rustAuditableMaxBytes int64 = 16 << 20 // 16 MiB

// auditableManifest is the on-the-wire shape of the cargo-auditable
// JSON. We only consume name + version + the root marker.
type auditableManifest struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  string `json:"source"`
		Root    bool   `json:"root,omitempty"`
	} `json:"packages"`
}

// Extract reads the .dep-v0 section, decompresses, and parses.
//
// Returns (empty, nil) for ELF files without a .dep-v0 section
// (every C/Go/non-auditable Rust binary). Non-nil error only for
// truly malformed sections (bad zlib, unparseable JSON).
func (*RustExtractor) Extract(_ context.Context, file File) (Identity, error) {
	f, err := elf.NewFile(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // bad ELF is "no match", not an error
	}
	defer func() { _ = f.Close() }()

	section := f.Section(".dep-v0")
	if section == nil {
		return Identity{}, nil
	}
	raw, err := section.Data()
	if err != nil {
		return Identity{}, fmt.Errorf("rust: read .dep-v0: %w", err)
	}

	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return Identity{}, fmt.Errorf("rust: decompress .dep-v0: %w", err)
	}
	defer func() { _ = zr.Close() }()

	var manifest auditableManifest
	if err := json.NewDecoder(io.LimitReader(zr, rustAuditableMaxBytes)).Decode(&manifest); err != nil {
		return Identity{}, fmt.Errorf("rust: parse .dep-v0 JSON: %w", err)
	}
	if len(manifest.Packages) == 0 {
		return Identity{}, nil
	}

	rootIdx := -1
	for i, p := range manifest.Packages {
		if p.Root {
			rootIdx = i
			break
		}
	}
	if rootIdx == -1 {
		return Identity{}, nil
	}
	root := manifest.Packages[rootIdx]
	if root.Name == "" {
		return Identity{}, nil
	}

	id := Identity{
		Name:    root.Name,
		Version: root.Version,
		PURL:    purlCargo(root.Name, root.Version),
		Properties: map[string]string{
			"rust.auditable": "true",
			"rust.dep.count": fmt.Sprintf("%d", len(manifest.Packages)-1),
		},
	}
	for i, p := range manifest.Packages {
		if i == rootIdx || p.Name == "" {
			continue
		}
		id.SubComponents = append(id.SubComponents, Identity{
			Name:    p.Name,
			Version: p.Version,
			PURL:    purlCargo(p.Name, p.Version),
		})
	}
	return id, nil
}

// purlCargo renders a `pkg:cargo/<name>@<version>` PURL.
func purlCargo(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return "pkg:cargo/" + name
	}
	return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
}
