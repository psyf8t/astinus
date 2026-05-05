package extractor

import (
	"bytes"
	"context"
	"debug/pe"
	"fmt"
	"regexp"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// PEExtractor recognises Windows PE binaries (`.exe`, `.dll`).
//
// Today the extractor is intentionally minimal: it confirms the file
// is a PE, records the machine architecture, and falls back to
// filename-based version parsing. Full VS_VERSIONINFO resource
// parsing (ProductName / ProductVersion / CompanyName from the
// .rsrc section) is documented as deferred — container images are
// overwhelmingly Linux and PE files are rare enough that the ROI
// on a 200-LOC resource-tree parser is small. ADR-0022 records
// the trade-off.
type PEExtractor struct{}

// Name implements Extractor.
func (*PEExtractor) Name() string { return "pe" }

// Confidence — without VERSIONINFO we only recover a name from the
// filename. Treat as a low-confidence fallback.
func (*PEExtractor) Confidence() float64 { return 0.6 }

// Match — PE files start with `MZ` magic.
func (*PEExtractor) Match(_ context.Context, file File) bool {
	return fingerprint.IsPE(file.Body)
}

// Extract returns whatever metadata `debug/pe` directly exposes
// (machine architecture, characteristics flags) plus a filename-
// derived name + version.
//
// Returns (empty, nil) when the PE header is unreadable AND the
// filename has no recognisable version pattern.
func (*PEExtractor) Extract(_ context.Context, file File) (Identity, error) {
	f, err := pe.NewFile(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // bad PE is "no match", not an error
	}
	defer func() { _ = f.Close() }()

	props := map[string]string{
		"pe.machine": peMachineString(f.Machine),
	}

	name, version := parsePEFilename(file.Path)
	if name == "" {
		// Without a parseable filename we have no usable Name —
		// drop the identity. Operators see only the
		// `astinus:untracked:category=executable` stamp the base
		// classifier writes.
		return Identity{}, nil
	}
	id := Identity{
		Name:       name,
		Version:    version,
		PURL:       purlGenericPE(name, version),
		Properties: props,
	}
	return id, nil
}

// peFilenameVersion matches `Name-1.2.3.exe`, `Name_v4.5.exe`,
// `Name 1.0.dll`. The version segment is required so we don't
// accidentally claim every `.exe` is a real package.
var peFilenameVersion = regexp.MustCompile(`^(?P<name>[A-Za-z][A-Za-z0-9_+.-]*?)[-_ ]v?(?P<version>\d[A-Za-z0-9._+-]*)\.(?:exe|dll)$`)

func parsePEFilename(filePath string) (name, version string) {
	base := basename(filePath)
	m := peFilenameVersion.FindStringSubmatch(base)
	if m == nil {
		return "", ""
	}
	nameIdx := peFilenameVersion.SubexpIndex("name")
	versionIdx := peFilenameVersion.SubexpIndex("version")
	return m[nameIdx], m[versionIdx]
}

// purlGenericPE renders a `pkg:nuget/...` PURL. NuGet is the
// closest mainstream registry for PE-shipped packages; consumers
// downstream may rewrite to `pkg:generic` if NuGet is wrong for
// their case.
func purlGenericPE(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return "pkg:nuget/" + name
	}
	return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
}

// peMachineString turns debug/pe's numeric machine code into the
// stable string used in Properties. debug/pe's stringer is internal
// so we hand-roll the most common values.
func peMachineString(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	default:
		return fmt.Sprintf("0x%04x", m)
	}
}
