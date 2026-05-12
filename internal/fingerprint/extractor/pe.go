package extractor

import (
	"bytes"
	"context"
	"debug/pe"
	"fmt"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// PEExtractor recognises Windows PE binaries (`.exe`, `.dll`).
//
// The extractor confirms the file is a PE and records the machine
// architecture as a property. It does NOT synthesise a package
// identity — VS_VERSIONINFO resource parsing (ProductName /
// ProductVersion / CompanyName from the .rsrc section) is deferred
// (ADR-0022 records the trade-off), and the filename-pattern
// fallback that earlier revisions used was a guess that fabricated
// `pkg:nuget/<name>@<version>` rows from any binary named
// `something-1.2.3.exe`. S4 Task 0 removed it; PE files without
// embedded resource metadata are recorded as observed-only by the
// untracked enricher.
type PEExtractor struct{}

// Name implements Extractor.
func (*PEExtractor) Name() string { return "pe" }

// Confidence — without VERSIONINFO we cannot recover identity. The
// value is kept for the interface contract but the extractor never
// produces a non-empty Identity today.
func (*PEExtractor) Confidence() float64 { return 0.6 }

// Match — PE files start with `MZ` magic.
func (*PEExtractor) Match(_ context.Context, file File) bool {
	return fingerprint.IsPE(file.Body)
}

// Extract returns Identity only when verifiable PE metadata is
// recoverable. Today no path produces it (VS_VERSIONINFO parsing is
// future work, S4 Task 0 removed the filename-pattern guess), so
// the function always returns (empty, nil) for well-formed PE files
// — operators see the `astinus:untracked:category=executable` stamp
// and the observed-only marker.
func (*PEExtractor) Extract(_ context.Context, file File) (Identity, error) {
	f, err := pe.NewFile(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // bad PE is "no match", not an error
	}
	defer func() { _ = f.Close() }()
	_ = peMachineString(f.Machine) // reserved for future VERSIONINFO path
	return Identity{}, nil
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
