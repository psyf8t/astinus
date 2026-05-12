package extractor

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// ELFLibraryExtractor recovers an Identity from a generic ELF file's
// SONAME and GNU build-id. It runs LAST in the registry chain — the
// language-specific extractors (Go, Rust) match first and produce
// stronger Identities; the ELF extractor catches everything else
// (`libc.so.6`, `libssl.so.3`, vendored `.so` blobs).
//
// S4 Task 0: SONAME is the only identity signal this extractor trusts.
// Earlier revisions fell back to the file's basename when SONAME was
// absent — that produced ~77 phantom `pkg:generic/<basename>` rows on
// real images (stripped busybox / openssl helpers, named symlinks),
// which then attracted false-positive CVE matches in downstream
// scanners. A binary without a DT_SONAME entry has no verifiable
// package identity, so the extractor now returns empty Identity and
// the untracked enricher records the file as observed-only.
type ELFLibraryExtractor struct{}

// Name implements Extractor.
func (*ELFLibraryExtractor) Name() string { return "elf-library" }

// Confidence — SONAME + build-id are real metadata but not sufficient
// to fingerprint the package without distro context. Operators
// downstream may want to gate on this.
func (*ELFLibraryExtractor) Confidence() float64 { return 0.6 }

// Match accepts only ELF magic; PE / Mach-O fall through to their
// extractors.
func (*ELFLibraryExtractor) Match(_ context.Context, file File) bool {
	return fingerprint.IsELF(file.Body)
}

// Extract reads the ELF file and returns Identity when DT_SONAME is
// present (the only ELF metadata that anchors a package identity).
// GNU build-id and .rodata version strings alone don't tell us which
// package the binary belongs to, so they no longer fabricate an
// Identity — the caller will record the file as observed-only. S4
// Task 0.
func (*ELFLibraryExtractor) Extract(_ context.Context, file File) (Identity, error) {
	f, err := elf.NewFile(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // malformed ELF is not an error from the registry's POV
	}
	defer func() { _ = f.Close() }()

	soname := readELFSoname(f)
	if soname == "" {
		// No SONAME — without it we have no verifiable identity.
		// Earlier revisions fell back to basename(file.Path) and
		// produced phantom `pkg:generic/<basename>` rows; that path
		// is gone (see type doc).
		return Identity{}, nil
	}

	name := sonameToName(soname)
	if name == "" {
		return Identity{}, nil
	}

	buildID := readELFBuildID(f)
	version := readELFVersionString(f)

	props := map[string]string{
		"elf.soname":  soname,
		"elf.machine": f.Machine.String(),
	}
	if buildID != "" {
		props["elf.buildid"] = buildID
	}

	id := Identity{
		Name:       name,
		Version:    version,
		PURL:       purlGeneric(name, version),
		Properties: props,
	}
	return id, nil
}

// readELFSoname returns the DT_SONAME string from the .dynamic
// section, or "" when no SONAME is recorded (executables typically
// have none; libraries usually do).
func readELFSoname(f *elf.File) string {
	soStrings, err := f.DynString(elf.DT_SONAME)
	if err != nil || len(soStrings) == 0 {
		return ""
	}
	return soStrings[0]
}

// readELFBuildID returns the GNU build-id (hex string) from the
// .note.gnu.build-id section. Returns "" when the section is absent
// (older toolchains, manually stripped binaries).
func readELFBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	// Note format: namesz | descsz | type | "GNU\0" | desc[descsz]
	// We only care about desc; it's always at offset 16.
	if len(data) < 16 {
		return ""
	}
	desc := data[16:]
	return hex.EncodeToString(desc)
}

// rodataVersionPattern matches common version strings embedded in
// .rodata: "1.2.3", "v0.5.6", "2024.01.15". The pattern is anchored
// on a leading separator (NUL or non-alphanumeric) so it doesn't
// match arbitrary digit substrings.
var rodataVersionPattern = regexp.MustCompile(`(?:^|\x00|[^\w.])v?(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?)\b`)

// rodataMaxBytes caps how much of .rodata we scan for a version
// string. Real ELF .rodata can be many MiB; we don't need to scan
// the whole thing.
const rodataMaxBytes = 1 << 20 // 1 MiB

// readELFVersionString scrapes a version-like substring from the
// first MiB of .rodata. Heuristic — many CLI tools embed their
// version literally as a string. Returns "" when nothing matches.
func readELFVersionString(f *elf.File) string {
	sec := f.Section(".rodata")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	if len(data) > rodataMaxBytes {
		data = data[:rodataMaxBytes]
	}
	m := rodataVersionPattern.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// sonameToName strips the `lib` prefix and `.so.X.Y.Z` suffix from a
// shared-library name. `libsodium.so.23.3.0` → `sodium`.
func sonameToName(soname string) string {
	if soname == "" {
		return ""
	}
	name := soname
	if i := strings.Index(name, ".so"); i > 0 {
		name = name[:i]
	}
	name = strings.TrimPrefix(name, "lib")
	return name
}

// purlGeneric renders a `pkg:generic/<name>@<version>` PURL. Used by
// the ELF library extractor when no language-specific PURL applies.
func purlGeneric(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return "pkg:generic/" + name
	}
	return fmt.Sprintf("pkg:generic/%s@%s", name, version)
}

// basename returns path's basename (last `/`-separated segment).
// Local helper so the package doesn't depend on path/filepath for a
// one-liner.
func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
