package extractor

import (
	"bytes"
	"context"
	"debug/elf"
	"strings"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// ELFLibraryExtractor used to synthesise an Identity from an ELF
// file's DT_SONAME + GNU build-id. S5 Task 1 reduced it to a
// no-op: SONAME alone does not anchor a verifiable package
// identity. `libcrypto.so.3` → SONAME → `crypto` doesn't tell us
// whether the binary is OpenSSL, LibreSSL, BoringSSL, or wolfSSL;
// the resulting `pkg:generic/crypto@` row matches nothing in NVD
// (`crypto:crypto` is not a registered vendor:product pair) and
// inflates the SBOM's addition count without contributing to
// vulnerability scanning.
//
// Run-#3 benchmark on a real Grafana image surfaced ~60 such
// SONAME-derived phantoms (`crypto`, `cap`, `cares`, `brotlicommon`,
// `brotlidec`, `iconv`, `curl` from `libcurl.so`, …). They dropped
// `addition_precision` to 0.42 and pushed the net Grype TP delta
// negative even after the Sprint 5 Task 0 stdlib hotfix.
//
// Decision: ELF SONAME goes the same way as the basename fallback
// dropped in S4 Task 0 (ADR-0038). Both are real file-level
// metadata, but neither maps to a package identity downstream
// tooling can match. The right home for ELF library identity is
// the upstream package manager (apk / dpkg / rpm), which Syft
// already catalogs reliably. ADR-0048.
//
// The struct + Match + Name + Confidence are preserved so the
// registry's interface stays uniform and a future content-grounded
// heuristic (symbol-table fingerprint against a known-build
// catalogue, GNU build-id → distro-package lookup, etc.) can slot
// back in without churning the registry wiring. The
// `sonameToName` helper is preserved alongside its unit test as
// scaffolding for that future work.
type ELFLibraryExtractor struct{}

// Name implements Extractor.
func (*ELFLibraryExtractor) Name() string { return "elf-library" }

// Confidence — placeholder; the extractor produces no Identity
// today. Value retained for the registry's interface contract.
func (*ELFLibraryExtractor) Confidence() float64 { return 0.6 }

// Match accepts only ELF magic; PE / Mach-O fall through to their
// extractors.
func (*ELFLibraryExtractor) Match(_ context.Context, file File) bool {
	return fingerprint.IsELF(file.Body)
}

// Extract returns Identity{} unconditionally for ELF inputs after
// S5 Task 1. The SONAME-based synthesis it used to perform (and
// ADR-0038 had kept as the one ELF identity signal worth trusting)
// produced ~60 `pkg:generic/<sonamename>@` phantom rows on real
// images and dragged `addition_precision` below the trustworthy
// threshold.
//
// The decoded ELF header is still walked for validation — a
// truncated / malformed ELF still returns (empty, nil) — but no
// fields propagate to the Identity. ADR-0048.
//
// The malformed-ELF path stays a no-error return because the
// registry treats `(empty, nil)` as "I don't match"; only true
// non-recoverable errors propagate via the second return.
func (*ELFLibraryExtractor) Extract(_ context.Context, file File) (Identity, error) {
	f, err := elf.NewFile(bytes.NewReader(file.Body))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // malformed ELF is not an error from the registry's POV
	}
	_ = f.Close()
	return Identity{}, nil
}

// sonameToName strips the `lib` prefix and `.so.X.Y.Z` suffix from a
// shared-library name. `libsodium.so.23.3.0` → `sodium`. Retained
// (with its unit test) as scaffolding for a future content-grounded
// ELF identity heuristic; not called by Extract today (S5 Task 1).
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

// basename returns path's basename (last `/`-separated segment).
// Local helper used by the PE and Java extractors.
func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
