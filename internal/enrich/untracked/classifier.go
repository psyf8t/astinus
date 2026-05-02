package untracked

import (
	"path"
	"strings"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// Category groups untracked files into the few buckets the enricher
// actually treats differently.
type Category int

const (
	// CategoryNoise is the bucket for files we deliberately ignore
	// (caches, locales, manpages, build artefacts). Listed for
	// completeness — the classifier just returns the bucket and the
	// caller decides whether to skip.
	CategoryNoise Category = iota
	// CategoryExecutable covers ELF/PE/Mach-O binaries.
	CategoryExecutable
	// CategoryArchive covers JAR/WAR/EAR/zip files.
	CategoryArchive
	// CategoryStaticArchive is .a — build-time intermediate, skipped.
	CategoryStaticArchive
	// CategoryScript covers files starting with `#!`.
	CategoryScript
	// CategoryLibrary covers .so / .dylib / .dll dynamic libraries.
	CategoryLibrary
	// CategoryConfig covers config / data / cert files we don't
	// fingerprint individually.
	CategoryConfig
	// CategoryUnknown means the bytes didn't match anything else.
	// The enricher still records it (with hash + name) so the SBOM
	// at least mentions it.
	CategoryUnknown
)

// Result is the outcome of classifying a single file.
type Result struct {
	Category Category
	// Note carries a short human-readable rationale for debug logs.
	Note string
}

// noisePathPrefixes is the prefix set we drop wholesale. Listed as
// constants so the spec ("полный список skip-patterns") is auditable.
var noisePathPrefixes = []string{
	"usr/share/man/",
	"usr/share/doc/",
	"usr/share/info/",
	"usr/share/locale/",
	"usr/share/i18n/",
	"usr/share/zoneinfo/",
	"usr/share/help/",
	"usr/lib/locale/",
	"var/cache/",
	"var/log/",
	"var/lib/dpkg/info/",
	"var/lib/apt/",
	"tmp/",
	"run/",
	"dev/",
	"proc/",
	"sys/",
	"etc/ssl/certs/",
	"etc/ca-certificates/",
}

// noiseSuffixes are extensions / filename endings we drop.
var noiseSuffixes = []string{
	".pyc",
	".pyo",
	".pyd",
	".dwarf",
	".debug",
	".la",
	".gmo",
	".mo",
	".cache",
}

// noiseBasenames are exact basenames we drop.
var noiseBasenames = map[string]struct{}{
	"__pycache__":  {},
	".DS_Store":    {},
	"Thumbs.db":    {},
	".gitkeep":     {},
	".gitignore":   {},
	"__init__.pyc": {},
}

// noisePathContains are substrings whose appearance in the path
// flags the file as noise (handles `__pycache__/foo.pyc`-style
// nested directories).
var noisePathContains = []string{
	"/__pycache__/",
	"/.cache/",
	"/.npm/",
	"/.yarn/",
}

// Classify routes a file into one of the Categories.
//
// magic is the leading bytes of the file (best-effort — pass at
// least 8 bytes, ideally the first 16). The function does NOT read
// the rest of the file.
func Classify(filePath string, magic []byte) Result {
	if r, ok := classifyAsNoise(filePath); ok {
		return r
	}
	if r, ok := classifyByExtension(filePath, magic); ok {
		return r
	}
	if r, ok := classifyByMagic(magic); ok {
		return r
	}
	return Result{Category: CategoryUnknown, Note: "unmatched"}
}

func classifyAsNoise(filePath string) (Result, bool) {
	if isNoisePath(filePath) {
		return Result{Category: CategoryNoise, Note: "noise path"}, true
	}
	if _, ok := noiseBasenames[path.Base(filePath)]; ok {
		return Result{Category: CategoryNoise, Note: "noise basename"}, true
	}
	for _, suffix := range noiseSuffixes {
		if strings.HasSuffix(filePath, suffix) {
			return Result{Category: CategoryNoise, Note: "noise suffix " + suffix}, true
		}
	}
	return Result{}, false
}

func classifyByExtension(filePath string, magic []byte) (Result, bool) {
	if strings.HasSuffix(filePath, ".a") {
		return Result{Category: CategoryStaticArchive, Note: ".a static archive"}, true
	}
	switch strings.ToLower(path.Ext(filePath)) {
	case ".so", ".dylib", ".dll":
		return Result{Category: CategoryLibrary, Note: "library by extension"}, true
	case ".jar", ".war", ".ear":
		return Result{Category: CategoryArchive, Note: "java archive by extension"}, true
	case ".zip":
		if fingerprint.IsZIPArchive(magic) {
			return Result{Category: CategoryArchive, Note: "generic zip"}, true
		}
	case ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg",
		".pem", ".crt", ".cer", ".key":
		return Result{Category: CategoryConfig, Note: "config/data by extension"}, true
	case ".md", ".txt", ".rst", ".html", ".htm":
		return Result{Category: CategoryConfig, Note: "documentation by extension"}, true
	}
	return Result{}, false
}

func classifyByMagic(magic []byte) (Result, bool) {
	switch {
	case fingerprint.IsELF(magic):
		return Result{Category: CategoryExecutable, Note: "ELF magic"}, true
	case fingerprint.IsPE(magic):
		return Result{Category: CategoryExecutable, Note: "PE magic"}, true
	case fingerprint.IsMachO(magic):
		return Result{Category: CategoryExecutable, Note: "Mach-O magic"}, true
	case fingerprint.IsZIPArchive(magic):
		return Result{Category: CategoryArchive, Note: "ZIP magic"}, true
	case fingerprint.IsScriptShebang(magic):
		return Result{Category: CategoryScript, Note: "shebang"}, true
	}
	return Result{}, false
}

// isNoisePath returns true when filePath sits under a noise prefix
// or contains a noise substring.
func isNoisePath(filePath string) bool {
	p := strings.TrimPrefix(filePath, "/")
	for _, prefix := range noisePathPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	for _, sub := range noisePathContains {
		if strings.Contains("/"+p, sub) {
			return true
		}
	}
	return false
}
