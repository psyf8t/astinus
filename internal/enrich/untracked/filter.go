package untracked

import (
	"path"
	"strings"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// noisyFilenames lists per-package metadata files that ship inside
// almost every package and almost never represent a separately-tracked
// component. Skipped by default; opt back in via Options.IncludeNoise.
//
// This catalog covers the dominant "license + readme + changelog +
// authorship" pattern across npm / pypi / maven / debian / rpm.
var noisyFilenames = map[string]struct{}{
	"AUTHORS":       {},
	"AUTHORS.md":    {},
	"AUTHORS.txt":   {},
	"CHANGELOG":     {},
	"CHANGELOG.md":  {},
	"CHANGELOG.rst": {},
	"CHANGELOG.txt": {},
	"CHANGES":       {},
	"CHANGES.md":    {},
	"CHANGES.txt":   {},
	"CODEOWNERS":    {},
	"CONTRIBUTING":  {},
	"CONTRIBUTORS":  {},
	"COPYING":       {},
	"COPYING.LIB":   {},
	"COPYRIGHT":     {},
	"INSTALL":       {},
	"INSTALL.md":    {},
	"LICENCE":       {},
	"LICENCE.md":    {},
	"LICENCE.txt":   {},
	"LICENSE":       {},
	"LICENSE.md":    {},
	"LICENSE.txt":   {},
	"MAINTAINERS":   {},
	"NEWS":          {},
	"NEWS.md":       {},
	"NOTICE":        {},
	"NOTICE.md":     {},
	"NOTICE.txt":    {},
	"PATENTS":       {},
	"README":        {},
	"README.md":     {},
	"README.rst":    {},
	"README.txt":    {},
	"SECURITY":      {},
	"SECURITY.md":   {},
	"THANKS":        {},
	"TODO":          {},
	"TODO.md":       {},
	"VERSION":       {},
}

// noisyExtensions are file extensions for source / test / debug
// artefacts that are not shipped components.
//
// IMPORTANT — do NOT add to this list:
//   - .jar / .war / .ear (Java artefacts ARE components)
//   - .so / .dylib / .dll (shared libraries ARE components)
//   - .py / .js (could be entry points or minified bundles)
//   - .py / .pl files (entry points)
var noisyExtensions = map[string]struct{}{
	".asc":    {}, // GPG signature
	".c":      {}, // C source
	".cc":     {}, // C++ source
	".cpp":    {}, // C++ source
	".cxx":    {}, // C++ source
	".d.ts":   {}, // TypeScript declarations
	".dwo":    {}, // dwarf debug
	".dwp":    {}, // dwarf debug
	".gpg":    {}, // GPG signature
	".h":      {}, // C/C++ header
	".hpp":    {}, // C++ header
	".hxx":    {}, // C++ header
	".map":    {}, // source maps
	".o":      {}, // object file
	".obj":    {}, // object file
	".pyi":    {}, // python stub
	".sig":    {}, // detached signature
	".sym":    {}, // debug symbols
	".symtab": {}, // debug symbol table
	".ts":     {}, // TypeScript source
	".tsx":    {}, // TypeScript source
}

// packageManifestFiles are the per-ecosystem files whose presence at
// some path P implies "everything under dirname(P) belongs to one
// package." Used to derive package roots from existing components'
// known locations.
var packageManifestFiles = map[string]struct{}{
	"package.json":      {}, // npm
	"package-lock.json": {}, // npm (sometimes only marker present)
	"setup.py":          {}, // pypi (legacy)
	"PKG-INFO":          {}, // pypi (sdist)
	"METADATA":          {}, // pypi (wheel)
	"RECORD":            {}, // pypi (wheel manifest)
	"Cargo.toml":        {}, // cargo
	"go.mod":            {}, // go module
	"composer.json":     {}, // composer / php
	"Gemfile":           {}, // rubygems
	"Gemfile.lock":      {}, // rubygems
	".gemspec":          {}, // rubygems (suffix match — handled separately)
	"pom.xml":           {}, // maven
	"build.gradle":      {}, // gradle
	"DESCRIPTION":       {}, // R / cran
	"control":           {}, // debian
	"PKGBUILD":          {}, // arch
}

// IncludeMask controls which categories the enricher records.
// Default is "production": every category EXCEPT Redundant + Noise.
// post-Stage-13 hardening sprint (Task 1).
type IncludeMask struct {
	// IncludeRedundant adds files that sit inside an already-known
	// package directory. Useful for debug; default false.
	IncludeRedundant bool
	// IncludeNoise adds files classified as noise (license, locale,
	// docs, etc.). Useful for debug; default false.
	IncludeNoise bool
}

// allow returns true when the enricher should record a file with
// the given category under this mask.
func (m IncludeMask) allow(c Category) bool {
	switch c {
	case CategoryRedundant:
		return m.IncludeRedundant
	case CategoryNoise:
		return m.IncludeNoise
	default:
		return true
	}
}

// extractKnownPathsFromComponent collects every file path the
// component already covers, reading both the canonical
// `Evidence.Locations` AND the `syft:location:N:path` properties
// that Syft emits (Syft does not populate evidence.occurrences).
//
// post-Stage-13 hardening sprint (Task 1.1) — this is the single
// biggest win against node_modules duplication.
func extractKnownPathsFromComponent(c *model.Component) []string {
	var out []string
	if c.Evidence != nil {
		for _, loc := range c.Evidence.Locations {
			if loc.Path != "" {
				out = append(out, normalize(loc.Path))
			}
		}
	}
	for k, v := range c.Properties {
		if v == "" {
			continue
		}
		// "syft:location:0:path", "syft:location:1:path", ...
		if strings.HasPrefix(k, "syft:location:") && strings.HasSuffix(k, ":path") {
			out = append(out, normalize(v))
		}
	}
	return out
}

// extractPackageRoot returns the directory that owns a path when the
// path looks like a per-package manifest (package.json, setup.py,
// METADATA, Cargo.toml, ...). Returns "" when the path does not
// announce itself as a package boundary.
//
// Example: "app/node_modules/lodash/package.json" → "app/node_modules/lodash".
func extractPackageRoot(p string) string {
	base := path.Base(p)
	if _, ok := packageManifestFiles[base]; ok {
		return path.Dir(p)
	}
	if strings.HasSuffix(base, ".gemspec") {
		return path.Dir(p)
	}
	return ""
}

// buildKnownIndex collects two sets from the existing SBOM:
//
//   - paths: every exact file path already covered (for
//     point-membership skip).
//   - dirs: every directory inferred to be a package root, derived
//     from the locations of per-package manifest files. A new file
//     under any of these directories is "redundant" — it belongs to
//     the package that owns the directory.
//
// The dirs set is path-prefix-checked, so order within the slice
// doesn't matter. Both sets store paths WITHOUT leading slash.
type knownIndex struct {
	paths map[string]struct{}
	dirs  []string
}

func buildKnownIndex(sbom *model.SBOM) *knownIndex {
	idx := &knownIndex{paths: map[string]struct{}{}}
	dirSet := map[string]struct{}{}

	var visit func(comps []model.Component)
	visit = func(comps []model.Component) {
		for i := range comps {
			c := &comps[i]
			for _, p := range extractKnownPathsFromComponent(c) {
				idx.paths[p] = struct{}{}
				if root := extractPackageRoot(p); root != "" {
					dirSet[root+"/"] = struct{}{}
				}
			}
			if len(c.SubComponents) > 0 {
				visit(c.SubComponents)
			}
		}
	}
	visit(sbom.Components)

	idx.dirs = make([]string, 0, len(dirSet))
	for d := range dirSet {
		idx.dirs = append(idx.dirs, d)
	}
	return idx
}

// isRedundantAgainstIndex reports whether the path is already known
// (exact match) or sits under a known package root — i.e. it belongs
// to a component the SBOM already covers and should not be added as
// a separate component.
func isRedundantAgainstIndex(filePath string, idx *knownIndex) bool {
	p := normalize(filePath)
	if _, ok := idx.paths[p]; ok {
		return true
	}
	for _, dir := range idx.dirs {
		if strings.HasPrefix(p+"/", dir) || strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}

// isDocsOrMetadata reports whether the path's basename or extension
// marks it as license / readme / source / debug-symbol noise.
//
// Edge case: a file under a known noise basename or extension is
// still NOT noise if its magic bytes show it is a real artefact (the
// caller composes this with classifyByMagic). Today the catalogs
// only cover textual / source noise that doesn't overlap with binary
// magic, so the simpler "filename wins" rule is safe.
func isDocsOrMetadata(filePath string) bool {
	base := path.Base(filePath)
	if _, ok := noisyFilenames[base]; ok {
		return true
	}
	ext := strings.ToLower(path.Ext(filePath))
	if _, ok := noisyExtensions[ext]; ok {
		return true
	}
	return false
}
