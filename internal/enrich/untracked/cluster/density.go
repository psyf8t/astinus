package cluster

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// densityScoreThreshold is the minimum score a directory needs to be
// emitted as a density-detected cluster. The number is calibrated
// against the dominant case (extracted source tarballs like
// `sqlite-3.44.0`): version-pattern in name + Makefile + README +
// large file count usually clears 7 by a comfortable margin, while
// random `/etc/` directories never do.
const densityScoreThreshold = 7

// signature is the per-directory feature snapshot the density scorer
// computes. Populated by walking the directory's immediate file list
// once.
type signature struct {
	hasMakefile      bool
	hasConfigure     bool
	hasCMakeLists    bool
	hasReadme        bool
	hasLicense       bool
	hasSrcDir        bool
	hasIncludeDir    bool
	hasTestDir       bool
	versionInDirName string // captured version when the dir name carries one
	dirNameStripped  string // dir base with the version trimmed off (the package name)
	fileCount        int
}

// scoreDirectory returns the (signature, score) for dir given its
// IMMEDIATE children (files + subdir basenames) plus the file count
// recursively under it. The recursive count is what makes a 1 000-file
// extracted tarball qualify.
func scoreDirectory(dir string, children []string, recursiveFileCount int) (signature, int) {
	sig := signature{fileCount: recursiveFileCount}
	for _, c := range children {
		stampChildSignal(&sig, c)
	}
	if name, version, ok := parseNameVersionFromDirName(path.Base(dir)); ok {
		sig.versionInDirName = version
		sig.dirNameStripped = name
	}
	return sig, scoreSignature(sig)
}

// stampChildSignal flips the relevant signature flags for one child
// basename. Extracted from scoreDirectory so the per-child switch
// stays cheap and the cyclomatic complexity of scoreDirectory itself
// stays low.
func stampChildSignal(sig *signature, c string) {
	switch c {
	case "Makefile", "makefile", "GNUmakefile":
		sig.hasMakefile = true
	case "configure", "configure.ac", "configure.in":
		sig.hasConfigure = true
	case "CMakeLists.txt":
		sig.hasCMakeLists = true
	}
	lc := strings.ToLower(c)
	switch {
	case strings.HasPrefix(lc, "readme"):
		sig.hasReadme = true
	case strings.HasPrefix(lc, "license"), strings.HasPrefix(lc, "licence"),
		lc == "copying", lc == "copying.lib":
		sig.hasLicense = true
	case lc == "src":
		sig.hasSrcDir = true
	case lc == "include":
		sig.hasIncludeDir = true
	case lc == "test", lc == "tests", lc == "spec":
		sig.hasTestDir = true
	}
}

// scoreSignature applies the scoring rubric to a populated signature.
// Numbers are tuneable; documented in ADR-0021.
func scoreSignature(sig signature) int {
	score := 0
	if sig.hasMakefile && sig.hasConfigure {
		score += 5 // autotools
	}
	if sig.hasCMakeLists {
		score += 4
	}
	if sig.versionInDirName != "" {
		score += 5
	}
	if sig.hasSrcDir && sig.hasIncludeDir {
		score += 3
	}
	if sig.hasTestDir {
		score += 2
	}
	if sig.hasLicense && sig.hasReadme {
		score += 2
	}
	if sig.fileCount > 100 {
		score++
	}
	if sig.fileCount > 1000 {
		score += 2
	}
	return score
}

// densityIdentity builds an Identity for a directory whose signature
// crossed the threshold. Returns ok=false when the directory cannot
// produce a usable name (no version-pattern AND no readable basename
// — extremely rare).
func densityIdentity(dir string, sig signature, score int) (Identity, bool) {
	name := sig.dirNameStripped
	version := sig.versionInDirName
	if name == "" {
		// Density without a version-in-name can still be a useful
		// cluster (think `/opt/myapp/` containing a Makefile + src/
		// + LICENSE). Use the dir basename verbatim and leave
		// version empty.
		if dir == "" {
			// The image root is never a cluster.
			return Identity{}, false
		}
		name = path.Base(dir)
		if name == "" || name == "/" || name == "." {
			return Identity{}, false
		}
	}
	confidence := float64(score) / 10.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	purl := fmt.Sprintf("pkg:generic/%s", name)
	if version != "" {
		purl = fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
	purl += fmt.Sprintf("?root=/%s", strings.TrimPrefix(dir, "/"))
	return Identity{
		Name:            name,
		Version:         version,
		PURL:            purl,
		Type:            "generic",
		Confidence:      confidence,
		DetectionMethod: fmt.Sprintf("density:score=%d", score),
	}, true
}

// nameVersionPatterns is the family of directory-name shapes the
// path parser recognises, in priority order. The last-match-wins
// nature of regexp.FindStringSubmatch means we try the most-specific
// shape first.
var nameVersionPatterns = []*regexp.Regexp{
	// sqlite-version-3.44.0 — explicit "version" segment
	regexp.MustCompile(`^(?P<name>[A-Za-z][A-Za-z0-9_+.-]*?)-version-(?P<version>\d[A-Za-z0-9._+-]*)$`),
	// yq-v4.40.5 — leading-v variant
	regexp.MustCompile(`^(?P<name>[A-Za-z][A-Za-z0-9_+.-]*?)-v(?P<version>\d[A-Za-z0-9._+-]*)$`),
	// linux_4.19.0 — underscore separator
	regexp.MustCompile(`^(?P<name>[A-Za-z][A-Za-z0-9+.-]*?)_(?P<version>\d[A-Za-z0-9._+-]*)$`),
	// bootstrap-5.3.2 / sqlite-3.44.0 — plain dash
	regexp.MustCompile(`^(?P<name>[A-Za-z][A-Za-z0-9_+.-]*?)-(?P<version>\d[A-Za-z0-9._+-]*)$`),
}

// parseNameVersionFromDirName tries each pattern in order and
// returns the first match's name + version groups. Returns ok=false
// when nothing matches (e.g., random `/etc/` directory names).
func parseNameVersionFromDirName(base string) (name, version string, ok bool) {
	for _, p := range nameVersionPatterns {
		m := p.FindStringSubmatch(base)
		if m == nil {
			continue
		}
		nameIdx := p.SubexpIndex("name")
		versionIdx := p.SubexpIndex("version")
		if nameIdx >= 0 && versionIdx >= 0 {
			return m[nameIdx], m[versionIdx], true
		}
	}
	return "", "", false
}
