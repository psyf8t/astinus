package extractor

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/psyf8t/astinus/internal/fingerprint"
)

// JavaExtractor recovers Maven coordinates from a JAR / WAR / EAR
// using a 2-tier source of truth:
//
//  1. `META-INF/maven/<group>/<artifact>/pom.properties` — the
//     authoritative source written by the Maven build plugin.
//     Records groupId + artifactId + version verbatim.
//  2. `META-INF/MANIFEST.MF` — the universal JAR manifest. We trust
//     Implementation-Title / Implementation-Version when populated;
//     fall back to OSGi Bundle-* keys.
//
// S4 Task 0 removed the filename-pattern third tier: a JAR named
// `commons-lang3-3.14.0.jar` with no manifest and no pom.properties
// is not a verifiable identity claim, and synthesising one let
// re-packaged / renamed JARs slip into the SBOM as identified
// components. JARs that fall past both tiers are recorded as
// observed-only by the untracked enricher.
type JavaExtractor struct{}

// Name implements Extractor.
func (*JavaExtractor) Name() string { return "java" }

// Confidence — the reported value tracks the BEST tier the
// extractor reached. We expose the maximum because Match runs
// before we know which tier will hit; the per-tier confidence is
// stamped in Identity.Properties for operators who need it.
func (*JavaExtractor) Confidence() float64 { return 0.9 }

// Match accepts JAR-shaped filenames (.jar / .war / .ear) whose
// body starts with the zip magic. The zip magic check rejects files
// that have the right extension but were truncated mid-download.
func (*JavaExtractor) Match(_ context.Context, file File) bool {
	if !looksLikeJARName(file.Path) {
		return false
	}
	return fingerprint.IsZIPArchive(file.Body)
}

// Extract walks the 2-tier source-of-truth chain. Returns
// (empty, nil) when neither pom.properties nor MANIFEST.MF yields
// a verifiable identity — the untracked enricher records the JAR
// as observed-only in that case. S4 Task 0.
func (*JavaExtractor) Extract(_ context.Context, file File) (Identity, error) {
	zr, err := zip.NewReader(bytes.NewReader(file.Body), int64(len(file.Body)))
	if err != nil {
		return Identity{}, nil //nolint:nilerr // bad zip is "no match", not an error
	}

	if id, ok := readPomProperties(zr); ok {
		return id, nil
	}
	if id, ok := readManifestIdentity(file, zr); ok {
		return id, nil
	}
	return Identity{}, nil
}

// ─── tier 1: META-INF/maven/.../pom.properties ─────────────────────

func readPomProperties(zr *zip.Reader) (Identity, bool) {
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "META-INF/maven/") || !strings.HasSuffix(f.Name, "/pom.properties") {
			continue
		}
		props, err := loadPomProperties(f)
		if err != nil {
			continue
		}
		artifact := props["artifactId"]
		if artifact == "" {
			continue
		}
		group := props["groupId"]
		version := props["version"]
		id := Identity{
			Name:    artifact,
			Version: version,
			Vendor:  group,
			PURL:    purlMaven(group, artifact, version),
			Properties: map[string]string{
				"java.tier":     "pom-properties",
				"maven.groupId": group,
			},
		}
		return id, true
	}
	return Identity{}, false
}

// pomPropertiesMaxBytes caps an individual pom.properties read.
// These files are kilobytes-sized in practice; the cap defends
// against zip-bomb pathological inputs.
const pomPropertiesMaxBytes = 64 << 10 // 64 KiB

func loadPomProperties(f *zip.File) (map[string]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(io.LimitReader(rc, pomPropertiesMaxBytes))
	if err != nil {
		return nil, err
	}
	return parsePropertiesFile(body), nil
}

// parsePropertiesFile parses java.util.Properties shape: `key=value`
// per line, `#` and `!` are comments, leading whitespace is
// stripped. We do not handle multi-line continuations or unicode
// escapes — pom.properties never uses them in practice.
func parsePropertiesFile(body []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 32*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.IndexAny(line, "=:")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// ─── tier 2: META-INF/MANIFEST.MF ──────────────────────────────────

func readManifestIdentity(file File, _ *zip.Reader) (Identity, bool) {
	manifest, err := fingerprint.ReadJARMetadata(file.Body)
	if err != nil {
		if errors.Is(err, fingerprint.ErrNoManifest) || errors.Is(err, fingerprint.ErrNotJAR) {
			return Identity{}, false
		}
		return Identity{}, false
	}
	if manifest == nil {
		return Identity{}, false
	}
	name := nonEmpty(manifest.BundleSymbolicName, manifest.ImplementationTitle, manifest.BundleName)
	version := nonEmpty(manifest.BundleVersion, manifest.ImplementationVersion)
	if name == "" || version == "" {
		return Identity{}, false
	}
	id := Identity{
		Name:    name,
		Version: version,
		Vendor:  manifest.ImplementationVendor,
		PURL:    purlMaven(manifest.ImplementationVendor, name, version),
		Properties: map[string]string{
			"java.tier":            "manifest",
			"java.implementation":  manifest.ImplementationTitle,
			"java.bundle.symbolic": manifest.BundleSymbolicName,
			"java.bundle.version":  manifest.BundleVersion,
		},
	}
	if manifest.MainClass != "" {
		id.Properties["java.main-class"] = manifest.MainClass
	}
	return id, true
}

// ─── helpers ───────────────────────────────────────────────────────

func looksLikeJARName(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".war") ||
		strings.HasSuffix(lower, ".ear")
}

// purlMaven assembles a Maven PURL. Empty group renders as
// `pkg:maven/<artifact>@<version>` (caller supplies "" when only
// the manifest tier or filename tier matched).
func purlMaven(group, artifact, version string) string {
	if artifact == "" {
		return ""
	}
	out := "pkg:maven/"
	if group != "" {
		out += group + "/"
	}
	out += artifact
	if version != "" {
		out += "@" + version
	}
	return out
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
