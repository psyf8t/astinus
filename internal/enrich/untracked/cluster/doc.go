// Package cluster groups filesystem files that belong to the same
// upstream package into a single SBOM component, instead of recording
// each of the package's many files as a separate "untracked"
// component.
//
// # Why this exists
//
// `wget && tar -xzf sqlite-3.44.0.tar.gz` extracts ~2 000 files into
// `/opt/extracted/sqlite-version-3.44.0/`. Without clustering each of
// those files trips the untracked walker — the resulting SBOM has
// 2 000 entries for what is in fact ONE component. Bootstrap, vendored
// npm, Python wheels installed under `/opt/...` produce the same shape
// at smaller scales. After Hardening Sprint #1 the untracked-unknown
// count was dominated by these extracted-archive cases.
//
// # Strategy: anchor + density
//
// Detection runs in two stages:
//
//  1. **Anchor stage** — walk the image's visible files. When the
//     visitor sees a recognised package-manifest file (package.json,
//     Cargo.toml, go.mod, pom.xml, pyproject.toml, METADATA,
//     composer.json, Chart.yaml, *.gemspec) it parses just enough of
//     the file to extract `name + version` and records the file's
//     parent directory as a cluster root with confidence 1.0.
//
//  2. **Density stage** — for directories that contain no anchor but
//     look like an extracted source tree (`src/`, `Makefile`,
//     `configure`, `LICENSE`, version-pattern in directory name, file
//     count > 100), score the directory and emit a generic cluster
//     when the score crosses the threshold. This catches the
//     `sqlite-3.44.0` extracted-tarball case.
//
// Clusters are sorted by depth so a nested anchor wins over a
// shallower one (`/app/node_modules/foo/node_modules/bar/package.json`
// is its own cluster, separate from foo). Files under a cluster root
// are recorded as redundant under that cluster's component, not as
// independent untracked components.
//
// # What this package does NOT do
//
// It does not extract the cluster's files to disk; it does not hash
// individual cluster members; it does not perform vulnerability
// matching. Its single responsibility is "group files into clusters
// and emit one identity per cluster". Downstream enrichers (CPE,
// fingerprint matcher) consume the resulting Component as they would
// any other.
package cluster
