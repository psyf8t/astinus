package cluster

// Identity is the parsed package identity recovered from a cluster's
// anchor file or density signature.
//
// Fields are deliberately small — the cluster's full evidence (file
// list, total size) lives on the parent Cluster struct so identity
// can stay copy-cheap and serialisable.
type Identity struct {
	// Name is the package name (`name` field in package.json,
	// `[package].name` in Cargo.toml, etc.). Required for a cluster
	// to be emitted; an anchor file with no recoverable name is
	// dropped.
	Name string

	// Version is the package version. Optional — some anchors
	// (Helm charts under development, Go modules without explicit
	// version) emit clusters with empty Version; the cluster is
	// still useful for grouping.
	Version string

	// PURL is the Package URL the anchor type natively maps to:
	//   pkg:npm/<name>@<version>
	//   pkg:cargo/<name>@<version>
	//   pkg:golang/<module-path>@<version>
	//   pkg:maven/<group>/<artifact>@<version>
	//   pkg:pypi/<name>@<version>
	//   pkg:composer/<vendor>/<package>@<version>
	//   pkg:gem/<name>@<version>
	//   pkg:helm/<name>@<version>
	//   pkg:generic/<name>@<version>?root=<path>   (density-detected)
	PURL string

	// Type is the ecosystem name — short string consumed by the
	// `astinus:cluster:type` property. One of: "npm", "cargo",
	// "golang", "maven", "pypi", "composer", "gem", "helm",
	// "generic".
	Type string

	// AnchorPath is the path of the manifest file that triggered
	// detection. Empty for density-detected clusters.
	AnchorPath string

	// Confidence is 1.0 for anchor matches, < 1.0 for density
	// matches (proportional to the score). Surfaced in
	// `astinus:cluster:confidence`.
	Confidence float64

	// DetectionMethod describes how the cluster was found. Surfaced
	// in `astinus:cluster:detection-method`. Examples:
	//   "anchor:package.json"
	//   "anchor:dist-info/METADATA"
	//   "density:score=9"
	DetectionMethod string
}

// Cluster is one detected package — its identity, the directory it
// lives in, and the visible files it claims as members.
type Cluster struct {
	// Identity is the parsed metadata (Name, Version, PURL, ...).
	Identity Identity

	// Root is the canonical directory path that contains the
	// cluster's files (without a trailing slash). For an anchor
	// cluster this is `dirname(AnchorPath)`. For a density cluster
	// it's the directory the density scorer fingerprinted.
	Root string

	// Files is the canonical paths (slash-separated, no leading
	// slash) of every file the cluster claims. Populated by
	// assignFilesToClusters AFTER all clusters are detected so
	// nesting is handled correctly (a parent cluster does not
	// claim files that belong to a deeper nested cluster).
	Files []string

	// TotalSize is the sum of file sizes in Files (bytes).
	TotalSize int64
}

// Within reports whether p sits under c.Root. p must be in canonical
// form (slash-separated, no leading slash). Used by
// assignFilesToClusters and by the untracked enricher's pre-filter.
func (c *Cluster) Within(p string) bool {
	if c == nil || c.Root == "" {
		return false
	}
	return p == c.Root || hasPrefixWithSep(p, c.Root)
}

// hasPrefixWithSep reports whether p starts with prefix followed by
// a `/`. Avoids the `etc` matching `etcd` false positive that a
// plain HasPrefix would produce.
func hasPrefixWithSep(p, prefix string) bool {
	if len(p) <= len(prefix) {
		return false
	}
	if p[:len(prefix)] != prefix {
		return false
	}
	return p[len(prefix)] == '/'
}
