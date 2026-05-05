package lifecycle

import (
	"strings"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ProductMapping is the per-product rule: which endoflife.date
// product key to use, and how to derive the cycle key from the
// Component's version string.
//
// VersionFormat:
//   - "major"        — keep the leading numeric segment (Node 20)
//   - "major.minor"  — keep the first two segments (Python 3.11)
//   - "exact"        — pass the version through unchanged
type ProductMapping struct {
	Product       string
	VersionFormat string
}

// purlToProduct maps PURL prefixes to endoflife.date products.
// Used for OS-level packages where the distro identity is encoded
// in the PURL.
var purlToProduct = map[string]ProductMapping{
	"pkg:apk/alpine":      {Product: "alpine", VersionFormat: "major.minor"},
	"pkg:deb/debian":      {Product: "debian", VersionFormat: "major"},
	"pkg:deb/ubuntu":      {Product: "ubuntu", VersionFormat: "major.minor"},
	"pkg:rpm/centos":      {Product: "centos", VersionFormat: "major"},
	"pkg:rpm/rhel":        {Product: "rhel", VersionFormat: "major"},
	"pkg:rpm/rocky":       {Product: "rocky-linux", VersionFormat: "major"},
	"pkg:rpm/almalinux":   {Product: "almalinux", VersionFormat: "major"},
	"pkg:rpm/fedora":      {Product: "fedora", VersionFormat: "major"},
	"pkg:rpm/amazonlinux": {Product: "amazon-linux", VersionFormat: "major"},
	"pkg:rpm/opensuse":    {Product: "opensuse", VersionFormat: "major.minor"},
}

// nameToProduct maps Component.Name to endoflife.date products.
// Used for runtime / language Components surfaced as application or
// library type with no PURL prefix to key off (e.g. a Go binary
// classified as type=application named `node`). Keys are matched
// case-insensitively.
var nameToProduct = map[string]ProductMapping{
	// Languages / runtimes
	"node":    {Product: "nodejs", VersionFormat: "major"},
	"nodejs":  {Product: "nodejs", VersionFormat: "major"},
	"python":  {Product: "python", VersionFormat: "major.minor"},
	"python3": {Product: "python", VersionFormat: "major.minor"},
	"go":      {Product: "go", VersionFormat: "major.minor"},
	"golang":  {Product: "go", VersionFormat: "major.minor"},
	"openjdk": {Product: "openjdk", VersionFormat: "major"},
	"java":    {Product: "openjdk", VersionFormat: "major"},
	"jdk":     {Product: "openjdk", VersionFormat: "major"},
	"jre":     {Product: "openjdk", VersionFormat: "major"},
	"ruby":    {Product: "ruby", VersionFormat: "major.minor"},
	"php":     {Product: "php", VersionFormat: "major.minor"},
	"perl":    {Product: "perl", VersionFormat: "major.minor"},
	"rust":    {Product: "rust", VersionFormat: "major.minor"},
	"dotnet":  {Product: "dotnet", VersionFormat: "major"},

	// Databases
	"postgres":      {Product: "postgresql", VersionFormat: "major"},
	"postgresql":    {Product: "postgresql", VersionFormat: "major"},
	"mysql":         {Product: "mysql", VersionFormat: "major.minor"},
	"mariadb":       {Product: "mariadb", VersionFormat: "major.minor"},
	"redis":         {Product: "redis", VersionFormat: "major"},
	"mongodb":       {Product: "mongodb", VersionFormat: "major"},
	"sqlite":        {Product: "sqlite", VersionFormat: "major.minor"},
	"cassandra":     {Product: "cassandra", VersionFormat: "major"},
	"elasticsearch": {Product: "elasticsearch", VersionFormat: "major"},

	// Runtimes / orchestrators
	"kubernetes": {Product: "kubernetes", VersionFormat: "major.minor"},
	"docker":     {Product: "docker-engine", VersionFormat: "major"},
	"containerd": {Product: "containerd", VersionFormat: "major.minor"},
	"podman":     {Product: "podman", VersionFormat: "major"},
	"nginx":      {Product: "nginx", VersionFormat: "major.minor"},
	"apache":     {Product: "apache", VersionFormat: "major.minor"},
	"httpd":      {Product: "apache", VersionFormat: "major.minor"},
	"haproxy":    {Product: "haproxy", VersionFormat: "major.minor"},

	// OS surfaced as a Component (containers often have one of
	// these as type=operating-system).
	"alpine": {Product: "alpine", VersionFormat: "major.minor"},
	"debian": {Product: "debian", VersionFormat: "major"},
	"ubuntu": {Product: "ubuntu", VersionFormat: "major.minor"},
	"centos": {Product: "centos", VersionFormat: "major"},
	"rhel":   {Product: "rhel", VersionFormat: "major"},
}

// MapToProduct derives the (endoflife product, cycle key) pair for
// a Component. Returns ok=false when the Component cannot be
// mapped — most Components in a real SBOM (npm libraries etc.)
// fall in this bucket.
//
// PURL prefix wins over name lookup so a Component named "alpine"
// inside a `pkg:apk/alpine/...` PURL routes via the PURL rule
// (which carries the distro version, not the package version).
func MapToProduct(c *model.Component) (product, versionKey string, ok bool) {
	if c == nil {
		return "", "", false
	}
	if c.PURL != "" {
		for prefix, mapping := range purlToProduct {
			if strings.HasPrefix(c.PURL, prefix) {
				return mapping.Product, formatVersion(c.Version, mapping.VersionFormat), true
			}
		}
	}
	if c.Name == "" {
		return "", "", false
	}
	if mapping, exists := nameToProduct[strings.ToLower(c.Name)]; exists {
		return mapping.Product, formatVersion(c.Version, mapping.VersionFormat), true
	}
	return "", "", false
}

// formatVersion truncates a semver-style version string to the
// requested precision. Empty version → empty key (Resolver treats
// as "no cycle to look up" — Source returns ErrNotFound).
func formatVersion(version, format string) string {
	if version == "" {
		return ""
	}
	parts := strings.Split(version, ".")
	switch format {
	case "major":
		return parts[0]
	case "major.minor":
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return parts[0]
	case "exact":
		return version
	default:
		return version
	}
}

// ProductMappingCount returns the size of the bundled mapping
// table (PURL prefixes + names). Used by tests to gate that
// future edits don't accidentally drop products.
func ProductMappingCount() (purls, names int) {
	return len(purlToProduct), len(nameToProduct)
}
