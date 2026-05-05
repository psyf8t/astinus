package registry

import (
	"context"
	"errors"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// Source is the per-ecosystem package-registry adapter.
//
// Implementations route a parsed PURL through one or more mirror
// URLs (with optional auth + mTLS) and return enrichment metadata.
// Concurrency: Fetch is called from the enricher's hot loop;
// implementations MUST be safe for concurrent use after construction.
//
// Errors: Fetch returns ErrNotFound for "this package isn't in this
// registry"; ErrTransient for retryable failures (5xx, network
// timeout, rate-limit denial); a wrapped real error for everything
// else. The Resolver continues to the next Source on ErrNotFound /
// ErrTransient — it stops only when one Source returns metadata.
type Source interface {
	// Name is the short identifier used in logs and stamped onto
	// the `astinus:registry:source` Component property.
	Name() string

	// Supports reports whether this Source handles the given PURL
	// type. The Resolver short-circuits Fetch calls on Sources
	// whose Supports returns false.
	Supports(purlType string) bool

	// Fetch returns enrichment metadata for the parsed PURL or one
	// of the sentinel errors above. nil metadata + nil error is
	// reserved for "the request succeeded but the response had no
	// usable fields" — the Resolver treats it like ErrNotFound.
	Fetch(ctx context.Context, purl cpe.PURL) (*Metadata, error)

	// RequiresNetwork is true when Fetch makes outbound HTTP
	// calls. The Resolver filters these out under `--no-network`.
	RequiresNetwork() bool
}

// Metadata is the enrichment payload one Source produces for one
// PURL. All fields are optional; the enricher merges only the
// non-empty ones onto the Component (never overrides).
type Metadata struct {
	// Name / Version / Description are the canonical identifying
	// fields. Name and Version are usually identical to the PURL's
	// — kept for log diagnostics.
	Name        string
	Version     string
	Description string

	// Licenses is the deduplicated SPDX-id-or-name list as the
	// registry recorded them. Source implementations normalise
	// upstream variants ("Apache License 2.0" → "Apache-2.0")
	// where unambiguous.
	Licenses []License

	// Supplier identifies the publishing organisation. Most
	// registries don't natively model "supplier" — Sources project
	// the closest available signal (npm publisher, distro
	// maintainer, etc.).
	Supplier Supplier

	// Author is the per-component human author when distinct from
	// supplier (npm `author`, PyPI `author_email`).
	Author string

	// Homepage / Repository / BugTracker / Documentation are URL
	// breadcrumbs the SBOM writer projects as
	// `astinus:registry:*` Component properties (the canonical
	// model doesn't model CycloneDX externalReferences as typed
	// fields — see ADR-0033 §3 for the rationale).
	Homepage      string
	Repository    string
	BugTracker    string
	Documentation string

	// Hashes is the {algorithm → hex value} map for the package's
	// distribution artifact. Useful for supply-chain verification:
	// the SBOM writer adds new entries to Component.Hashes when
	// they're absent.
	Hashes map[string]string

	// Keywords / Maintainers carry less-structured signals some
	// downstream consumers find useful. Reserved for future
	// projection into Component properties.
	Keywords    []string
	Maintainers []Maintainer
}

// IsEmpty reports whether the metadata has nothing usable. The
// Resolver treats an empty Metadata identical to ErrNotFound.
func (m *Metadata) IsEmpty() bool {
	if m == nil {
		return true
	}
	return m.Description == "" &&
		m.Author == "" &&
		m.Homepage == "" &&
		m.Repository == "" &&
		m.BugTracker == "" &&
		m.Documentation == "" &&
		len(m.Licenses) == 0 &&
		m.Supplier.Name == "" &&
		len(m.Hashes) == 0
}

// License is one license entry as the registry reported it.
// SPDXID is preferred when distinguishable; Name is the raw label
// when it can't be normalised.
type License struct {
	SPDXID string
	Name   string
	URL    string
}

// Supplier identifies the package publisher.
type Supplier struct {
	Name  string
	URL   string
	Email string
}

// Maintainer is one named maintainer for diagnostics. Reserved.
type Maintainer struct {
	Name  string
	Email string
	URL   string
}

// Sentinel errors. The Resolver branches on these; Source
// implementations MUST wrap their internal errors with
// `errors.Join` or `fmt.Errorf("...: %w", ErrNotFound)` so the
// branching works.
var (
	// ErrNotFound — the package isn't in this Source. Resolver
	// continues to the next Source.
	ErrNotFound = errors.New("registry: package not found")

	// ErrTransient — temporary failure (5xx, network timeout,
	// rate-limit denial). Resolver continues to the next Source.
	ErrTransient = errors.New("registry: transient failure")

	// ErrNoNetwork — Source requires network but `--no-network`
	// was set. Resolver swallows this silently (no warn-spam).
	ErrNoNetwork = errors.New("registry: network required but disabled")

	// ErrUnsupported — Source doesn't handle this PURL type. The
	// Resolver normally short-circuits via Supports(); this is the
	// belt-and-braces fallback for Sources that fail Supports
	// later (e.g. a typo'd PURL passed Supports but not the
	// detailed check).
	ErrUnsupported = errors.New("registry: PURL type not supported by this source")
)
