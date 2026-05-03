// Package enrich runs a chain of Enrichers over a canonical SBOM,
// each adding (and only adding) information drawn from the paired
// container image.
//
// Contract for every enricher (per spec section 8.5):
//
//   - Idempotent. Calling Enrich twice on the same SBOM must produce
//     the same result. The reader hydrates Astinus-typed fields back
//     from `astinus:*` properties (see internal/sbom/cyclonedx) so a
//     second run does not duplicate them.
//   - Non-destructive. Enrichers MUST NOT remove or rewrite fields
//     populated by the SBOM source. They may add new fields and
//     adjust their own typed fields (LayerInfo, Origin, etc.).
//   - Resilient. Missing data is logged at debug level; it does not
//     abort the pipeline.
//   - Namespaced. Any property an enricher writes belongs under
//     `astinus:<enricher-name>:*` or one of the well-known names in
//     `internal/sbom/model/properties.go`.
package enrich

import (
	"context"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Enricher modifies a canonical SBOM in place using information from
// the paired image bundle.
type Enricher interface {
	// Name is the unique identifier used by --enable / --disable
	// flags and as the property namespace prefix
	// (`astinus:<name>:*`).
	Name() string

	// Dependencies declares which other enrichers MUST run before
	// this one. Each entry is the dependency's `Name()`. The
	// pipeline runs `TopoSort` before dispatch and refuses to
	// start when a declared dependency is missing or when the
	// graph has a cycle (PRSD-Task-6).
	//
	// Return nil (or an empty slice) for an enricher that doesn't
	// need ordering hints — it will run in input order relative
	// to its peers.
	Dependencies() []string

	// Enrich mutates sbom. It SHOULD return early on context
	// cancellation. It MAY do I/O (read layers, look up CPEs);
	// pipeline-level instrumentation lives in pipeline.go.
	Enrich(ctx context.Context, sbom *model.SBOM, bundle *image.Bundle) error
}
