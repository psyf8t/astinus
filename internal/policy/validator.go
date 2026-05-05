package policy

import (
	"context"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Validator inspects a finalized SBOM and returns zero or more
// findings. Concrete validators live under `policy/builtin/`.
//
// Concurrency: validators are invoked from the compliance enricher's
// hot loop; implementations MUST be safe for concurrent calls
// (today the loop is sequential, but future work may parallelise).
//
// Errors: Validate returns an error only when the validator could
// not run at all (e.g. an embedded resource failed to load). A
// validator that ran and found nothing returns `(nil, nil)`. A
// validator that found problems returns the findings + nil error.
type Validator interface {
	// Name is the short identifier used for log lines and the
	// `astinus:compliance:<name>:status` SBOM property.
	Name() string

	// Description is a one-line operator-facing explanation of
	// what this validator checks. Surfaced in CLI diagnostics.
	Description() string

	// Validate inspects sbom and returns findings.
	Validate(ctx context.Context, sbom *model.SBOM) ([]Finding, error)
}
