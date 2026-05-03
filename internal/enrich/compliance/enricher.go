package compliance

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/policy"
	builtin "github.com/psyf8t/astinus/internal/policy/builtin/compliance"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// Name is the enricher identifier (`--enable compliance`).
const Name = "compliance"

// Enricher runs every registered policy.Validator and stamps the
// resulting findings onto the SBOM.
type Enricher struct {
	validators []policy.Validator
}

// New returns the Enricher configured with the bundled defaults
// (NTIA, EU CRA, CycloneDX-structural, SPDX-structural).
func New() *Enricher {
	return NewWithValidators(
		builtin.NewNTIA(),
		builtin.NewEUCRA(),
		builtin.NewCycloneDXStructural(),
		builtin.NewSPDXStructural(),
	)
}

// NewWithValidators returns an Enricher with the supplied
// validator chain. Useful for tests + future CLI flags that
// disable individual validators.
func NewWithValidators(validators ...policy.Validator) *Enricher {
	return &Enricher{validators: append([]policy.Validator(nil), validators...)}
}

// Name implements enrich.Enricher.
func (*Enricher) Name() string { return Name }

// Dependencies implements enrich.Enricher. PRSD-Task-6: compliance
// MUST run AFTER `dedup` (the finalize stage) so validators see the
// post-dedup component set with every PURL / CPE / Origin already
// stamped.
func (*Enricher) Dependencies() []string { return []string{"dedup"} }

// Enrich runs every validator and stamps findings onto the SBOM.
//
// The enricher never aborts the pipeline: validator errors are
// logged and the chain continues with the next validator. Findings
// land in three places:
//
//   - `sbom.Metadata.Properties[astinus:compliance:findings-count]`
//     (and the per-severity counts) — aggregate.
//   - `sbom.Metadata.Properties[astinus:compliance:<validator>:status]`
//     — per-validator pass / passed-with-warnings / failed.
//   - `c.Properties[astinus:compliance:finding:<rule-id>]` =
//     `<severity>` on the Component the finding names — per-finding.
//     Cross-rule findings on the same component aggregate via
//     suffixed keys.
//
// Findings is the slice the CLI's `--fail-on` gate consumes; the
// enricher returns the count via the SBOM property. The slice
// itself is not surfaced through the Enricher signature because
// `enrich.Enricher.Enrich` returns only `error` — the slice is
// reachable from the SBOM properties downstream consumers parse.
func (e *Enricher) Enrich(ctx context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	if sbom == nil {
		return fmt.Errorf("compliance: nil sbom")
	}
	logger := slog.Default()

	all := make([]policy.Finding, 0, 16)
	statuses := make(map[string]string, len(e.validators))

	for _, v := range e.validators {
		findings, err := v.Validate(ctx, sbom)
		if err != nil {
			logger.Warn("compliance.validator.error",
				"validator", v.Name(),
				"err", err.Error())
			statuses[v.Name()] = "errored"
			continue
		}
		statuses[v.Name()] = statusFor(findings)
		all = append(all, findings...)
	}

	stampMetadata(sbom, statuses, all)
	stampPerComponent(sbom, all)

	logger.Info("compliance.complete",
		"validators", len(e.validators),
		"findings_total", len(all),
		"critical", countSeverity(all, policy.SeverityCritical),
		"high", countSeverity(all, policy.SeverityHigh),
		"medium", countSeverity(all, policy.SeverityMedium),
		"low", countSeverity(all, policy.SeverityLow),
		"info", countSeverity(all, policy.SeverityInfo),
	)
	return nil
}

// statusFor reduces a per-validator findings slice into a single
// status string consumed by the SBOM property writer.
func statusFor(findings []policy.Finding) string {
	if len(findings) == 0 {
		return "passed"
	}
	for _, f := range findings {
		if f.Severity.AtLeast(policy.SeverityHigh) {
			return "failed"
		}
	}
	return "passed-with-warnings"
}

// stampMetadata writes per-validator status + aggregate counts on
// the SBOM-level Metadata.Properties.
func stampMetadata(sbom *model.SBOM, statuses map[string]string, all []policy.Finding) {
	if sbom.Metadata.Properties == nil {
		sbom.Metadata.Properties = map[string]string{}
	}
	for name, status := range statuses {
		sbom.Metadata.Properties["astinus:compliance:"+name+":status"] = status
	}
	sbom.Metadata.Properties[model.PropertyComplianceFindingsCount] =
		strconv.Itoa(len(all))
	sbom.Metadata.Properties[model.PropertyComplianceCriticalCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityCritical))
	sbom.Metadata.Properties[model.PropertyComplianceHighCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityHigh))
	sbom.Metadata.Properties[model.PropertyComplianceMediumCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityMedium))
	sbom.Metadata.Properties[model.PropertyComplianceLowCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityLow))
}

// stampPerComponent writes `astinus:compliance:finding:<rule-id>`
// on each named Component so dashboards can correlate findings to
// components without parsing aggregate counts.
func stampPerComponent(sbom *model.SBOM, findings []policy.Finding) {
	for _, f := range findings {
		if f.Component == "" {
			continue
		}
		c := findComponentByBOMRef(sbom.Components, f.Component)
		if c == nil {
			continue
		}
		if c.Properties == nil {
			c.Properties = map[string]string{}
		}
		c.Properties["astinus:compliance:finding:"+f.RuleID] = f.Severity.String()
	}
}

// findComponentByBOMRef does a depth-first search for the component
// that owns the BOMRef. Linear today; the slice is bounded by SBOM
// size and dedup runs before us.
func findComponentByBOMRef(comps []model.Component, ref string) *model.Component {
	for i := range comps {
		if comps[i].BOMRef == ref {
			return &comps[i]
		}
		if found := findComponentByBOMRef(comps[i].SubComponents, ref); found != nil {
			return found
		}
	}
	return nil
}

// countSeverity returns the number of findings at exactly s.
func countSeverity(findings []policy.Finding, s policy.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Findings returns the canonical findings slice for the SBOM by
// re-running every validator. Used by the CLI's `--fail-on` gate
// after Enrich has finished — the gate needs the actual Severity
// values, which the per-Component property only conveys as a
// string.
//
// Calling Findings repeatedly is safe (validators are idempotent);
// callers who need the severity slice without re-running can read
// the aggregate counts from `sbom.Metadata.Properties`.
func (e *Enricher) Findings(ctx context.Context, sbom *model.SBOM) []policy.Finding {
	out := make([]policy.Finding, 0, 16)
	for _, v := range e.validators {
		findings, err := v.Validate(ctx, sbom)
		if err != nil {
			continue
		}
		out = append(out, findings...)
	}
	return out
}
