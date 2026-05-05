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
	severity   *builtin.SeverityPolicy
}

// New returns the Enricher configured with the bundled defaults
// (NTIA, EU CRA, CycloneDX-structural, SPDX-structural) and the
// default per-ecosystem severity policy (S3 Task 2 / ADR-0031).
func New() *Enricher {
	return NewWithValidators(
		builtin.NewNTIA(),
		builtin.NewEUCRA(),
		builtin.NewCycloneDXStructural(),
		builtin.NewSPDXStructural(),
	)
}

// NewWithValidators returns an Enricher with the supplied
// validator chain and the default severity policy.
func NewWithValidators(validators ...policy.Validator) *Enricher {
	return &Enricher{
		validators: append([]policy.Validator(nil), validators...),
		severity:   builtin.DefaultSeverityPolicy(),
	}
}

// WithSeverityPolicy overrides the per-ecosystem severity policy.
// Used by `--compliance-config` to apply YAML-loaded overrides.
func (e *Enricher) WithSeverityPolicy(p *builtin.SeverityPolicy) *Enricher {
	if p != nil {
		e.severity = p
	}
	return e
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

	raw := make([]policy.Finding, 0, 16)
	type validatorRun struct {
		findings []policy.Finding
		errored  bool
	}
	runs := make(map[string]validatorRun, len(e.validators))

	for _, v := range e.validators {
		findings, err := v.Validate(ctx, sbom)
		if err != nil {
			logger.Warn("compliance.validator.error",
				"validator", v.Name(),
				"err", err.Error())
			runs[v.Name()] = validatorRun{errored: true}
			continue
		}
		runs[v.Name()] = validatorRun{findings: findings}
		raw = append(raw, findings...)
	}

	// Apply per-ecosystem severity policy: each finding's severity
	// is recomputed based on the rule that fired and the Component
	// it names. SeverityIgnored findings are dropped entirely
	// (not stamped, not counted) so the SBOM stays clean of
	// type=file noise. ADR-0031.
	allFindings, ignoredCount := e.applyPolicy(sbom, raw)

	statuses := make(map[string]string, len(runs))
	for name, r := range runs {
		if r.errored {
			statuses[name] = "errored"
			continue
		}
		statuses[name] = statusFor(applyPolicyToValidatorSlice(e.severity, sbom, r.findings))
	}

	stampMetadata(sbom, statuses, allFindings)
	stampPerComponent(sbom, allFindings)

	logger.Info("compliance.complete",
		"validators", len(e.validators),
		"findings_total", len(allFindings),
		"actionable", countActionable(allFindings),
		"critical", countSeverity(allFindings, policy.SeverityCritical),
		"high", countSeverity(allFindings, policy.SeverityHigh),
		"medium", countSeverity(allFindings, policy.SeverityMedium),
		"low", countSeverity(allFindings, policy.SeverityLow),
		"info", countSeverity(allFindings, policy.SeverityInfo),
		"ignored_dropped", ignoredCount,
	)
	return nil
}

// applyPolicy walks raw, looks each finding up in the SeverityPolicy,
// adjusts its Severity (only when a rule matched), and drops anything
// that resolves to SeverityIgnored. Returns the surviving findings +
// the count of ignored entries (for the `compliance.complete` log).
//
// Findings whose RuleID has no policy rule keep their validator-
// emitted severity so custom validators with bespoke rules continue
// to work.
func (e *Enricher) applyPolicy(sbom *model.SBOM, raw []policy.Finding) ([]policy.Finding, int) {
	if e.severity == nil {
		return raw, 0
	}
	out := make([]policy.Finding, 0, len(raw))
	ignored := 0
	for _, f := range raw {
		c := componentForFinding(sbom, f)
		sev, _, matched := e.severity.Severity(f.RuleID, c)
		if matched && sev == policy.SeverityIgnored {
			ignored++
			continue
		}
		if matched {
			f.Severity = sev
		}
		out = append(out, f)
	}
	return out, ignored
}

// applyPolicyToValidatorSlice is the per-validator equivalent of
// applyPolicy used by the status-aggregation step. The status
// reflects the post-policy severities so a validator whose findings
// are all SeverityInfo after policy reads as `passed-with-warnings`,
// not `failed`. Unmatched RuleIDs preserve their original severity.
func applyPolicyToValidatorSlice(p *builtin.SeverityPolicy, sbom *model.SBOM, findings []policy.Finding) []policy.Finding {
	if p == nil {
		return findings
	}
	out := make([]policy.Finding, 0, len(findings))
	for _, f := range findings {
		c := componentForFinding(sbom, f)
		sev, _, matched := p.Severity(f.RuleID, c)
		if matched && sev == policy.SeverityIgnored {
			continue
		}
		if matched {
			f.Severity = sev
		}
		out = append(out, f)
	}
	return out
}

// componentForFinding returns the Component the finding names, or
// nil for SBOM-level findings (no Component reference).
func componentForFinding(sbom *model.SBOM, f policy.Finding) *model.Component {
	if f.Component == "" {
		return nil
	}
	return findComponentByBOMRef(sbom.Components, f.Component)
}

// countActionable counts findings at severity medium or higher —
// the set security teams want to triage first. Info / low are
// transparency / hygiene categories and do not count as actionable.
func countActionable(findings []policy.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Severity.AtLeast(policy.SeverityMedium) {
			n++
		}
	}
	return n
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
	sbom.Metadata.Properties[model.PropertyComplianceActionableCount] =
		strconv.Itoa(countActionable(all))
	sbom.Metadata.Properties[model.PropertyComplianceCriticalCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityCritical))
	sbom.Metadata.Properties[model.PropertyComplianceHighCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityHigh))
	sbom.Metadata.Properties[model.PropertyComplianceMediumCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityMedium))
	sbom.Metadata.Properties[model.PropertyComplianceLowCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityLow))
	sbom.Metadata.Properties[model.PropertyComplianceInfoCount] =
		strconv.Itoa(countSeverity(all, policy.SeverityInfo))
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
// re-running every validator and applying the SeverityPolicy. Used
// by the CLI's `--fail-on` gate after Enrich has finished — the
// gate needs post-policy severities so an operator running
// `--fail-on medium` doesn't trip on a finding the policy
// downgraded to info.
//
// Calling Findings repeatedly is safe (validators are idempotent
// and the policy is pure); callers who need the severity slice
// without re-running can read the aggregate counts from
// `sbom.Metadata.Properties`.
func (e *Enricher) Findings(ctx context.Context, sbom *model.SBOM) []policy.Finding {
	raw := make([]policy.Finding, 0, 16)
	for _, v := range e.validators {
		findings, err := v.Validate(ctx, sbom)
		if err != nil {
			continue
		}
		raw = append(raw, findings...)
	}
	out, _ := e.applyPolicy(sbom, raw)
	return out
}
