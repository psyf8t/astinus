package compliance

import (
	"context"
	"fmt"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// SPDXStructuralValidator checks the canonical model for the
// fields SPDX 2.3 marks as required.
//
// What's checked (per SPDX 2.3 spec §6 + §7):
//
//   - Document-level: at least one Component is present (an SPDX
//     document with no packages is technically valid but
//     operationally useless).
//   - Per-Component / per-Package: `name` is required;
//     `downloadLocation` is required (we proxy it via PURL
//     presence — SPDX writers fall back to NOASSERTION when PURL
//     is empty, which is valid but penalised).
//   - License: SPDX requires `licenseConcluded` and
//     `licenseDeclared` per package; we surface a low-severity
//     finding when the canonical model has zero License entries
//     for a Component. SPDX writers default empty to NOASSERTION,
//     so this is operator-quality, not a hard schema break.
//
// What's NOT checked:
//
//   - SPDX-ID format / uniqueness (the SPDX writer assigns these
//     deterministically; the canonical model doesn't expose them
//     pre-render).
//   - Document-level metadata (DocumentName, SPDXVersion,
//     dataLicense) — Astinus's SPDX writer always populates these
//     correctly; not a real failure mode.
//   - Snippets, ExternalDocumentRefs, OtherLicenses — Astinus
//     doesn't model them.
type SPDXStructuralValidator struct{}

// NewSPDXStructural returns a fresh validator.
func NewSPDXStructural() *SPDXStructuralValidator {
	return &SPDXStructuralValidator{}
}

// Name implements policy.Validator.
func (*SPDXStructuralValidator) Name() string { return "spdx-structural" }

// Description implements policy.Validator.
func (*SPDXStructuralValidator) Description() string {
	return "SPDX 2.3 required-field structural checks (no full schema validation)"
}

// Validate implements policy.Validator.
func (v *SPDXStructuralValidator) Validate(_ context.Context, sbom *model.SBOM) ([]policy.Finding, error) {
	if sbom == nil {
		return nil, nil
	}
	out := make([]policy.Finding, 0, 4)
	if len(sbom.Components) == 0 {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityHigh,
			RuleID:    "SPDX-EMPTY-PACKAGES",
			Message:   "SPDX document has no packages",
			Reference: "SPDX 2.3 §7",
		})
	}
	out = appendSPDXComponentFindings(out, sbom.Components)
	return out, nil
}

func appendSPDXComponentFindings(out []policy.Finding, comps []model.Component) []policy.Finding {
	for i := range comps {
		c := &comps[i]
		if c.Name == "" {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityCritical,
				RuleID:    "SPDX-PACKAGE-NAME-MISSING",
				Component: c.BOMRef,
				Message:   "SPDX package lacks required `name`",
				Reference: "SPDX 2.3 §7.1",
			})
		}
		if c.PURL == "" {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityLow,
				RuleID:    "SPDX-DOWNLOAD-LOCATION-NOASSERTION",
				Component: c.BOMRef,
				Message:   fmt.Sprintf("Component %q has no PURL — SPDX downloadLocation defaults to NOASSERTION", componentLabel(c)),
				Reference: "SPDX 2.3 §7.7",
			})
		}
		if len(c.Licenses) == 0 {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityLow,
				RuleID:    "SPDX-LICENSE-NOASSERTION",
				Component: c.BOMRef,
				Message:   fmt.Sprintf("Component %q has no license metadata — SPDX licenseConcluded defaults to NOASSERTION", componentLabel(c)),
				Reference: "SPDX 2.3 §7.13",
			})
		}
		if len(c.SubComponents) > 0 {
			out = appendSPDXComponentFindings(out, c.SubComponents)
		}
	}
	return out
}
