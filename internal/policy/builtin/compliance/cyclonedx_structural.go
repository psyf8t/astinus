package compliance

import (
	"context"
	"fmt"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// CycloneDXStructuralValidator checks the canonical model for the
// fields the CycloneDX 1.6 schema marks as "required" — the
// dominant cause of downstream-consumer rejection.
//
// What's checked (per the CycloneDX 1.6 schema):
//
//   - Top-level: at least one Component (an empty `components`
//     array is technically valid but operationally useless).
//   - Per-Component: `type` MUST be one of the recognised
//     CycloneDX componentTypes; `name` MUST be non-empty.
//   - Per-Component: `bom-ref` SHOULD be unique across the SBOM
//     (CycloneDX 1.6 ref-uniqueness rule).
//
// What's NOT checked (and the rationale):
//
//   - Schema-level field-format rules (URI shape, regex
//     patterns) — they are the failure modes downstream
//     consumers handle gracefully and a full JSONSchema
//     dependency is heavy. Documented in ADR-0025.
//   - Hash algorithm names against the schema's enum — the
//     model already constrains these via constants.
//   - Externally-referenced fields the model does not store
//     (snippets, custom extensions) — Astinus doesn't emit
//     them so there's nothing to check.
type CycloneDXStructuralValidator struct{}

// NewCycloneDXStructural returns a fresh validator.
func NewCycloneDXStructural() *CycloneDXStructuralValidator {
	return &CycloneDXStructuralValidator{}
}

// Name implements policy.Validator.
func (*CycloneDXStructuralValidator) Name() string { return "cyclonedx-structural" }

// Description implements policy.Validator.
func (*CycloneDXStructuralValidator) Description() string {
	return "CycloneDX 1.6 required-field structural checks (no full schema validation)"
}

// Validate implements policy.Validator.
func (v *CycloneDXStructuralValidator) Validate(_ context.Context, sbom *model.SBOM) ([]policy.Finding, error) {
	if sbom == nil {
		return nil, nil
	}
	out := make([]policy.Finding, 0, 4)
	out = appendCDXTopLevelFindings(out, sbom)
	out = appendCDXComponentFindings(out, sbom.Components)
	out = appendCDXBOMRefDuplicates(out, sbom.Components)
	return out, nil
}

func appendCDXTopLevelFindings(out []policy.Finding, sbom *model.SBOM) []policy.Finding {
	if len(sbom.Components) == 0 {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityHigh,
			RuleID:    "CDX-EMPTY-COMPONENTS",
			Message:   "CycloneDX SBOM has no components — useless to downstream consumers",
			Reference: "CycloneDX 1.6 schema $.components",
		})
	}
	return out
}

func appendCDXComponentFindings(out []policy.Finding, comps []model.Component) []policy.Finding {
	for i := range comps {
		c := &comps[i]
		if c.Name == "" {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityCritical,
				RuleID:    "CDX-COMPONENT-NAME-MISSING",
				Component: c.BOMRef,
				Message:   "Component lacks required `name`",
				Reference: "CycloneDX 1.6 schema $.components[].name",
			})
		}
		if !isRecognisedComponentType(c.Type) {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityHigh,
				RuleID:    "CDX-COMPONENT-TYPE-INVALID",
				Component: c.BOMRef,
				Message:   fmt.Sprintf("Component %q has unrecognised type %q", componentLabel(c), c.Type),
				Reference: "CycloneDX 1.6 schema $.components[].type",
			})
		}
		if len(c.SubComponents) > 0 {
			out = appendCDXComponentFindings(out, c.SubComponents)
		}
	}
	return out
}

// appendCDXBOMRefDuplicates flags Components that share a non-empty
// BOMRef. CycloneDX 1.6 requires `bom-ref` to be unique across the
// document; downstream consumers (Dependency-Track, Trivy) rely on
// this when resolving relationship pointers.
func appendCDXBOMRefDuplicates(out []policy.Finding, comps []model.Component) []policy.Finding {
	seen := make(map[string]struct{}, len(comps))
	walkAllComponents(comps, func(c *model.Component) {
		if c.BOMRef == "" {
			return
		}
		if _, dup := seen[c.BOMRef]; dup {
			out = append(out, policy.Finding{
				Severity:  policy.SeverityHigh,
				RuleID:    "CDX-BOMREF-DUPLICATE",
				Component: c.BOMRef,
				Message:   fmt.Sprintf("Duplicate bom-ref %q across components", c.BOMRef),
				Reference: "CycloneDX 1.6 schema bom-ref uniqueness",
			})
			return
		}
		seen[c.BOMRef] = struct{}{}
	})
	return out
}

// isRecognisedComponentType reports whether t is one of the
// canonical CycloneDX componentType strings (mirrored in
// internal/sbom/model/component.go).
func isRecognisedComponentType(t model.ComponentType) bool {
	switch t {
	case model.ComponentTypeApplication, model.ComponentTypeContainer,
		model.ComponentTypeDevice, model.ComponentTypeFile,
		model.ComponentTypeFirmware, model.ComponentTypeFramework,
		model.ComponentTypeLibrary, model.ComponentTypeOS,
		model.ComponentTypePlatform, model.ComponentTypeUnknown:
		return true
	default:
		// Empty type is a structural failure too — flagged as
		// invalid type rather than a separate rule.
		return false
	}
}
