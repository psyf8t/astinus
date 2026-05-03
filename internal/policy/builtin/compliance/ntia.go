package compliance

import (
	"context"
	"fmt"

	"github.com/psyf8t/astinus/internal/policy"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// NTIAValidator implements the NTIA Minimum Elements for an SBOM
// (US Executive Order 14028, NTIA report 2021-07-12).
//
// Seven elements per the report:
//
//  1. Supplier Name
//  2. Component Name
//  3. Component Version
//  4. Other Unique Identifiers (PURL / CPE / SWID — Astinus checks
//     PURL or any non-empty CPE; SWID is not modelled).
//  5. Dependency Relationship
//  6. Author of SBOM Data
//  7. Timestamp
//
// Element severity mapping:
//
//   - missing Component Name           → critical (structural)
//   - missing Component Version        → high
//   - missing Supplier (and Author)    → medium
//   - missing Identifier               → medium
//   - missing SBOM Author              → high
//   - missing SBOM Timestamp           → high
//   - large SBOM with no Relationships → medium
//
// `type=file` Components are skipped — NTIA's element list is
// scoped to dependency Components, not file-system entries the
// untracked walker may have produced as `file` rows for forensic
// purposes.
type NTIAValidator struct{}

// NewNTIA returns a fresh NTIAValidator. Stateless; safe for
// concurrent reuse.
func NewNTIA() *NTIAValidator { return &NTIAValidator{} }

// Name implements policy.Validator.
func (*NTIAValidator) Name() string { return "ntia-minimum-elements" }

// Description implements policy.Validator.
func (*NTIAValidator) Description() string {
	return "NTIA Minimum Elements for an SBOM (US Executive Order 14028)"
}

// Validate implements policy.Validator.
func (v *NTIAValidator) Validate(_ context.Context, sbom *model.SBOM) ([]policy.Finding, error) {
	if sbom == nil {
		return nil, nil
	}
	out := make([]policy.Finding, 0, 8)
	out = appendMetadataFindings(out, sbom)
	out = appendComponentFindings(out, sbom.Components)
	out = appendRelationshipFinding(out, sbom)
	return out, nil
}

// appendMetadataFindings checks SBOM-level NTIA elements
// (Author + Timestamp). Element 6 + Element 7.
func appendMetadataFindings(out []policy.Finding, sbom *model.SBOM) []policy.Finding {
	if !hasSBOMAuthor(sbom.Metadata) {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityHigh,
			RuleID:    "NTIA-METADATA-AUTHOR",
			Message:   "SBOM lacks author metadata",
			Reference: "NTIA Minimum Element 6: Author of SBOM Data",
		})
	}
	if sbom.Metadata.Timestamp.IsZero() {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityHigh,
			RuleID:    "NTIA-METADATA-TIMESTAMP",
			Message:   "SBOM lacks timestamp",
			Reference: "NTIA Minimum Element 7: Timestamp",
		})
	}
	return out
}

// appendComponentFindings walks every Component (and its
// SubComponents) and checks the per-component elements.
func appendComponentFindings(out []policy.Finding, comps []model.Component) []policy.Finding {
	for i := range comps {
		c := &comps[i]
		if c.Type == model.ComponentTypeFile {
			continue
		}
		out = checkComponent(out, c)
		if len(c.SubComponents) > 0 {
			out = appendComponentFindings(out, c.SubComponents)
		}
	}
	return out
}

// checkComponent enforces elements 1–4 on one Component.
func checkComponent(out []policy.Finding, c *model.Component) []policy.Finding {
	if c.Name == "" {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityCritical,
			RuleID:    "NTIA-NAME",
			Component: c.BOMRef,
			Message:   "Component lacks name",
			Reference: "NTIA Minimum Element 2: Component Name",
		})
	}
	if c.Version == "" {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityHigh,
			RuleID:    "NTIA-VERSION",
			Component: c.BOMRef,
			Message:   fmt.Sprintf("Component %q lacks version", componentLabel(c)),
			Reference: "NTIA Minimum Element 3: Component Version",
		})
	}
	if c.Supplier == "" && c.Author == "" {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityMedium,
			RuleID:    "NTIA-SUPPLIER",
			Component: c.BOMRef,
			Message:   fmt.Sprintf("Component %q lacks supplier and author", componentLabel(c)),
			Reference: "NTIA Minimum Element 1: Supplier Name",
		})
	}
	if c.PURL == "" && len(c.CPEs) == 0 {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityMedium,
			RuleID:    "NTIA-IDENTIFIER",
			Component: c.BOMRef,
			Message:   fmt.Sprintf("Component %q has no unique identifier (PURL/CPE)", componentLabel(c)),
			Reference: "NTIA Minimum Element 4: Other Unique Identifiers",
		})
	}
	return out
}

// appendRelationshipFinding emits a single SBOM-level finding when a
// large component set has no recorded dependency relationships. A
// 1-component SBOM legitimately has no relationships; a
// 100-component SBOM almost certainly does in real packaging.
//
// The threshold (10) is intentionally lenient — the goal is to
// flag the "we forgot to record any" failure mode, not to second-
// guess every operator's relationship policy.
func appendRelationshipFinding(out []policy.Finding, sbom *model.SBOM) []policy.Finding {
	if len(sbom.Components) >= 10 && len(sbom.Relationships) == 0 {
		out = append(out, policy.Finding{
			Severity:  policy.SeverityMedium,
			RuleID:    "NTIA-RELATIONSHIPS",
			Message:   fmt.Sprintf("SBOM has %d components but no recorded relationships", len(sbom.Components)),
			Reference: "NTIA Minimum Element 5: Dependency Relationship",
		})
	}
	return out
}

// hasSBOMAuthor reports whether the metadata records at least one
// authoring source — either an explicit Author or any Tool entry
// (Astinus stamps itself + downstream tools as Tools, so this is
// the typical happy path).
func hasSBOMAuthor(m model.Metadata) bool {
	if len(m.Authors) > 0 {
		return true
	}
	for _, t := range m.Tools {
		if t.Name != "" {
			return true
		}
	}
	return false
}

// componentLabel returns a human-readable label for finding
// messages. Falls back to BOMRef when Name is empty (which itself
// would have triggered the NAME finding).
func componentLabel(c *model.Component) string {
	if c.Name != "" {
		return c.Name
	}
	if c.BOMRef != "" {
		return c.BOMRef
	}
	return "<unnamed>"
}
