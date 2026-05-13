package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cdxVEXDoc is the subset of the CycloneDX VEX schema Astinus
// consumes — top-level vulnerabilities[] with id + affects + analysis.
// Full schema: https://cyclonedx.org/docs/1.5/json/#vulnerabilities
//
// A normal CDX SBOM that ALSO carries vulnerabilities[] is read the
// same way; we ignore everything else.
type cdxVEXDoc struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxVulnerability struct {
	ID       string       `json:"id"`
	Affects  []cdxAffects `json:"affects"`
	Analysis cdxAnalysis  `json:"analysis"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// parseCDXVEXInto reads body as CycloneDX VEX and appends its
// effects to store. CycloneDX uses slightly different terminology
// from OpenVEX:
//
//   - `analysis.state` is the equivalent of OpenVEX `status`.
//   - `affects[].ref` carries a BOMRef OR a PURL string (the spec
//     permits both); we treat anything starting with `pkg:` as a
//     PURL directly. BOMRef-style refs are passed through as-is
//     and resolved against the operator's SBOM at suppression time
//     (today the Lookup is PURL-keyed; BOMRef-shape refs simply
//     never match a PURL — operators using BOMRef in VEX should
//     supplement with a PURL OR use OpenVEX, which keys on PURL
//     directly).
//   - `analysis.justification` uses a different vocabulary
//     (`code_not_present`, `code_not_reachable`, etc.) which we
//     normalise into the OpenVEX set via cdxJustificationMap.
func parseCDXVEXInto(store *Store, body []byte, source string) error {
	var doc cdxVEXDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !strings.EqualFold(doc.BomFormat, "CycloneDX") {
		return fmt.Errorf("missing/wrong bomFormat (%q)", doc.BomFormat)
	}
	for _, v := range doc.Vulnerabilities {
		if v.ID == "" {
			continue
		}
		status := normaliseStatus(v.Analysis.State)
		if status == "" {
			continue
		}
		just := cdxJustificationMap[strings.ToLower(strings.TrimSpace(v.Analysis.Justification))]
		for _, a := range v.Affects {
			ref := strings.TrimSpace(a.Ref)
			if ref == "" {
				continue
			}
			store.AddEffect(Effect{
				VulnID:        v.ID,
				ProductPURL:   ref,
				Status:        status,
				Justification: just,
				Detail:        v.Analysis.Detail,
				Source:        source,
			})
		}
	}
	return nil
}

// cdxJustificationMap translates the CycloneDX VEX justification
// vocabulary into OpenVEX's. Unknown values pass through as the
// empty Justification (the gate doesn't gate on justification,
// only on status, so this is operator-visible information only).
var cdxJustificationMap = map[string]Justification{
	"code_not_present":                JustVulnerableCodeNotPresent,
	"code_not_reachable":              JustVulnerableCodeNotInExecutePath,
	"requires_configuration":          JustVulnerableCodeNotInExecutePath,
	"requires_dependency":             JustVulnerableCodeNotPresent,
	"requires_environment":            JustVulnerableCodeNotInExecutePath,
	"protected_by_compiler":           JustInlineMitigationsAlreadyExist,
	"protected_at_runtime":            JustInlineMitigationsAlreadyExist,
	"protected_at_perimeter":          JustInlineMitigationsAlreadyExist,
	"protected_by_mitigating_control": JustInlineMitigationsAlreadyExist,
	"component_not_present":           JustComponentNotPresent,
}
