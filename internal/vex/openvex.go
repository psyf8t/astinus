package vex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// openVEXDoc is the subset of the OpenVEX schema Astinus consumes —
// header + statements list with vulnerability id + products + status
// + optional justification. Full schema:
// https://github.com/openvex/spec
type openVEXDoc struct {
	Context    string           `json:"@context"`
	ID         string           `json:"@id"`
	Author     string           `json:"author"`
	Timestamp  time.Time        `json:"timestamp"`
	Version    int              `json:"version"`
	Statements []openVEXStmtRaw `json:"statements"`
}

// openVEXStmtRaw decodes a single statement. The vulnerability + products
// fields are spec-permissive (objects OR strings), so we capture them
// as RawMessage and normalise via openVEXVulnRef / openVEXProductRef.
type openVEXStmtRaw struct {
	Vulnerability json.RawMessage   `json:"vulnerability"`
	Products      []json.RawMessage `json:"products"`
	Status        string            `json:"status"`
	Justification string            `json:"justification,omitempty"`
	Detail        string            `json:"impact_statement,omitempty"`
	ActionStmt    string            `json:"action_statement,omitempty"`
}

// openVEXVulnRef is the structured form of a `vulnerability` field —
// `{ "name": "CVE-..." }`. The bare string `"CVE-..."` shape is also
// permitted by the spec; readOpenVEXVulnID handles both.
type openVEXVulnRef struct {
	Name string `json:"name"`
	ID   string `json:"@id"`
}

// openVEXProductRef is the structured form of a `products[]` entry —
// `{ "@id": "pkg:..." }`. Bare-string `"pkg:..."` also permitted;
// readOpenVEXProductPURL handles both.
type openVEXProductRef struct {
	ID   string `json:"@id"`
	Name string `json:"name"`
}

// parseOpenVEXInto reads body as OpenVEX and appends its effects to
// store. The source path is recorded on every effect so downstream
// consumers can attribute a suppression to a specific file.
func parseOpenVEXInto(store *Store, body []byte, source string) error {
	var doc openVEXDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !strings.HasPrefix(doc.Context, "https://openvex.dev/ns/") {
		return fmt.Errorf("unrecognised @context %q (want https://openvex.dev/ns/...)", doc.Context)
	}
	for _, stmt := range doc.Statements {
		vulnID := readOpenVEXVulnID(stmt.Vulnerability)
		if vulnID == "" {
			continue
		}
		status := normaliseStatus(stmt.Status)
		if status == "" {
			continue
		}
		just := Justification(stmt.Justification)
		detail := stmt.Detail
		if detail == "" {
			detail = stmt.ActionStmt
		}
		for _, raw := range stmt.Products {
			purl := readOpenVEXProductPURL(raw)
			if purl == "" {
				continue
			}
			store.AddEffect(Effect{
				VulnID:        vulnID,
				ProductPURL:   purl,
				Status:        status,
				Justification: just,
				Detail:        detail,
				Source:        source,
			})
		}
	}
	return nil
}

// readOpenVEXVulnID accepts either the structured `{name, @id}`
// shape or a bare string. Prefers `name` over `@id` because the
// majority of public OpenVEX documents place the CVE there.
func readOpenVEXVulnID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		return asStr
	}
	var ref openVEXVulnRef
	if err := json.Unmarshal(raw, &ref); err == nil {
		if ref.Name != "" {
			return ref.Name
		}
		return ref.ID
	}
	return ""
}

// readOpenVEXProductPURL accepts either `{@id, name}` or a bare
// string. Prefers `@id` (the canonical PURL slot in OpenVEX 0.2).
func readOpenVEXProductPURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		return asStr
	}
	var ref openVEXProductRef
	if err := json.Unmarshal(raw, &ref); err == nil {
		if ref.ID != "" {
			return ref.ID
		}
		return ref.Name
	}
	return ""
}

// normaliseStatus maps the input status string to the Status enum.
// Unknown values return the zero string ("") so the caller drops
// the statement.
func normaliseStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "affected":
		return StatusAffected
	case "not_affected", "not-affected":
		return StatusNotAffected
	case "fixed":
		return StatusFixed
	case "under_investigation", "under-investigation":
		return StatusUnderInvestigation
	}
	return ""
}
