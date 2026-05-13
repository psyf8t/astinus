package vex

import (
	"encoding/json"
	"strings"
)

// Format identifies the VEX document shape recognised by content
// inspection (no file-extension matching — operators routinely
// save VEX as `.json` either way). S6 Task 6.
type Format int

// Recognised VEX document formats. FormatUnknown is the zero value
// returned for anything that isn't a JSON object or doesn't match
// a known shape.
const (
	FormatUnknown Format = iota
	FormatOpenVEX
	FormatCDXVEX
)

// String renders the format as a stable identifier for log lines
// and diagnostic output.
func (f Format) String() string {
	switch f {
	case FormatOpenVEX:
		return "openvex"
	case FormatCDXVEX:
		return "cyclonedx-vex"
	default:
		return "unknown"
	}
}

// detectShape is the minimal JSON shape we sniff for format
// detection — both @context (OpenVEX) and bomFormat (CycloneDX)
// in one decode pass.
type detectShape struct {
	Context     string          `json:"@context"`
	BomFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Vulns       json.RawMessage `json:"vulnerabilities,omitempty"`
}

// DetectFormat inspects the document body and returns the matching
// Format. Returns FormatUnknown for any input that isn't a JSON
// object or doesn't match a known shape. The caller is expected
// to map FormatUnknown to a meaningful operator error.
func DetectFormat(body []byte) Format {
	var d detectShape
	if err := json.Unmarshal(body, &d); err != nil {
		return FormatUnknown
	}
	if strings.HasPrefix(d.Context, "https://openvex.dev/ns/") {
		return FormatOpenVEX
	}
	if strings.EqualFold(d.BomFormat, "CycloneDX") && len(d.Vulns) > 0 {
		return FormatCDXVEX
	}
	return FormatUnknown
}
