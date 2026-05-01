// Package sbom is the entry point for SBOM I/O.
//
// It hosts the format auto-detector here and re-exports the canonical
// model. Format-specific readers / writers live in subpackages
// (cyclonedx/, spdx/) that depend on internal/sbom/model.
package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"unicode"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// peekLimit is the maximum number of bytes Detect will consult when
// classifying a stream that might be large. Anything that does not
// disclose its format in the first 64 KiB is unreasonable for an SBOM.
const peekLimit = 64 * 1024

// ErrEmptyInput is returned by Detect when the input has no
// non-whitespace bytes.
var ErrEmptyInput = errors.New("sbom: empty input")

// Detect reads r in full, returns the detected format, and gives back
// the consumed bytes so the caller does not have to seek/replay r.
//
// Detection is best-effort and based only on shape (first non-space
// byte, top-level keys for JSON, root element for XML, leading
// "SPDXVersion:" line for tag-value). It deliberately does not validate
// schema — that's the parser's job.
func Detect(r io.Reader) (model.Format, []byte, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return model.FormatUnknown, body, fmt.Errorf("sbom: read input: %w", err)
	}
	format, err := DetectBytes(body)
	return format, body, err
}

// DetectBytes is Detect's pure-bytes counterpart. It reports
// ErrEmptyInput when body has no non-whitespace content; otherwise it
// returns FormatUnknown (and a nil error) when the shape doesn't match
// any known SBOM.
func DetectBytes(body []byte) (model.Format, error) {
	trimmed := bytes.TrimLeftFunc(body, unicode.IsSpace)
	if len(trimmed) == 0 {
		return model.FormatUnknown, ErrEmptyInput
	}

	switch trimmed[0] {
	case '{':
		return detectJSON(trimmed), nil
	case '<':
		return detectXML(trimmed), nil
	default:
		// SPDX tag-value documents must start with SPDXVersion: per
		// the spec.
		if bytes.HasPrefix(trimmed, []byte("SPDXVersion:")) {
			return model.FormatSPDXTagValue, nil
		}
		return model.FormatUnknown, nil
	}
}

// detectJSON inspects a JSON document — already trimmed to start at '{'
// — for the few well-known top-level keys that SBOM formats expose.
func detectJSON(body []byte) model.Format {
	// Limit how much we feed json.Decoder so a 200 MB attestation
	// doesn't melt before we even start parsing.
	limit := body
	if len(limit) > peekLimit {
		limit = limit[:peekLimit]
	}

	// Use a minimal struct so unknown fields are ignored cheaply.
	var head struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		SPDXVersion string `json:"spdxVersion"`
	}
	// Tolerate truncation in the peek window — any error other than
	// "no key found" still yields the conclusion drawn from whatever
	// the decoder did populate.
	_ = json.Unmarshal(limit, &head)

	switch {
	case bytes.EqualFold([]byte(head.BOMFormat), []byte("CycloneDX")):
		return model.FormatCycloneDXJSON
	case head.SPDXVersion != "":
		return model.FormatSPDXJSON
	default:
		return model.FormatUnknown
	}
}

// detectXML returns FormatCycloneDXXML when the root element is `bom`,
// otherwise FormatUnknown. SPDX has no XML serialization.
func detectXML(body []byte) model.Format {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return model.FormatUnknown
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name.Local == "bom" {
				return model.FormatCycloneDXXML
			}
			return model.FormatUnknown
		}
	}
}
