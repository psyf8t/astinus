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
	"strings"
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

// ErrUTF16NotSupported is returned when the input begins with a UTF-16
// byte-order mark. SBOM specs (CycloneDX 1.6, SPDX 2.3, SPDX 3.0) all
// mandate UTF-8; we surface a clear error rather than misclassify.
var ErrUTF16NotSupported = errors.New("sbom: UTF-16 input not supported (UTF-8 only)")

// utf8BOM is the byte sequence Windows tooling (Notepad, PowerShell,
// some Excel exports) prepends to JSON files. It is NOT Unicode
// whitespace, so a plain `bytes.TrimLeftFunc(body, unicode.IsSpace)`
// leaves it in place — the post-stage-13 review F-002 root cause.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// utf16LEBOM and utf16BEBOM are the little/big-endian UTF-16 markers.
var (
	utf16LEBOM = []byte{0xFF, 0xFE}
	utf16BEBOM = []byte{0xFE, 0xFF}
)

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
// ErrEmptyInput when body has no non-whitespace content,
// ErrUTF16NotSupported when the input is UTF-16 encoded; otherwise it
// returns FormatUnknown (and a nil error) when the shape doesn't match
// any known SBOM.
//
// A leading UTF-8 BOM (0xEF 0xBB 0xBF), commonly added by Windows
// tooling, is stripped before the shape check.
func DetectBytes(body []byte) (model.Format, error) {
	switch {
	case bytes.HasPrefix(body, utf16LEBOM), bytes.HasPrefix(body, utf16BEBOM):
		return model.FormatUnknown, ErrUTF16NotSupported
	case bytes.HasPrefix(body, utf8BOM):
		body = body[len(utf8BOM):]
	}

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
//
// Implementation note: the original Stage-1 version used
// `json.Unmarshal` on the peek window, which is NOT tolerant to
// truncation. Minified SBOMs from Syft 1.34+ (and many other
// producers) routinely exceed 64 KiB; truncating mid-array left
// the result struct empty even when the format-defining key was
// already in the consumed bytes. The streaming decoder below walks
// top-level keys one token at a time and returns the moment it
// sees `bomFormat: "CycloneDX"` or a non-empty `spdxVersion`, no
// matter where they appear in the object. See ADR-0016.
func detectJSON(body []byte) model.Format {
	// Limit how much we feed the decoder so a 200 MB attestation
	// doesn't melt before we even start parsing.
	limit := body
	if len(limit) > peekLimit {
		limit = limit[:peekLimit]
	}

	dec := json.NewDecoder(bytes.NewReader(limit))

	// Expect the opening '{'.
	tok, err := dec.Token()
	if err != nil {
		return model.FormatUnknown
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return model.FormatUnknown
	}

	// Walk top-level keys. Any io.ErrUnexpectedEOF / io.EOF from the
	// peek window cutoff is treated as "stop, return what we have".
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return model.FormatUnknown
		}
		key, ok := keyTok.(string)
		if !ok {
			return model.FormatUnknown
		}
		if format, done := classifyTopLevelKey(dec, key); done {
			return format
		}
	}

	return model.FormatUnknown
}

// classifyTopLevelKey reads the value for the given top-level key and
// reports the SBOM format if the key/value pair is a definitive marker.
// done=true means stop walking; format is the verdict (Unknown when the
// decoder errored). done=false means the key was not format-defining
// (or the value was inconclusive) — caller should keep walking.
func classifyTopLevelKey(dec *json.Decoder, key string) (model.Format, bool) {
	switch key {
	case "bomFormat":
		valTok, err := dec.Token()
		if err != nil {
			return model.FormatUnknown, true
		}
		if val, ok := valTok.(string); ok && strings.EqualFold(val, "CycloneDX") {
			return model.FormatCycloneDXJSON, true
		}
		// bomFormat present but not CycloneDX — keep walking in case
		// spdxVersion shows up later (defensive).
		return model.FormatUnknown, false

	case "spdxVersion":
		valTok, err := dec.Token()
		if err != nil {
			return model.FormatUnknown, true
		}
		if val, ok := valTok.(string); ok && val != "" {
			return model.FormatSPDXJSON, true
		}
		return model.FormatUnknown, false

	default:
		if err := skipJSONValue(dec); err != nil {
			return model.FormatUnknown, true
		}
		return model.FormatUnknown, false
	}
}

// skipJSONValue consumes one complete JSON value from dec, recursing
// into objects and arrays so the next dec.Token() returns the
// following key (in an object) or value (in an array).
//
// Behaviour:
//
//   - primitives (string / number / bool / null): one Token call,
//     return.
//   - objects: consume key/value pairs until the matching '}'.
//   - arrays: consume values until the matching ']'.
//
// Errors from dec.Token are returned verbatim; callers treat any
// error as "stop walking" because it usually means the peek window
// truncated the document mid-value.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// Primitive — already consumed.
		return nil
	}
	for dec.More() {
		// Inside an object the next token is a key — consume it
		// before recursing into its value.
		if delim == '{' {
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
		if err := skipJSONValue(dec); err != nil {
			return err
		}
	}
	// Consume the closing delim.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
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
