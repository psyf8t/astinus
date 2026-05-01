package cyclonedx

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ErrEmptyInput is returned by Read* when the input has no bytes.
var ErrEmptyInput = errors.New("cyclonedx: empty input")

// ReadJSON parses a CycloneDX JSON SBOM from r into the canonical model.
func ReadJSON(r io.Reader) (*model.SBOM, error) {
	return read(r, cdx.BOMFileFormatJSON, model.FormatCycloneDXJSON)
}

// ReadXML parses a CycloneDX XML SBOM from r into the canonical model.
func ReadXML(r io.Reader) (*model.SBOM, error) {
	return read(r, cdx.BOMFileFormatXML, model.FormatCycloneDXXML)
}

// ReadBytes is the bytes-friendly counterpart of ReadJSON / ReadXML;
// the caller specifies the format explicitly.
func ReadBytes(body []byte, format model.Format) (*model.SBOM, error) {
	if len(body) == 0 {
		return nil, ErrEmptyInput
	}
	switch format {
	case model.FormatCycloneDXJSON:
		return ReadJSON(bytes.NewReader(body))
	case model.FormatCycloneDXXML:
		return ReadXML(bytes.NewReader(body))
	default:
		return nil, fmt.Errorf("cyclonedx: unsupported format %q", format)
	}
}

func read(r io.Reader, fileFormat cdx.BOMFileFormat, sourceFormat model.Format) (*model.SBOM, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cyclonedx: read input: %w", err)
	}
	if len(body) == 0 {
		return nil, ErrEmptyInput
	}

	bom := cdx.NewBOM()
	dec := cdx.NewBOMDecoder(bytes.NewReader(body), fileFormat)
	if err := dec.Decode(bom); err != nil {
		return nil, fmt.Errorf("cyclonedx: decode: %w", err)
	}
	return fromCDX(bom, body, sourceFormat), nil
}
