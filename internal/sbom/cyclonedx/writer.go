package cyclonedx

import (
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// WriteOptions configures the cyclonedx writer.
type WriteOptions struct {
	// Pretty toggles indented JSON / XML output.
	Pretty bool
	// SpecVersion overrides SpecVersionPrimary. Zero value means default.
	SpecVersion cdx.SpecVersion
}

// WriteJSON serializes sbom as CycloneDX JSON to w.
func WriteJSON(w io.Writer, sbom *model.SBOM, opts WriteOptions) error {
	return write(w, sbom, cdx.BOMFileFormatJSON, opts)
}

// WriteXML serializes sbom as CycloneDX XML to w.
func WriteXML(w io.Writer, sbom *model.SBOM, opts WriteOptions) error {
	return write(w, sbom, cdx.BOMFileFormatXML, opts)
}

func write(w io.Writer, sbom *model.SBOM, fileFormat cdx.BOMFileFormat, opts WriteOptions) error {
	if sbom == nil {
		return fmt.Errorf("cyclonedx: nil sbom")
	}
	bom := toCDX(sbom)

	specVersion := opts.SpecVersion
	if specVersion == 0 {
		specVersion = SpecVersionPrimary
	}
	bom.SpecVersion = specVersion

	enc := cdx.NewBOMEncoder(w, fileFormat).SetPretty(opts.Pretty).SetEscapeHTML(false)
	if err := enc.Encode(bom); err != nil {
		return fmt.Errorf("cyclonedx: encode: %w", err)
	}
	return nil
}
