package spdx

import (
	"fmt"
	"io"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/tagvalue"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

// WriteOptions configures the SPDX writer.
type WriteOptions struct {
	// Pretty toggles indented JSON output. Ignored by tag-value.
	Pretty bool
}

// WriteJSON serialises sbom as SPDX 2.3 JSON to w.
func WriteJSON(w io.Writer, sbom *model.SBOM, opts WriteOptions) error {
	if sbom == nil {
		return fmt.Errorf("spdx: nil sbom")
	}
	doc := toSPDX(sbom)
	jsonOpts := []spdxjson.WriteOption{spdxjson.EscapeHTML(false)}
	if opts.Pretty {
		jsonOpts = append(jsonOpts, spdxjson.Indent("  "))
	}
	if err := spdxjson.Write(doc, w, jsonOpts...); err != nil {
		return fmt.Errorf("spdx: encode json: %w", err)
	}
	return nil
}

// WriteTagValue serialises sbom as SPDX 2.3 tag-value to w.
func WriteTagValue(w io.Writer, sbom *model.SBOM, _ WriteOptions) error {
	if sbom == nil {
		return fmt.Errorf("spdx: nil sbom")
	}
	doc := toSPDX(sbom)
	if err := tagvalue.Write(doc, w); err != nil {
		return fmt.Errorf("spdx: encode tag-value: %w", err)
	}
	return nil
}
