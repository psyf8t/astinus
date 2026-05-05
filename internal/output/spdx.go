package output

import (
	"io"

	"github.com/psyf8t/astinus/internal/sbom/model"
	"github.com/psyf8t/astinus/internal/sbom/spdx"
)

// FormatSPDXJSON is the CLI name for the JSON SPDX 2.3 renderer.
const FormatSPDXJSON = "spdx-json"

// FormatSPDXTagValue is the CLI name for the tag-value SPDX 2.3 renderer.
const FormatSPDXTagValue = "spdx-tag-value"

func init() {
	RegisterFormat(FormatSPDXJSON, func(o Options) Renderer {
		return &spdxJSONRenderer{pretty: o.Pretty}
	})
	RegisterFormat(FormatSPDXTagValue, func(_ Options) Renderer {
		return &spdxTagValueRenderer{}
	})
}

type spdxJSONRenderer struct {
	pretty bool
}

func (r *spdxJSONRenderer) Name() string     { return FormatSPDXJSON }
func (r *spdxJSONRenderer) MIMEType() string { return "application/spdx+json" }
func (r *spdxJSONRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	return spdx.WriteJSON(w, sbom, spdx.WriteOptions{Pretty: r.pretty})
}

type spdxTagValueRenderer struct{}

func (r *spdxTagValueRenderer) Name() string     { return FormatSPDXTagValue }
func (r *spdxTagValueRenderer) MIMEType() string { return "text/spdx" }
func (r *spdxTagValueRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	return spdx.WriteTagValue(w, sbom, spdx.WriteOptions{})
}
