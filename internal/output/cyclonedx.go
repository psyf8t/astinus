package output

import (
	"io"

	"github.com/psyf8t/astinus/internal/sbom/cyclonedx"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// FormatCycloneDXJSON is the CLI name for the JSON CycloneDX renderer.
const FormatCycloneDXJSON = "cyclonedx-json"

// FormatCycloneDXXML is the CLI name for the XML CycloneDX renderer.
const FormatCycloneDXXML = "cyclonedx-xml"

func init() {
	RegisterFormat(FormatCycloneDXJSON, func(o Options) Renderer {
		return &cdxJSONRenderer{pretty: o.Pretty}
	})
	RegisterFormat(FormatCycloneDXXML, func(o Options) Renderer {
		return &cdxXMLRenderer{pretty: o.Pretty}
	})
}

type cdxJSONRenderer struct {
	pretty bool
}

func (r *cdxJSONRenderer) Name() string     { return FormatCycloneDXJSON }
func (r *cdxJSONRenderer) MIMEType() string { return "application/vnd.cyclonedx+json" }
func (r *cdxJSONRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	return cyclonedx.WriteJSON(w, sbom, cyclonedx.WriteOptions{Pretty: r.pretty})
}

type cdxXMLRenderer struct {
	pretty bool
}

func (r *cdxXMLRenderer) Name() string     { return FormatCycloneDXXML }
func (r *cdxXMLRenderer) MIMEType() string { return "application/vnd.cyclonedx+xml" }
func (r *cdxXMLRenderer) Render(w io.Writer, sbom *model.SBOM) error {
	return cyclonedx.WriteXML(w, sbom, cyclonedx.WriteOptions{Pretty: r.pretty})
}

// FormatSame is the sentinel value the CLI passes when the user
// wants the output format to mirror the input format. It is not
// itself a registered renderer; the CLI resolves it before calling
// Get().
const FormatSame = "same"

// ResolveSame translates FormatSame into a concrete renderer name
// based on the SBOM's source format. Falls back to cyclonedx-json
// when the source is unknown (e.g. canonical SBOM constructed in
// memory by tests).
func ResolveSame(srcFormat model.Format) string {
	switch srcFormat {
	case model.FormatCycloneDXJSON:
		return FormatCycloneDXJSON
	case model.FormatCycloneDXXML:
		return FormatCycloneDXXML
	case model.FormatSPDXJSON:
		return FormatSPDXJSON
	case model.FormatSPDXTagValue:
		return FormatSPDXTagValue
	default:
		return FormatCycloneDXJSON
	}
}
