package spdx

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"

	sbompkg "github.com/psyf8t/astinus/internal/sbom"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// ErrEmptyInput is returned by Read* when the input is empty.
var ErrEmptyInput = errors.New("spdx: empty input")

// ReadJSON parses an SPDX 2.x JSON document into the canonical model.
func ReadJSON(r io.Reader) (*model.SBOM, error) {
	body, err := sbompkg.ReadAllCapped(r)
	if err != nil {
		return nil, fmt.Errorf("spdx: read input: %w", err)
	}
	return ReadBytes(body, model.FormatSPDXJSON)
}

// ReadTagValue parses an SPDX 2.x tag-value document.
func ReadTagValue(r io.Reader) (*model.SBOM, error) {
	body, err := sbompkg.ReadAllCapped(r)
	if err != nil {
		return nil, fmt.Errorf("spdx: read input: %w", err)
	}
	return ReadBytes(body, model.FormatSPDXTagValue)
}

// ReadBytes is the bytes-friendly counterpart of ReadJSON / ReadTagValue.
func ReadBytes(body []byte, format model.Format) (*model.SBOM, error) {
	if len(body) == 0 {
		return nil, ErrEmptyInput
	}

	var (
		doc *spdx.Document
		err error
	)
	switch format {
	case model.FormatSPDXJSON:
		doc, err = spdxjson.Read(bytes.NewReader(body))
	case model.FormatSPDXTagValue:
		doc, err = tagvalue.Read(bytes.NewReader(body))
	default:
		return nil, fmt.Errorf("spdx: unsupported format %q", format)
	}
	if err != nil {
		return nil, fmt.Errorf("spdx: decode: %w", err)
	}
	return fromSPDX(asV23(doc), body, format), nil
}

// asV23 ensures we operate on the v2.3 type even when the loader
// returned an older revision (we support consuming 2.1/2.2 inputs
// transparently — tools-golang's Read does the conversion).
//
// In tools-golang v0.5.7, spdx.Document is a type alias of
// v2_3.Document for the "current" version, so this is a noop today.
func asV23(d *spdx.Document) *v23.Document { return d }
