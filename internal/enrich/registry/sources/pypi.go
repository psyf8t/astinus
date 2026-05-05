package sources

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// pypiUpstream is the public pypi.org JSON API base. PyPI's JSON
// API returns the per-package metadata; per-version is at
// `/pypi/<name>/<version>/json`.
const pypiUpstream = "https://pypi.org/pypi"

// PyPI fetches metadata from pypi.org JSON API or operator-supplied
// mirrors (devpi, Artifactory PyPI, Nexus PyPI). The JSON API
// schema documented at https://warehouse.pypa.io/api-reference/json.html
type PyPI struct {
	mirrors  []config.MirrorEntry
	client   *http.Client
	logger   *slog.Logger
	upstream string
}

// NewPyPI returns a PyPI Source.
func NewPyPI(mirrors []config.MirrorEntry, client *http.Client) *PyPI {
	if client == nil {
		client = registry.DefaultClient()
	}
	return &PyPI{
		mirrors:  mirrors,
		client:   client,
		logger:   slog.Default(),
		upstream: pypiUpstream,
	}
}

// WithUpstream overrides the pypi.org base URL. Test-only.
func (p *PyPI) WithUpstream(u string) *PyPI {
	p.upstream = u
	return p
}

// WithLogger overrides the slog destination.
func (p *PyPI) WithLogger(l *slog.Logger) *PyPI {
	if l != nil {
		p.logger = l
	}
	return p
}

// Name implements registry.Source.
func (*PyPI) Name() string { return "pypi" }

// Supports implements registry.Source.
func (*PyPI) Supports(t string) bool { return strings.EqualFold(t, "pypi") }

// RequiresNetwork implements registry.Source.
func (*PyPI) RequiresNetwork() bool { return true }

// Fetch implements registry.Source.
func (p *PyPI) Fetch(ctx context.Context, purl cpe.PURL) (*registry.Metadata, error) {
	if purl.Name == "" {
		return nil, registry.ErrUnsupported
	}
	chain := registry.MirrorChain{Mirrors: p.mirrors, Upstream: p.upstream}

	pathSuffix := "/" + purl.Name
	if purl.Version != "" {
		pathSuffix += "/" + purl.Version
	}
	pathSuffix += "/json"

	var raw pypiResponse
	parser := func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&raw)
	}
	if err := registry.FetchJSON(ctx, p.client, chain, pathSuffix, p.Name(), parser, p.logger); err != nil {
		return nil, err
	}
	meta := convertPyPIMetadata(&raw, purl)
	if meta.IsEmpty() {
		return nil, registry.ErrNotFound
	}
	return meta, nil
}

// pypiResponse is the subset of the PyPI JSON API response we
// consume. The full schema is large; we read the `info` block
// (per-version) and the `releases` distribution table for hashes.
type pypiResponse struct {
	Info struct {
		Name             string         `json:"name"`
		Version          string         `json:"version"`
		Summary          string         `json:"summary"`
		Description      string         `json:"description"`
		HomePage         string         `json:"home_page"`
		ProjectURL       string         `json:"project_url"`
		ProjectURLs      map[string]any `json:"project_urls"`
		Author           string         `json:"author"`
		AuthorEmail      string         `json:"author_email"`
		Maintainer       string         `json:"maintainer"`
		MaintainerEmail  string         `json:"maintainer_email"`
		License          string         `json:"license"`
		LicenseExpr      string         `json:"license_expression"`
		Keywords         string         `json:"keywords"`
		Classifiers      []string       `json:"classifiers"`
		BugTrackerURL    string         `json:"bugtrack_url"`
		DocumentationURL string         `json:"docs_url"`
	} `json:"info"`
	URLs []struct {
		Filename string            `json:"filename"`
		Digests  map[string]string `json:"digests"`
	} `json:"urls"`
}

// convertPyPIMetadata projects a parsed PyPI response onto the
// registry.Metadata shape.
func convertPyPIMetadata(raw *pypiResponse, purl cpe.PURL) *registry.Metadata {
	out := &registry.Metadata{
		Name:        raw.Info.Name,
		Version:     raw.Info.Version,
		Description: pypiDescription(raw),
	}
	if license := pypiLicense(raw); len(license) > 0 {
		out.Licenses = license
	}
	if raw.Info.Author != "" {
		out.Author = raw.Info.Author
		out.Supplier.Name = raw.Info.Author
		out.Supplier.Email = raw.Info.AuthorEmail
	} else if raw.Info.Maintainer != "" {
		out.Author = raw.Info.Maintainer
		out.Supplier.Name = raw.Info.Maintainer
		out.Supplier.Email = raw.Info.MaintainerEmail
	}
	out.Homepage = raw.Info.HomePage
	if out.Homepage == "" && raw.Info.ProjectURL != "" {
		out.Homepage = raw.Info.ProjectURL
	}
	out.Repository = pypiRepository(raw.Info.ProjectURLs)
	if raw.Info.BugTrackerURL != "" {
		out.BugTracker = raw.Info.BugTrackerURL
	} else {
		out.BugTracker = pypiURLByLabel(raw.Info.ProjectURLs, "issues", "bug", "tracker")
	}
	out.Documentation = raw.Info.DocumentationURL
	if out.Documentation == "" {
		out.Documentation = pypiURLByLabel(raw.Info.ProjectURLs, "docs", "documentation")
	}
	if raw.Info.Keywords != "" {
		for _, k := range strings.Split(raw.Info.Keywords, ",") {
			if k = strings.TrimSpace(k); k != "" {
				out.Keywords = append(out.Keywords, k)
			}
		}
	}
	if hashes := pypiHashes(raw, purl.Version); len(hashes) > 0 {
		out.Hashes = hashes
	}
	return out
}

// pypiDescription prefers `summary` (single line) over `description`
// (potentially multi-page README).
func pypiDescription(raw *pypiResponse) string {
	if raw.Info.Summary != "" {
		return raw.Info.Summary
	}
	if raw.Info.Description != "" {
		return raw.Info.Description
	}
	return ""
}

// pypiLicense reads the modern `license_expression` field first
// (PEP 639), then falls back to the legacy `license` text.
// Classifiers like "License :: OSI Approved :: MIT License" are
// secondary signals when both fields are empty.
func pypiLicense(raw *pypiResponse) []registry.License {
	if raw.Info.LicenseExpr != "" {
		return licenseFromString(raw.Info.LicenseExpr)
	}
	if raw.Info.License != "" {
		return licenseFromString(raw.Info.License)
	}
	for _, c := range raw.Info.Classifiers {
		if id := licenseFromClassifier(c); id != "" {
			return []registry.License{{SPDXID: id, Name: id}}
		}
	}
	return nil
}

// licenseFromClassifier maps a few common PyPI classifiers to SPDX
// ids. Conservative — only the unambiguous cases. Unmapped
// classifiers fall through to "no license".
func licenseFromClassifier(c string) string {
	switch c {
	case "License :: OSI Approved :: MIT License":
		return "MIT"
	case "License :: OSI Approved :: Apache Software License":
		return "Apache-2.0"
	case "License :: OSI Approved :: BSD License":
		return "BSD-3-Clause"
	case "License :: OSI Approved :: GNU General Public License v2 (GPLv2)":
		return "GPL-2.0-only"
	case "License :: OSI Approved :: GNU General Public License v3 (GPLv3)":
		return "GPL-3.0-only"
	case "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":
		return "LGPL-3.0-only"
	case "License :: OSI Approved :: ISC License (ISCL)":
		return "ISC"
	case "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":
		return "MPL-2.0"
	}
	return ""
}

// pypiRepository pulls the VCS URL from `project_urls` honouring
// the conventional labels.
func pypiRepository(urls map[string]any) string {
	for _, label := range []string{"Source", "Source Code", "Repository", "GitHub", "Code"} {
		if v, ok := urls[label].(string); ok && v != "" {
			return cleanVCSURL(v)
		}
	}
	return ""
}

// pypiURLByLabel performs a case-insensitive prefix search on the
// project_urls labels, returning the first matching URL.
func pypiURLByLabel(urls map[string]any, prefixes ...string) string {
	for k, v := range urls {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		lower := strings.ToLower(k)
		for _, p := range prefixes {
			if strings.Contains(lower, strings.ToLower(p)) {
				return s
			}
		}
	}
	return ""
}

// pypiHashes pulls the digests for the version's distribution
// files. Keyed by algorithm; sha256 is preferred, sha512 / md5 are
// kept when present.
func pypiHashes(raw *pypiResponse, version string) map[string]string {
	_ = version // urls slice is already per-version when the per-version endpoint was used
	out := map[string]string{}
	for _, u := range raw.URLs {
		for alg, hex := range u.Digests {
			if hex == "" {
				continue
			}
			normalised := strings.ToLower(alg)
			if _, exists := out[normalised]; !exists {
				out[normalised] = hex
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
