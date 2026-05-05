package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

func TestPyPI_Fetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/requests/2.31.0/json") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{
				"name":         "requests",
				"version":      "2.31.0",
				"summary":      "Python HTTP for Humans.",
				"license":      "Apache-2.0",
				"author":       "Kenneth Reitz",
				"author_email": "me@kennethreitz.org",
				"home_page":    "https://requests.readthedocs.io",
				"project_urls": map[string]any{
					"Source": "https://github.com/psf/requests",
					"Issues": "https://github.com/psf/requests/issues",
				},
				"keywords": "http, requests, https",
			},
			"urls": []map[string]any{
				{
					"filename": "requests-2.31.0.tar.gz",
					"digests": map[string]any{
						"sha256": "deadbeef",
					},
				},
			},
		})
	}))
	defer server.Close()

	p := NewPyPI(nil, server.Client()).WithUpstream(server.URL)
	meta, err := p.Fetch(context.Background(),
		cpe.PURL{Type: "pypi", Name: "requests", Version: "2.31.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta == nil || meta.Name != "requests" {
		t.Fatalf("meta = %+v", meta)
	}
	if len(meta.Licenses) != 1 || meta.Licenses[0].SPDXID != "Apache-2.0" {
		t.Errorf("licenses = %+v", meta.Licenses)
	}
	if meta.Author != "Kenneth Reitz" || meta.Supplier.Email != "me@kennethreitz.org" {
		t.Errorf("author/supplier wrong: %+v / %+v", meta.Author, meta.Supplier)
	}
	if meta.Repository != "https://github.com/psf/requests" {
		t.Errorf("repository = %q", meta.Repository)
	}
	if meta.BugTracker != "https://github.com/psf/requests/issues" {
		t.Errorf("bug tracker = %q", meta.BugTracker)
	}
	if meta.Homepage != "https://requests.readthedocs.io" {
		t.Errorf("homepage = %q", meta.Homepage)
	}
	if len(meta.Keywords) != 3 {
		t.Errorf("keywords = %v, want 3 entries", meta.Keywords)
	}
	if meta.Hashes["sha256"] != "deadbeef" {
		t.Errorf("hash missing: %v", meta.Hashes)
	}
}

func TestLicenseFromClassifier(t *testing.T) {
	cases := map[string]string{
		"License :: OSI Approved :: MIT License":             "MIT",
		"License :: OSI Approved :: Apache Software License": "Apache-2.0",
		"License :: OSI Approved :: ISC License (ISCL)":      "ISC",
		"License :: Other/Proprietary":                       "",
	}
	for in, want := range cases {
		if got := licenseFromClassifier(in); got != want {
			t.Errorf("classifier %q → %q, want %q", in, got, want)
		}
	}
}

func TestPyPI_FetchMissingNameUnsupported(t *testing.T) {
	p := NewPyPI(nil, nil)
	_, err := p.Fetch(context.Background(), cpe.PURL{Type: "pypi"})
	if err == nil {
		t.Error("expected error for missing name")
	}
}
