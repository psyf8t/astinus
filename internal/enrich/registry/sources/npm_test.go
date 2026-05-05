package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// TestNPM_FetchUpstream — happy path: hit the upstream, decode the
// per-version response, project all the fields the converter knows
// how to handle.
func TestNPM_FetchUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/lodash/4.17.21") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":        "lodash",
			"version":     "4.17.21",
			"description": "Lodash modular utilities.",
			"license":     "MIT",
			"homepage":    "https://lodash.com/",
			"repository": map[string]string{
				"type": "git",
				"url":  "git+https://github.com/lodash/lodash.git",
			},
			"author": "John-David Dalton <john@example.com> (https://allyoucanleet.com/)",
			"dist": map[string]string{
				"shasum":    "abc123",
				"integrity": "sha512-" + base64Of("hello world"),
			},
		})
	}))
	defer server.Close()

	n := NewNPM(nil, server.Client()).WithUpstream(server.URL)
	meta, err := n.Fetch(context.Background(),
		cpe.PURL{Type: "npm", Name: "lodash", Version: "4.17.21"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta == nil || meta.Name != "lodash" {
		t.Fatalf("meta = %+v", meta)
	}
	if len(meta.Licenses) != 1 || meta.Licenses[0].SPDXID != "MIT" {
		t.Errorf("licenses = %+v", meta.Licenses)
	}
	if meta.Homepage != "https://lodash.com/" {
		t.Errorf("homepage = %q", meta.Homepage)
	}
	if meta.Repository != "https://github.com/lodash/lodash" {
		t.Errorf("repository = %q (want git+ stripped, .git stripped)", meta.Repository)
	}
	if meta.Author != "John-David Dalton" {
		t.Errorf("author = %q", meta.Author)
	}
	if meta.Supplier.Email != "john@example.com" {
		t.Errorf("supplier email = %q", meta.Supplier.Email)
	}
	if meta.Hashes["sha1"] != "abc123" {
		t.Errorf("sha1 hash missing: %v", meta.Hashes)
	}
}

// TestNormalizeNPMLicense_ManyShapes — npm's `license` field has
// existed in three shapes across the registry's history. The
// normaliser handles each, plus the special UNLICENSED marker that
// signals a private package (drop, not "license=UNLICENSED").
func TestNormalizeNPMLicense_ManyShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string // JSON literal for the license field
		want []string
	}{
		{"plain SPDX id", `"MIT"`, []string{"MIT"}},
		{"Apache 2.0", `"Apache-2.0"`, []string{"Apache-2.0"}},
		{"SPDX expression in parens", `"(MIT OR Apache-2.0)"`, []string{"MIT OR Apache-2.0"}},
		{"BSD 3-Clause", `"BSD-3-Clause"`, []string{"BSD-3-Clause"}},
		{"object form", `{"type":"MIT","url":"https://opensource.org/licenses/MIT"}`, []string{"MIT"}},
		{"UNLICENSED is dropped", `"UNLICENSED"`, nil},
		{"SEE LICENSE IN", `"SEE LICENSE IN LICENSE.txt"`, []string{"SEE LICENSE IN LICENSE.txt"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeNPMLicense(json.RawMessage(c.raw))
			if len(got) != len(c.want) {
				t.Fatalf("got %d licenses, want %d (%+v)", len(got), len(c.want), got)
			}
			for i := range c.want {
				switch {
				case got[i].SPDXID != "":
					if got[i].SPDXID != c.want[i] {
						t.Errorf("[%d] SPDXID = %q, want %q", i, got[i].SPDXID, c.want[i])
					}
				default:
					if got[i].Name != c.want[i] {
						t.Errorf("[%d] Name = %q, want %q", i, got[i].Name, c.want[i])
					}
				}
			}
		})
	}
}

// TestNormalizeNPMLicenses_LegacyArray exercises the deprecated
// `licenses[]` array shape that ancient npm packages (pre-2014)
// still carry.
func TestNormalizeNPMLicenses_LegacyArray(t *testing.T) {
	raw := json.RawMessage(`[
		{"type":"MIT","url":"https://example.com/mit"},
		{"type":"Apache-2.0"}
	]`)
	got := normalizeNPMLicenses(raw)
	if len(got) != 2 {
		t.Fatalf("got %d licenses, want 2", len(got))
	}
	if got[0].SPDXID != "MIT" || got[1].SPDXID != "Apache-2.0" {
		t.Errorf("licenses = %+v", got)
	}
}

func TestParseNPMAuthorString(t *testing.T) {
	cases := map[string]npmAuthor{
		"":                                {},
		"Just A Name":                     {Name: "Just A Name"},
		"Name <e@x.com>":                  {Name: "Name", Email: "e@x.com"},
		"Name <e@x.com> (https://x.com)":  {Name: "Name", Email: "e@x.com", URL: "https://x.com"},
		"Name (https://x.com) <e@x.com>":  {Name: "Name", Email: "e@x.com", URL: "https://x.com"},
		"Name <e@x.com> (https://x.com) ": {Name: "Name", Email: "e@x.com", URL: "https://x.com"},
	}
	for in, want := range cases {
		got := parseNPMAuthorString(in)
		if got != want {
			t.Errorf("parseNPMAuthorString(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestCleanVCSURL(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"https://github.com/x/y":         "https://github.com/x/y",
		"git+https://github.com/x/y.git": "https://github.com/x/y",
		"git://github.com/x/y.git":       "git://github.com/x/y",
		"  https://github.com/x/y  ":     "https://github.com/x/y",
	}
	for in, want := range cases {
		if got := cleanVCSURL(in); got != want {
			t.Errorf("cleanVCSURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNPMPathFor_ScopedPackage(t *testing.T) {
	got := npmPathFor(cpe.PURL{Type: "npm", Namespace: "@types", Name: "node", Version: "20"})
	// The npm registry accepts the literal `@` (RFC 3986 sub-delim);
	// only the `/` between scope and name needs `%2F`.
	if !strings.Contains(got, "@types%2Fnode") || !strings.HasSuffix(got, "/20") {
		t.Errorf("npmPathFor scoped = %q (want @types%%2Fnode + /20)", got)
	}
}

func TestNPMSourceMetadataFlags(t *testing.T) {
	n := NewNPM(nil, nil)
	if n.Name() != "npm" || !n.Supports("npm") || !n.Supports("NPM") || n.Supports("pypi") {
		t.Errorf("name/Supports broken: name=%q supports(npm)=%v", n.Name(), n.Supports("npm"))
	}
	if !n.RequiresNetwork() {
		t.Error("npm Source must require network")
	}
}

// TestNPM_FetchVersionMissing — Fetch on a PURL without a Version
// should return ErrUnsupported (we'd fetch the package-level
// metadata which can't be projected to a per-version Component).
func TestNPM_FetchVersionMissing(t *testing.T) {
	n := NewNPM(nil, nil)
	_, err := n.Fetch(context.Background(), cpe.PURL{Type: "npm", Name: "lodash"})
	if err == nil {
		t.Fatal("expected error when Version missing")
	}
	if !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

// base64Of is a tiny helper for the integrity-hash test.
func base64Of(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
