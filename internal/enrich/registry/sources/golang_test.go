package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

func TestGolang_FetchInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1.9.3.info") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Version":"v1.9.3","Time":"2023-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	g := NewGolang(nil, server.Client()).WithUpstream(server.URL)
	meta, err := g.Fetch(context.Background(),
		cpe.PURL{Type: "golang", Namespace: "github.com/sirupsen", Name: "logrus", Version: "v1.9.3"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if meta == nil || meta.Version != "v1.9.3" {
		t.Errorf("meta = %+v", meta)
	}
	if meta.Repository != "https://github.com/sirupsen/logrus" {
		t.Errorf("repository = %q", meta.Repository)
	}
}

func TestEscapeModulePath(t *testing.T) {
	cases := map[string]string{
		"github.com/sirupsen/logrus":      "github.com/sirupsen/logrus",
		"github.com/Masterminds/squirrel": "github.com/!masterminds/squirrel",
		"github.com/PuerkitoBio/goquery":  "github.com/!puerkito!bio/goquery",
		"google.golang.org/grpc":          "google.golang.org/grpc",
	}
	for in, want := range cases {
		if got := escapeModulePath(in); got != want {
			t.Errorf("escapeModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGolangVCSGuess(t *testing.T) {
	cases := map[string]string{
		"github.com/x/y":         "https://github.com/x/y",
		"github.com/x/y/v2":      "https://github.com/x/y",
		"gitlab.com/foo/bar":     "https://gitlab.com/foo/bar",
		"k8s.io/client-go":       "",
		"google.golang.org/grpc": "",
	}
	for in, want := range cases {
		if got := golangVCSGuess(in); got != want {
			t.Errorf("vcs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadModFile(t *testing.T) {
	body := strings.NewReader(`module example.com/test

go 1.22

require github.com/x/y v1.2.3
`)
	if got := readModFile(body); got != "example.com/test" {
		t.Errorf("readModFile = %q", got)
	}
}

func TestGolangSourceMetadata(t *testing.T) {
	g := NewGolang(nil, nil)
	if g.Name() != "golang" || !g.Supports("golang") || g.Supports("npm") {
		t.Errorf("Name/Supports broken: name=%q", g.Name())
	}
	if !g.RequiresNetwork() {
		t.Error("Golang Source must require network")
	}
}
