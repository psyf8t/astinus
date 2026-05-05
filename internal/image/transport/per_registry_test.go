package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubRT struct {
	hits int
	tag  string
}

func (s *stubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	s.hits++
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	rec.Body.WriteString(s.tag)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func TestNewPerRegistryRequiresDefault(t *testing.T) {
	if _, err := NewPerRegistry(nil); err == nil {
		t.Fatal("expected error for nil default")
	}
}

func TestPerRegistryDispatch(t *testing.T) {
	def := &stubRT{tag: "default"}
	special := &stubRT{tag: "special"}
	pr, err := NewPerRegistry(def)
	if err != nil {
		t.Fatal(err)
	}
	pr.Set("artifactory.corp.com", special)

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://artifactory.corp.com/v2/", http.NoBody)
	resp, err := pr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if special.hits != 1 || def.hits != 0 {
		t.Errorf("dispatch wrong: special=%d def=%d", special.hits, def.hits)
	}

	req2, _ := http.NewRequestWithContext(t.Context(), "GET", "https://docker.io/v2/", http.NoBody)
	resp2, err := pr.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if def.hits != 1 || special.hits != 1 {
		t.Errorf("default not used for unknown host: def=%d special=%d", def.hits, special.hits)
	}
}

func TestPerRegistryHostsCaseInsensitive(t *testing.T) {
	def := &stubRT{tag: "default"}
	special := &stubRT{tag: "special"}
	pr, _ := NewPerRegistry(def)
	pr.Set("ARTIFACTORY.corp.com", special)

	req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://artifactory.corp.com/v2/", http.NoBody)
	resp, err := pr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if special.hits != 1 {
		t.Errorf("case-insensitive lookup failed: special=%d", special.hits)
	}
}

func TestPerRegistryNilRequest(t *testing.T) {
	def := &stubRT{tag: "default"}
	pr, _ := NewPerRegistry(def)
	resp, err := pr.RoundTrip(nil)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected error on nil request")
	}
}

func TestPerRegistryHosts(t *testing.T) {
	pr, _ := NewPerRegistry(&stubRT{tag: "default"})
	pr.Set("a.example", &stubRT{})
	pr.Set("b.example", &stubRT{})
	got := pr.Hosts()
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "a.example") || !strings.Contains(joined, "b.example") {
		t.Errorf("hosts = %v", got)
	}
}
