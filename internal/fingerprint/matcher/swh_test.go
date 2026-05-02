package matcher

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSWHMatcher200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/content/sha256:") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sha256":"abc",
			"length":1234,
			"filenames":["jq-1.7.1"],
			"data_url":"https://archive.softwareheritage.org/api/1/content/sha256:abc/raw"
		}`))
	}))
	defer srv.Close()

	m := NewSWHMatcher(srv.URL, srv.Client())
	got, err := m.Lookup(context.Background(), "sha256", "abc")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "jq-1.7.1" || got.Source != "swh" {
		t.Errorf("got %+v", got)
	}
}

func TestSWHMatcher404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := NewSWHMatcher(srv.URL, srv.Client())
	_, err := m.Lookup(context.Background(), "sha256", "x")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestSWHMatcher429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := NewSWHMatcher(srv.URL, srv.Client())
	_, err := m.Lookup(context.Background(), "sha256", "x")
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if errors.Is(err, ErrNoMatch) {
		t.Errorf("429 should not be ErrNoMatch (real error): %v", err)
	}
	if !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("err message should mention rate-limited: %v", err)
	}
}

func TestSWHMatcherUnsupportedAlgorithm(t *testing.T) {
	m := NewSWHMatcher("http://example.invalid", nil)
	_, err := m.Lookup(context.Background(), "md5", "x")
	if !errors.Is(err, ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch", err)
	}
}

func TestSWHMatcherSHA1Path(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/content/sha1:") {
			t.Errorf("expected sha1 path, got %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"sha1":"x","filenames":["a"]}`))
	}))
	defer srv.Close()
	m := NewSWHMatcher(srv.URL, srv.Client())
	if _, err := m.Lookup(context.Background(), "sha1", "deadbeef"); err != nil {
		t.Fatal(err)
	}
}

func TestSWHMatcherMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	m := NewSWHMatcher(srv.URL, srv.Client())
	_, err := m.Lookup(context.Background(), "sha256", "x")
	if err == nil {
		t.Fatal("expected error for malformed body")
	}
}

func TestSWHMatcherDefaultsClientAndBaseURL(t *testing.T) {
	m := NewSWHMatcher("", nil)
	if m.baseURL != DefaultSWHBaseURL {
		t.Errorf("baseURL = %q", m.baseURL)
	}
	if m.client != http.DefaultClient {
		t.Error("default client not used")
	}
}

func TestSWHMatcherName(t *testing.T) {
	if NewSWHMatcher("", nil).Name() != "swh" {
		t.Error("Name")
	}
}
