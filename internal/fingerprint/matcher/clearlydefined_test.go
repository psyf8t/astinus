package matcher

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestClearlyDefinedMatcherIsAlwaysNoMatch(t *testing.T) {
	m := NewClearlyDefinedMatcher("", http.DefaultClient)
	_, err := m.Lookup(context.Background(), "sha256", "anything")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
	if !strings.Contains(err.Error(), "no hash-to-coordinate") {
		t.Errorf("error should explain the limitation: %v", err)
	}
	if !strings.Contains(err.Error(), "offline-db") {
		t.Errorf("error should suggest the workaround: %v", err)
	}
}

func TestClearlyDefinedMatcherDefaults(t *testing.T) {
	m := NewClearlyDefinedMatcher("", nil)
	if m.baseURL != DefaultClearlyDefinedBaseURL {
		t.Errorf("baseURL = %q", m.baseURL)
	}
	if m.client != http.DefaultClient {
		t.Error("default client not used")
	}
}

func TestClearlyDefinedMatcherName(t *testing.T) {
	if NewClearlyDefinedMatcher("", nil).Name() != "clearlydefined" {
		t.Error("Name")
	}
}
