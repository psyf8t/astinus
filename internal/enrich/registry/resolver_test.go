package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
)

// fakeSource is a configurable Source for resolver tests. We don't
// hit the network — the resolver's mode/cache/dispatch logic is
// what we exercise here.
type fakeSource struct {
	name   string
	purl   string
	online bool
	calls  int
	meta   *Metadata
	err    error
}

func (f *fakeSource) Name() string           { return f.name }
func (f *fakeSource) Supports(t string) bool { return t == f.purl }
func (f *fakeSource) RequiresNetwork() bool  { return f.online }
func (f *fakeSource) Fetch(_ context.Context, _ cpe.PURL) (*Metadata, error) {
	f.calls++
	return f.meta, f.err
}

func TestResolver_RoutesByPURLType(t *testing.T) {
	a := &fakeSource{name: "a", purl: "npm", meta: &Metadata{Name: "from-a", Description: "non-empty"}}
	b := &fakeSource{name: "b", purl: "pypi", meta: &Metadata{Name: "from-b", Description: "non-empty"}}
	r := NewResolver(ResolverOptions{Sources: []Source{a, b}, NetworkOK: true})

	got, err := r.Resolve(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == nil || got.Name != "from-a" {
		t.Errorf("got %+v, want metadata from a", got)
	}
	if a.calls != 1 || b.calls != 0 {
		t.Errorf("a.calls=%d, b.calls=%d; want only a called", a.calls, b.calls)
	}
}

func TestResolver_FallsThroughOnNotFound(t *testing.T) {
	a := &fakeSource{name: "a", purl: "npm", err: ErrNotFound}
	b := &fakeSource{name: "b", purl: "npm", meta: &Metadata{Name: "from-b", Description: "non-empty"}}
	r := NewResolver(ResolverOptions{Sources: []Source{a, b}, NetworkOK: true})

	got, err := r.Resolve(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Name != "from-b" {
		t.Errorf("got %+v, want from-b after fall-through", got)
	}
	if a.calls != 1 || b.calls != 1 {
		t.Errorf("expected both sources called once each (a=%d b=%d)", a.calls, b.calls)
	}
}

func TestResolver_NetworkSourcesSkippedWhenNoNetwork(t *testing.T) {
	online := &fakeSource{name: "online", purl: "npm", online: true,
		meta: &Metadata{Name: "should-not-call", Description: "x"}}
	offline := &fakeSource{name: "offline", purl: "npm", online: false,
		meta: &Metadata{Name: "from-offline", Description: "x"}}
	r := NewResolver(ResolverOptions{
		Sources: []Source{online, offline}, NetworkOK: false,
	})
	got, _ := r.Resolve(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"})
	if got == nil || got.Name != "from-offline" {
		t.Errorf("got %+v, want offline source's result", got)
	}
	if online.calls != 0 {
		t.Errorf("online source called %d times under no-network", online.calls)
	}
}

func TestResolver_CachesNegativeResults(t *testing.T) {
	src := &fakeSource{name: "x", purl: "npm", err: ErrNotFound}
	r := NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true})

	for i := 0; i < 3; i++ {
		_, err := r.Resolve(context.Background(), cpe.PURL{Type: "npm", Name: "x", Version: "1"})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("iteration %d: err = %v, want ErrNotFound", i, err)
		}
	}
	if src.calls != 1 {
		t.Errorf("source called %d times; cache should have kept it at 1", src.calls)
	}
}

func TestResolver_NoSupportingSourceReturnsUnsupported(t *testing.T) {
	src := &fakeSource{name: "x", purl: "npm"}
	r := NewResolver(ResolverOptions{Sources: []Source{src}, NetworkOK: true})

	_, err := r.Resolve(context.Background(), cpe.PURL{Type: "deb", Name: "x", Version: "1"})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestResolver_NilSafe(t *testing.T) {
	r := NewResolver(ResolverOptions{NetworkOK: true})
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
	_, err := r.Resolve(context.Background(), cpe.PURL{Type: "npm", Name: "x"})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported (no sources)", err)
	}
}

func TestCanonicalPURLKey_Stable(t *testing.T) {
	a := canonicalPURLKey(cpe.PURL{Type: "NPM", Name: "Lodash", Version: "1"})
	b := canonicalPURLKey(cpe.PURL{Type: "npm", Name: "lodash", Version: "1"})
	if a != b {
		t.Errorf("canonical key not case-insensitive: %q vs %q", a, b)
	}
}
