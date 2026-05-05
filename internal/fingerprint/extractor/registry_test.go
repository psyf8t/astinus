package extractor

import (
	"context"
	"testing"
)

// fakeExtractor is a configurable Extractor that lets tests assert
// the Registry's dispatch and ordering behaviour without involving
// real binary parsing.
type fakeExtractor struct {
	name       string
	confidence float64
	matches    bool
	identity   Identity
	err        error
}

func (f *fakeExtractor) Name() string                         { return f.name }
func (f *fakeExtractor) Confidence() float64                  { return f.confidence }
func (f *fakeExtractor) Match(_ context.Context, _ File) bool { return f.matches }
func (f *fakeExtractor) Extract(_ context.Context, _ File) (Identity, error) {
	return f.identity, f.err
}

func TestRegistryEmptyOnNoMatches(t *testing.T) {
	r := New(&fakeExtractor{name: "a", matches: false})
	got := r.Identify(context.Background(), File{})
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0", len(got))
	}
}

func TestRegistryDropsEmptyIdentities(t *testing.T) {
	r := New(&fakeExtractor{
		name:    "a",
		matches: true,
		// IsEmpty() returns true for the zero Identity.
	})
	got := r.Identify(context.Background(), File{})
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0 (empty identities should be dropped)", len(got))
	}
}

func TestRegistrySortsByConfidenceDescending(t *testing.T) {
	r := New(
		&fakeExtractor{
			name: "low", confidence: 0.5, matches: true,
			identity: Identity{Name: "x", Version: "1"},
		},
		&fakeExtractor{
			name: "high", confidence: 0.95, matches: true,
			identity: Identity{Name: "x", Version: "1"},
		},
		&fakeExtractor{
			name: "mid", confidence: 0.7, matches: true,
			identity: Identity{Name: "x", Version: "1"},
		},
	)
	got := r.Identify(context.Background(), File{})
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Source != "high" || got[1].Source != "mid" || got[2].Source != "low" {
		t.Errorf("order = [%s, %s, %s], want [high, mid, low]",
			got[0].Source, got[1].Source, got[2].Source)
	}
}

func TestRegistryDropsExtractorErrors(t *testing.T) {
	r := New(
		&fakeExtractor{
			name: "broken", confidence: 0.95, matches: true,
			err: context.Canceled,
		},
		&fakeExtractor{
			name: "ok", confidence: 0.6, matches: true,
			identity: Identity{Name: "x"},
		},
	)
	got := r.Identify(context.Background(), File{})
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (broken extractor should not abort the chain)", len(got))
	}
	if got[0].Source != "ok" {
		t.Errorf("Source = %q", got[0].Source)
	}
}

func TestRegistryStampsSourceAndConfidence(t *testing.T) {
	r := New(&fakeExtractor{
		name: "tagged", confidence: 0.42, matches: true,
		identity: Identity{Name: "x"},
	})
	got := r.Identify(context.Background(), File{})
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Source != "tagged" {
		t.Errorf("Source = %q", got[0].Source)
	}
	if got[0].Confidence != 0.42 {
		t.Errorf("Confidence = %v", got[0].Confidence)
	}
}

func TestRegistryFirst(t *testing.T) {
	r := New(
		&fakeExtractor{
			name: "low", confidence: 0.5, matches: true,
			identity: Identity{Name: "low-id"},
		},
		&fakeExtractor{
			name: "high", confidence: 0.95, matches: true,
			identity: Identity{Name: "high-id"},
		},
	)
	id, ok := r.First(context.Background(), File{})
	if !ok {
		t.Fatal("First returned !ok")
	}
	if id.Name != "high-id" {
		t.Errorf("Name = %q, want high-id", id.Name)
	}

	r2 := New(&fakeExtractor{name: "miss", matches: false})
	if _, ok := r2.First(context.Background(), File{}); ok {
		t.Error("First should return ok=false when no extractor matches")
	}
}

func TestNewDefaultExposesAllSixExtractors(t *testing.T) {
	r := NewDefault()
	exts := r.Extractors()
	if len(exts) != 6 {
		t.Fatalf("default registry size = %d, want 6", len(exts))
	}
	wantNames := map[string]bool{
		"go": false, "rust": false, "java": false,
		"python": false, "pe": false, "elf-library": false,
	}
	for _, e := range exts {
		if _, ok := wantNames[e.Name()]; !ok {
			t.Errorf("unexpected extractor in default set: %q", e.Name())
		}
		wantNames[e.Name()] = true
	}
	for n, seen := range wantNames {
		if !seen {
			t.Errorf("default set missing %q", n)
		}
	}
}

func TestExtractorsReturnsCopy(t *testing.T) {
	r := New(&fakeExtractor{name: "a", matches: true})
	exts := r.Extractors()
	exts[0] = &fakeExtractor{name: "mutated"}
	if r.Extractors()[0].Name() == "mutated" {
		t.Error("Extractors should return a defensive copy")
	}
}

func TestIdentityIsEmpty(t *testing.T) {
	if !(Identity{}).IsEmpty() {
		t.Error("zero Identity should be empty")
	}
	if (Identity{Name: "x"}).IsEmpty() {
		t.Error("Identity with Name should not be empty")
	}
	if (Identity{PURL: "pkg:x/y"}).IsEmpty() {
		t.Error("Identity with PURL should not be empty")
	}
}
