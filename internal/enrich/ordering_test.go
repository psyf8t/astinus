package enrich

import (
	"strings"
	"testing"
)

// fakeEnrichers builds a typed []Enricher from variadic name+deps
// pairs so the tables below stay terse. Reuses stubEnricher (defined
// in pipeline_test.go) which is the package's canonical Enricher
// fixture — covers the Enrich method as well, even though the topo
// sort never calls it.
func fakeEnrichers(specs ...spec) []Enricher {
	out := make([]Enricher, len(specs))
	for i, s := range specs {
		out[i] = &stubEnricher{name: s.name, deps: s.deps}
	}
	return out
}

type spec struct {
	name string
	deps []string
}

// ─── Linear, diamond, and stable-tie cases ──────────────────────────

func TestTopoSortLinearChain(t *testing.T) {
	in := fakeEnrichers(
		spec{"c", []string{"b"}},
		spec{"a", nil},
		spec{"b", []string{"a"}},
	)
	out, err := TopoSort(in)
	if err != nil {
		t.Fatalf("TopoSort: %v", err)
	}
	if got := strings.Join(names(out), ","); got != "a,b,c" {
		t.Errorf("order = %s, want a,b,c", got)
	}
}

func TestTopoSortDiamond(t *testing.T) {
	// a → b → d
	//  \      ↑
	//   → c → /
	in := fakeEnrichers(
		spec{"d", []string{"b", "c"}},
		spec{"a", nil},
		spec{"b", []string{"a"}},
		spec{"c", []string{"a"}},
	)
	out, err := TopoSort(in)
	if err != nil {
		t.Fatalf("TopoSort: %v", err)
	}
	got := names(out)
	if got[0] != "a" {
		t.Errorf("first = %q, want a (root)", got[0])
	}
	if got[3] != "d" {
		t.Errorf("last = %q, want d (sink)", got[3])
	}
	// b and c can appear in either order; the algorithm walks
	// the input slice when seeding zero-in-degree, so b (input
	// index 2) retires before c (input index 3).
	if got[1] != "b" || got[2] != "c" {
		t.Errorf("middle = [%q, %q], want [b, c] (input order tie-break)",
			got[1], got[2])
	}
}

func TestTopoSortStableInputOrderForPeers(t *testing.T) {
	in := fakeEnrichers(
		spec{"first", nil},
		spec{"second", nil},
		spec{"third", nil},
		spec{"fourth", nil},
		spec{"fifth", nil},
	)
	out, _ := TopoSort(in)
	want := []string{"first", "second", "third", "fourth", "fifth"}
	got := names(out)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q (peer order must be stable)",
				i, got[i], want[i])
		}
	}
}

// ─── Error cases ────────────────────────────────────────────────────

func TestTopoSortDuplicateName(t *testing.T) {
	in := fakeEnrichers(
		spec{"x", nil},
		spec{"x", nil},
	)
	_, err := TopoSort(in)
	if err == nil {
		t.Fatal("expected duplicate-name error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("err = %v, want to mention 'duplicate'", err)
	}
}

// TestTopoSortUnknownDependencyIsLenient — TopoSort silently
// drops deps on enrichers not in the input slice (lenient mode).
// This is the deliberate trade-off for the CLI's `--disable`
// surface: when an operator disables an enricher's dependency,
// the dependent enricher must still run rather than abort the
// pipeline. ADR-0024 documents the deviation from the task
// spec's "error on unknown dep" wording.
func TestTopoSortUnknownDependencyIsLenient(t *testing.T) {
	in := fakeEnrichers(
		spec{"a", []string{"ghost"}},
	)
	out, err := TopoSort(in)
	if err != nil {
		t.Fatalf("expected no error in lenient mode, got %v", err)
	}
	if len(out) != 1 || out[0].Name() != "a" {
		t.Errorf("got %+v, want single enricher [a]", names(out))
	}
}

func TestTopoSortCycleDetection(t *testing.T) {
	in := fakeEnrichers(
		spec{"a", []string{"b"}},
		spec{"b", []string{"a"}},
	)
	_, err := TopoSort(in)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("err = %v, want to mention 'cyclic'", err)
	}
	if !strings.Contains(err.Error(), "a") || !strings.Contains(err.Error(), "b") {
		t.Errorf("err = %v, want both cycle members named", err)
	}
}

func TestTopoSortLongCycleDetection(t *testing.T) {
	// a → b → c → a; d is unrelated and should still retire fine.
	// But TopoSort returns an error on ANY cycle, so we just
	// assert the error names every cycle member.
	in := fakeEnrichers(
		spec{"a", []string{"c"}},
		spec{"b", []string{"a"}},
		spec{"c", []string{"b"}},
		spec{"d", nil},
	)
	_, err := TopoSort(in)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	for _, name := range []string{"a", "b", "c"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("err = %v, want to name cycle member %q", err, name)
		}
	}
}

// ─── Empty / single ─────────────────────────────────────────────────

func TestTopoSortEmpty(t *testing.T) {
	out, err := TopoSort(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("len = %d, want 0", len(out))
	}
}

func TestTopoSortSingle(t *testing.T) {
	in := fakeEnrichers(spec{"only", nil})
	out, err := TopoSort(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Name() != "only" {
		t.Errorf("got = %+v", out)
	}
}

// ─── Real production wiring ─────────────────────────────────────────

// TestTopoSortProductionWiring asserts the canonical 5-enricher
// pipeline from internal/cli/enrich.go orders correctly under the
// PRSD-Task-6 dependency declarations:
//
//	attribution (no deps)
//	untracked   (no deps)
//	basediff    (deps: untracked)
//	cpe         (deps: untracked)
//	dedup       (deps: basediff, cpe)
//
// Expected order: attribution, untracked, basediff, cpe, dedup.
func TestTopoSortProductionWiring(t *testing.T) {
	in := fakeEnrichers(
		spec{"attribution", nil},
		spec{"basediff", []string{"untracked"}},
		spec{"untracked", nil},
		spec{"cpe", []string{"untracked"}},
		spec{"dedup", []string{"basediff", "cpe"}},
	)
	out, err := TopoSort(in)
	if err != nil {
		t.Fatalf("TopoSort: %v", err)
	}
	got := names(out)
	want := []string{"attribution", "untracked", "basediff", "cpe", "dedup"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q (full order: %v)",
				i, got[i], want[i], got)
		}
	}
}

// ─── Helpers ────────────────────────────────────────────────────────

func names(in []Enricher) []string {
	out := make([]string, len(in))
	for i, e := range in {
		out[i] = e.Name()
	}
	return out
}
