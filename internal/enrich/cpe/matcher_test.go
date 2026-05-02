package cpe

import "testing"

func TestBundledResolverHit(t *testing.T) {
	r := NewBundledResolver()
	p, _ := ParsePURL("pkg:npm/express@4.18.2")
	out := r.Resolve(p)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Source != SourceBundled || out[0].Confidence != ConfidenceHigh {
		t.Errorf("got %+v", out[0])
	}
	if out[0].CPE != "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q", out[0].CPE)
	}
}

func TestBundledResolverMiss(t *testing.T) {
	r := NewBundledResolver()
	p, _ := ParsePURL("pkg:npm/never-going-to-exist-9999@1.0")
	if got := r.Resolve(p); len(got) != 0 {
		t.Errorf("want no matches, got %v", got)
	}
}

func TestHeuristicResolverPypi(t *testing.T) {
	r := NewHeuristicResolver()
	p, _ := ParsePURL("pkg:pypi/some-pkg@1.0")
	out := r.Resolve(p)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	want := "cpe:2.3:a:some-pkg_project:some-pkg:1.0:*:*:*:*:*:*:*"
	if out[0].CPE != want {
		t.Errorf("CPE = %q, want %q", out[0].CPE, want)
	}
	if out[0].Confidence != ConfidenceLow || out[0].Source != SourceHeuristic {
		t.Errorf("got %+v", out[0])
	}
}

func TestHeuristicResolverMaven(t *testing.T) {
	r := NewHeuristicResolver()
	p, _ := ParsePURL("pkg:maven/com.example.deeply.nested/widget@2.0")
	out := r.Resolve(p)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].CPE != "cpe:2.3:a:nested:widget:2.0:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q (vendor should be last namespace segment)", out[0].CPE)
	}
}

func TestHeuristicResolverGolang(t *testing.T) {
	r := NewHeuristicResolver()
	p, _ := ParsePURL("pkg:golang/github.com/myuser/mytool@v1.0")
	out := r.Resolve(p)
	want := "cpe:2.3:a:myuser:mytool:v1.0:*:*:*:*:*:*:*"
	if out[0].CPE != want {
		t.Errorf("CPE = %q, want %q", out[0].CPE, want)
	}
}

func TestHeuristicResolverFallbackVendorEqualsName(t *testing.T) {
	r := NewHeuristicResolver()
	p, _ := ParsePURL("pkg:gem/rare-gem@1.0")
	out := r.Resolve(p)
	want := "cpe:2.3:a:rare-gem:rare-gem:1.0:*:*:*:*:*:*:*"
	if out[0].CPE != want {
		t.Errorf("CPE = %q, want %q", out[0].CPE, want)
	}
}

func TestHeuristicResolverEmptyName(t *testing.T) {
	if got := (&HeuristicResolver{}).Resolve(PURL{}); len(got) != 0 {
		t.Errorf("want no matches, got %v", got)
	}
}

func TestChainBundledFirst(t *testing.T) {
	c := DefaultChain()
	p, _ := ParsePURL("pkg:npm/express@4.18.2")
	out := c.Resolve(p)
	if len(out) != 1 || out[0].Source != SourceBundled {
		t.Errorf("Chain should prefer bundled; got %+v", out)
	}
}

func TestChainFallsThroughToHeuristic(t *testing.T) {
	c := DefaultChain()
	p, _ := ParsePURL("pkg:gem/rare-gem-9999@1.0")
	out := c.Resolve(p)
	if len(out) != 1 || out[0].Source != SourceHeuristic {
		t.Errorf("Chain should fall through to heuristic; got %+v", out)
	}
}

func TestChainEmpty(t *testing.T) {
	c := NewChain()
	if got := c.Resolve(PURL{}); len(got) != 0 {
		t.Errorf("empty chain should yield no matches, got %v", got)
	}
}
