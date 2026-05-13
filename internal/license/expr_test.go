package license

import (
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/sbom/model"
)

func TestEvaluateComponent_DenyGPL(t *testing.T) {
	c := &model.Component{
		Name:     "gpl-package",
		Licenses: []model.License{{SPDXID: "GPL-3.0-only"}},
	}
	dec := EvaluateComponent(c, Options{Deny: []string{"GPL-3.0-only"}})
	if dec.Decision != ActionDeny {
		t.Errorf("Decision = %v, want ActionDeny", dec.Decision)
	}
	if len(dec.Denied) != 1 || dec.Denied[0] != "GPL-3.0-only" {
		t.Errorf("Denied = %v, want [GPL-3.0-only]", dec.Denied)
	}
	if !strings.Contains(dec.Reason, "--license-deny") {
		t.Errorf("Reason = %q, want mention of --license-deny", dec.Reason)
	}
}

func TestEvaluateComponent_AllowOnlyMITAndApache(t *testing.T) {
	cases := []struct {
		expression string
		want       Action
	}{
		{"MIT", ActionAllow},
		{"Apache-2.0", ActionAllow},
		{"BSD-3-Clause", ActionDeny},
		// Any of the OR alternatives matches → allow
		{"MIT OR GPL-3.0-only", ActionAllow},
		// Compound AND requires the intersection to land
		{"MIT AND Apache-2.0", ActionAllow},
	}
	opts := Options{Allow: []string{"MIT", "Apache-2.0"}}
	for _, c := range cases {
		comp := &model.Component{
			Licenses: []model.License{{Expression: c.expression}},
		}
		dec := EvaluateComponent(comp, opts)
		if dec.Decision != c.want {
			t.Errorf("expression %q: Decision = %v, want %v (reason: %s)",
				c.expression, dec.Decision, c.want, dec.Reason)
		}
	}
}

// TestEvaluateComponent_DenyPrecedenceOverAllow — ADR-0065 spelled
// out: a dual `MIT OR GPL-3.0-only` row fails when GPL-3.0-only is
// in deny, even though MIT is in allow. "If it CAN be released as
// GPL, treat it as GPL."
func TestEvaluateComponent_DenyPrecedenceOverAllow(t *testing.T) {
	c := &model.Component{
		Licenses: []model.License{{Expression: "MIT OR GPL-3.0-only"}},
	}
	dec := EvaluateComponent(c, Options{
		Allow: []string{"MIT"},
		Deny:  []string{"GPL-3.0-only"},
	})
	if dec.Decision != ActionDeny {
		t.Errorf("Decision = %v, want ActionDeny (deny > allow)", dec.Decision)
	}
}

func TestEvaluateComponent_RequireKnown(t *testing.T) {
	c := &model.Component{Name: "no-license"} // empty Licenses
	dec := EvaluateComponent(c, Options{RequireKnown: true})
	if dec.Decision != ActionDeny {
		t.Errorf("Decision = %v, want ActionDeny on require-known + no licenses",
			dec.Decision)
	}
	dec = EvaluateComponent(c, Options{RequireKnown: false})
	if dec.Decision != ActionUnknown {
		t.Errorf("Decision = %v, want ActionUnknown without require-known", dec.Decision)
	}
}

// TestEvaluateComponent_UnparseableExpression — a malformed
// expression (token that doesn't match isSPDXIdentifier) goes
// into dec.Unknown. Without require-known the component falls to
// ActionUnknown; with require-known it's denied.
func TestEvaluateComponent_UnparseableExpression(t *testing.T) {
	c := &model.Component{
		Licenses: []model.License{{Expression: "MIT OR 1stPlace"}}, // 1stPlace not a valid SPDX id
	}
	dec := EvaluateComponent(c, Options{RequireKnown: false})
	if dec.Decision != ActionUnknown {
		t.Errorf("Decision = %v, want ActionUnknown for unparseable expr", dec.Decision)
	}
	if len(dec.Unknown) != 1 {
		t.Errorf("Unknown = %v, want 1 entry", dec.Unknown)
	}

	dec = EvaluateComponent(c, Options{RequireKnown: true})
	if dec.Decision != ActionDeny {
		t.Errorf("Decision = %v, want ActionDeny with require-known", dec.Decision)
	}
}

// TestEvaluateComponent_DisabledGate covers the no-flags case —
// opts.IsEnabled() = false. The CLI short-circuits in this branch,
// but the helper should still produce a clean ActionAllow on a
// component with a license + Allow=Deny=empty + require-known=false.
func TestEvaluateComponent_DisabledGate(t *testing.T) {
	c := &model.Component{
		Licenses: []model.License{{SPDXID: "Apache-2.0"}},
	}
	dec := EvaluateComponent(c, Options{})
	if dec.Decision != ActionAllow {
		t.Errorf("Decision = %v, want ActionAllow on disabled gate", dec.Decision)
	}
}

func TestExtractSPDXIDs(t *testing.T) {
	cases := []struct {
		expr string
		ids  []string
		ok   bool
	}{
		{"MIT", []string{"MIT"}, true},
		{"MIT OR Apache-2.0", []string{"MIT", "Apache-2.0"}, true},
		{"MIT AND Apache-2.0", []string{"MIT", "Apache-2.0"}, true},
		{"(MIT OR Apache-2.0) AND CC0-1.0",
			[]string{"MIT", "Apache-2.0", "CC0-1.0"}, true},
		{"Apache-2.0 WITH LLVM-exception", []string{"Apache-2.0"}, true},
		{"", nil, false},
		{"   ", nil, false},
		// numeric-leading token isn't a valid SPDX id
		{"1stPlace", nil, false},
	}
	for _, c := range cases {
		ids, ok := extractSPDXIDs(c.expr)
		if ok != c.ok {
			t.Errorf("extractSPDXIDs(%q) ok = %v, want %v", c.expr, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(ids) != len(c.ids) {
			t.Errorf("extractSPDXIDs(%q) = %v, want %v", c.expr, ids, c.ids)
			continue
		}
		for i := range ids {
			if ids[i] != c.ids[i] {
				t.Errorf("extractSPDXIDs(%q)[%d] = %q, want %q",
					c.expr, i, ids[i], c.ids[i])
			}
		}
	}
}

func TestIsSPDXIdentifier(t *testing.T) {
	cases := []struct {
		tok  string
		want bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"BSD-3-Clause", true},
		{"GPL-3.0-only", true},
		{"GPL-3.0+", true},
		{"CC0-1.0", true},
		{"1stPlace", false}, // numeric-leading
		{"", false},
		{"-leading", false},  // non-letter start
		{"has space", false}, // space in token
	}
	for _, c := range cases {
		if got := isSPDXIdentifier(c.tok); got != c.want {
			t.Errorf("isSPDXIdentifier(%q) = %v, want %v", c.tok, got, c.want)
		}
	}
}

func TestIntersectFold_CaseInsensitive(t *testing.T) {
	got := intersectFold([]string{"MIT", "Apache-2.0"}, []string{"mit", "gpl-3.0-only"})
	if len(got) != 1 || got[0] != "MIT" {
		t.Errorf("intersectFold = %v, want [MIT] (case-insensitive)", got)
	}
}

func TestOptions_IsEnabled(t *testing.T) {
	cases := []struct {
		opts Options
		want bool
	}{
		{Options{}, false},
		{Options{Allow: []string{"MIT"}}, true},
		{Options{Deny: []string{"GPL-3.0-only"}}, true},
		{Options{RequireKnown: true}, true},
	}
	for _, c := range cases {
		if got := c.opts.IsEnabled(); got != c.want {
			t.Errorf("IsEnabled(%+v) = %v, want %v", c.opts, got, c.want)
		}
	}
}
