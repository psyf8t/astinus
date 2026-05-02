package enrich

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// stubEnricher is a tiny Enricher whose Enrich method records its
// invocations and either appends a property or returns a configured
// error.
type stubEnricher struct {
	name      string
	calls     int
	addProp   string
	addValue  string
	err       error
	cancelCtx bool
}

func (s *stubEnricher) Name() string { return s.name }
func (s *stubEnricher) Enrich(ctx context.Context, sbom *model.SBOM, _ *image.Bundle) error {
	s.calls++
	if s.cancelCtx {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.err != nil {
		return s.err
	}
	if s.addProp != "" {
		if sbom.Properties == nil {
			sbom.Properties = map[string]string{}
		}
		sbom.Properties[s.addProp] = s.addValue
	}
	return nil
}

func TestPipelineRunsInOrder(t *testing.T) {
	a := &stubEnricher{name: "a", addProp: "k", addValue: "1"}
	b := &stubEnricher{name: "b", addProp: "k", addValue: "2"}
	p := NewPipeline(nil, a, b)

	sbom := &model.SBOM{}
	bundle := &image.Bundle{SBOM: sbom}
	if err := p.Run(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a.calls != 1 || b.calls != 1 {
		t.Errorf("call counts a=%d b=%d", a.calls, b.calls)
	}
	if sbom.Properties["k"] != "2" {
		t.Errorf("expected b to win (last write), got %q", sbom.Properties["k"])
	}
}

func TestPipelineHaltsOnError(t *testing.T) {
	a := &stubEnricher{name: "a", err: errors.New("boom")}
	b := &stubEnricher{name: "b"}
	p := NewPipeline(nil, a, b)

	err := p.Run(context.Background(), &model.SBOM{}, &image.Bundle{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `"a"`) {
		t.Errorf("error should mention enricher name, got %v", err)
	}
	if b.calls != 0 {
		t.Errorf("b should NOT be called after a's error")
	}
}

func TestPipelineNilSBOM(t *testing.T) {
	if err := NewPipeline(nil).Run(context.Background(), nil, &image.Bundle{}); err == nil {
		t.Fatal("expected error for nil sbom")
	}
}

func TestPipelineNilBundle(t *testing.T) {
	if err := NewPipeline(nil).Run(context.Background(), &model.SBOM{}, nil); err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestPipelineStampsMetadata(t *testing.T) {
	p := NewPipeline(nil)
	sbom := &model.SBOM{}
	if err := p.Run(context.Background(), sbom, &image.Bundle{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sbom.Metadata.Properties[model.PropertyEnrichedBy] != "astinus" {
		t.Errorf("PropertyEnrichedBy = %q", sbom.Metadata.Properties[model.PropertyEnrichedBy])
	}
	if sbom.Metadata.Properties[model.PropertyEnrichedVersion] == "" {
		t.Error("PropertyEnrichedVersion should be populated")
	}
}

func TestPipelineStampIdempotent(t *testing.T) {
	p := NewPipeline(nil)
	sbom := &model.SBOM{}
	if err := p.Run(context.Background(), sbom, &image.Bundle{}); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	first := sbom.Metadata.Properties[model.PropertyEnrichedBy]
	if err := p.Run(context.Background(), sbom, &image.Bundle{}); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if sbom.Metadata.Properties[model.PropertyEnrichedBy] != first {
		t.Errorf("PropertyEnrichedBy changed across runs")
	}
}

func TestPipelineEnrichers(t *testing.T) {
	a := &stubEnricher{name: "a"}
	b := &stubEnricher{name: "b"}
	p := NewPipeline(nil, a, b)
	got := p.Enrichers()
	if len(got) != 2 || got[0].Name() != "a" || got[1].Name() != "b" {
		t.Errorf("Enrichers = %v", got)
	}
}

func TestPipelineContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := NewPipeline(nil, &stubEnricher{name: "a"})
	if err := p.Run(ctx, &model.SBOM{}, &image.Bundle{}); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestFilter(t *testing.T) {
	a := &stubEnricher{name: "a"}
	b := &stubEnricher{name: "b"}
	c := &stubEnricher{name: "c"}
	enrichers := []Enricher{a, b, c}

	t.Run("no filter", func(t *testing.T) {
		got := Filter(enrichers, nil, nil)
		if len(got) != 3 {
			t.Errorf("len = %d, want 3", len(got))
		}
	})
	t.Run("only enable a,c", func(t *testing.T) {
		got := Filter(enrichers, map[string]bool{"a": true, "c": true}, nil)
		if len(got) != 2 || got[0].Name() != "a" || got[1].Name() != "c" {
			t.Errorf("got = %v", got)
		}
	})
	t.Run("disable b", func(t *testing.T) {
		got := Filter(enrichers, nil, map[string]bool{"b": true})
		if len(got) != 2 || got[0].Name() != "a" || got[1].Name() != "c" {
			t.Errorf("got = %v", got)
		}
	})
	t.Run("disable wins over enable", func(t *testing.T) {
		got := Filter(enrichers,
			map[string]bool{"a": true, "b": true},
			map[string]bool{"b": true})
		if len(got) != 1 || got[0].Name() != "a" {
			t.Errorf("got = %v", got)
		}
	})
}
