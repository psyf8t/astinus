package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/registry"
)

// TestStubs_AllReportNotFound — gate that none of the deferred
// Sources accidentally start returning success without an
// implementation. Each stub MUST return ErrNotFound until its full
// implementation lands (ADR-0033 §6 follow-up).
func TestStubs_AllReportNotFound(t *testing.T) {
	cases := []struct {
		name     string
		ctor     func() registry.Source
		purlType string
	}{
		{"cargo", func() registry.Source { return NewCargo(nil, nil) }, "cargo"},
		{"gem", func() registry.Source { return NewRubyGems(nil, nil) }, "gem"},
		{"nuget", func() registry.Source { return NewNuGet(nil, nil) }, "nuget"},
		{"deb", func() registry.Source { return NewDebian(nil, nil) }, "deb"},
		{"alpine", func() registry.Source { return NewAlpine(nil, nil) }, "apk"},
		{"repology", func() registry.Source { return NewRepology(nil, nil) }, "repology"},
		{"ecosystems", func() registry.Source { return NewEcosystems(nil, nil) }, "ecosyste-ms"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.ctor()
			if !s.Supports(c.purlType) {
				t.Errorf("Supports(%q) = false; stub should claim its ecosystem", c.purlType)
			}
			if !s.RequiresNetwork() {
				t.Error("stub should declare RequiresNetwork=true")
			}
			meta, err := s.Fetch(context.Background(),
				cpe.PURL{Type: c.purlType, Name: "anything", Version: "1.0"})
			if !errors.Is(err, registry.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound (stub)", err)
			}
			if meta != nil {
				t.Errorf("meta = %+v, want nil from stub", meta)
			}
		})
	}
}
