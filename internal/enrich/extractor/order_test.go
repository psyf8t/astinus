package extractor_test

import (
	"context"
	"slices"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich"
	"github.com/psyf8t/astinus/internal/enrich/attribution"
	"github.com/psyf8t/astinus/internal/enrich/basediff"
	"github.com/psyf8t/astinus/internal/enrich/compliance"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/dedup"
	enrichextractor "github.com/psyf8t/astinus/internal/enrich/extractor"
	"github.com/psyf8t/astinus/internal/enrich/untracked"
	"github.com/psyf8t/astinus/internal/image"
	"github.com/psyf8t/astinus/internal/sbom/model"
)

// TestExtractor_TopologicalOrder is the regression gate for the
// pipeline placement contract from S3 Task 1: the extractor enricher
// MUST run AFTER untracked (so untracked-discovered binaries are part
// of its slate) and BEFORE cpe / dedup (so the lifted components pick
// up CPEs and feed the dedup key). Encodes the dependency declaration
// in a single assertion so a future reorder of the CLI's
// allEnrichers() slice cannot silently break the contract.
func TestExtractor_TopologicalOrder(t *testing.T) {
	enrichers := []enrich.Enricher{
		attribution.New(),
		basediff.New(),
		untracked.NewWithOptions(untracked.Options{}),
		enrichextractor.New(),
		cpe.New(),
		dedup.New(),
		compliance.New(),
	}

	sorted, err := enrich.TopoSort(enrichers)
	if err != nil {
		t.Fatalf("TopoSort: %v", err)
	}

	names := make([]string, len(sorted))
	for i, e := range sorted {
		names[i] = e.Name()
	}

	idx := func(name string) int { return slices.Index(names, name) }

	if idx("extractor") < idx("untracked") {
		t.Errorf("extractor must run AFTER untracked; order = %v", names)
	}
	if idx("extractor") > idx("cpe") {
		t.Errorf("extractor must run BEFORE cpe; order = %v", names)
	}
	if idx("extractor") > idx("dedup") {
		t.Errorf("extractor must run BEFORE dedup; order = %v", names)
	}
}

// TestExtractor_GracefulWithNilImageBundle exercises the production
// path where Enrich is called with a Bundle that has no image (the
// in-process pipeline test setups don't load an image). The lift
// phase should still run; only the layer-walk extraction is skipped.
func TestExtractor_GracefulWithNilImageBundle(t *testing.T) {
	sbom := &model.SBOM{Components: []model.Component{{
		BOMRef: "x@1", Name: "x",
		SubComponents: []model.Component{{
			Name: "dep", Version: "1", PURL: "pkg:npm/dep@1",
		}},
	}}}
	bundle := &image.Bundle{} // no Image
	if err := enrichextractor.New().Enrich(context.Background(), sbom, bundle); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Errorf("lift skipped on nil-image bundle: components = %d, want 2", len(sbom.Components))
	}
}
