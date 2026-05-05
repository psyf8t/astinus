package syftprefilter_test

import (
	"slices"
	"testing"

	"github.com/psyf8t/astinus/internal/enrich"
	"github.com/psyf8t/astinus/internal/enrich/attribution"
	"github.com/psyf8t/astinus/internal/enrich/basediff"
	"github.com/psyf8t/astinus/internal/enrich/compliance"
	"github.com/psyf8t/astinus/internal/enrich/cpe"
	"github.com/psyf8t/astinus/internal/enrich/dedup"
	enrichextractor "github.com/psyf8t/astinus/internal/enrich/extractor"
	"github.com/psyf8t/astinus/internal/enrich/syftprefilter"
	"github.com/psyf8t/astinus/internal/enrich/untracked"
)

// TestSyftPrefilter_TopologicalOrder is the regression gate for the
// pipeline placement contract from S3 Task 3: syft-prefilter MUST
// run BEFORE every other enricher. Encoded via Dependencies()=nil
// + first-in-input-order tie-break so the topological sort places
// it first when allEnrichers() lists it first.
func TestSyftPrefilter_TopologicalOrder(t *testing.T) {
	enrichers := []enrich.Enricher{
		syftprefilter.New(nil),
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
	if names[0] != syftprefilter.Name {
		t.Errorf("syft-prefilter must run first; order = %v", names)
	}
	// Sanity check: every other known enricher comes after.
	prefilterIdx := slices.Index(names, syftprefilter.Name)
	for _, after := range []string{"attribution", "basediff", "untracked",
		"extractor", "cpe", "dedup", "compliance"} {
		if idx := slices.Index(names, after); idx <= prefilterIdx {
			t.Errorf("%s ran at idx %d, want after syft-prefilter at idx %d (order = %v)",
				after, idx, prefilterIdx, names)
		}
	}
}
