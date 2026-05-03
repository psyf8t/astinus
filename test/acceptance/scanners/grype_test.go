//go:build acceptance

package scanners

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

// matchReport is the minimal subset of grype's JSON shape we need
// to assert on. Defined here to avoid pulling in grype as a
// dependency.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID string `json:"id"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

func TestAcceptance_GrypeFindsLog4Shell(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	helpers.RequireCommand(t, "grype")

	img := helpers.BuildImage(t, Log4ShellDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img, Mode: "hybrid"})

	out := filepath.Join(t.TempDir(), "sbom.cdx.json")
	helpers.SaveJSON(t, out, bom)

	raw := helpers.RunOK(t, "grype", "sbom:"+out, "-o", "json")
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("grype output is not JSON: %v\n%s", err, string(raw))
	}

	if !reportHasCVE(report, CVELog4Shell) {
		t.Errorf("Grype must find %s in Astinus output. "+
			"Symptom: CPE coverage on log4j-core insufficient. "+
			"Got %d total matches.", CVELog4Shell, len(report.Matches))
	}
}

func reportHasCVE(r grypeReport, cve string) bool {
	for _, m := range r.Matches {
		if m.Vulnerability.ID == cve {
			return true
		}
	}
	return false
}
