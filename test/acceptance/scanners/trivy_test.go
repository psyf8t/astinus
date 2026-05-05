//go:build acceptance

package scanners

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

// trivyReport is the minimal subset of trivy's JSON output.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func TestAcceptance_TrivyFindsLog4Shell(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	helpers.RequireCommand(t, "trivy")

	img := helpers.BuildImage(t, Log4ShellDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img, Mode: "hybrid"})

	out := filepath.Join(t.TempDir(), "sbom.cdx.json")
	helpers.SaveJSON(t, out, bom)

	raw := helpers.RunOK(t, "trivy", "sbom", "--format", "json", out)
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("trivy output is not JSON: %v\n%s", err, string(raw))
	}
	if !trivyHasCVE(report, CVELog4Shell) {
		t.Errorf("Trivy must find %s in Astinus output", CVELog4Shell)
	}
}

func trivyHasCVE(r trivyReport, cve string) bool {
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == cve {
				return true
			}
		}
	}
	return false
}
