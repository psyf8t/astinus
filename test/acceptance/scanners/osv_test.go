//go:build acceptance

package scanners

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

// osvReport is the minimal subset of osv-scanner's JSON output.
type osvReport struct {
	Results []struct {
		Packages []struct {
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func TestAcceptance_OSVScannerFindsLog4Shell(t *testing.T) {
	helpers.RequireDockerDaemon(t)
	helpers.RequireCommand(t, "osv-scanner")

	img := helpers.BuildImage(t, Log4ShellDockerfile, nil)
	syft := helpers.GenSyftSBOM(t, img)
	bom := helpers.RunAstinusFull(t, helpers.AstinusOpts{SBOM: syft, Image: img, Mode: "hybrid"})

	out := filepath.Join(t.TempDir(), "sbom.cdx.json")
	helpers.SaveJSON(t, out, bom)

	raw := helpers.RunOK(t, "osv-scanner", "--format", "json", "--sbom="+out)
	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("osv-scanner output is not JSON: %v\n%s", err, string(raw))
	}
	if !osvHasCVE(report, CVELog4Shell) {
		t.Errorf("OSV-Scanner must find %s in Astinus output", CVELog4Shell)
	}
}

func osvHasCVE(r osvReport, cve string) bool {
	for _, res := range r.Results {
		for _, p := range res.Packages {
			for _, v := range p.Vulnerabilities {
				if v.ID == cve || containsString(v.Aliases, cve) {
					return true
				}
			}
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
