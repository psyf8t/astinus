package cli

import (
	"fmt"
	"math"

	cpesources "github.com/psyf8t/astinus/internal/enrich/cpe/sources"
)

// nvdHybridSkipThreshold is the component-count above which the
// CLI omits the NVD API source from the resolver chain when the
// operator is in hybrid mode without an NVD_API_KEY.
//
// Calibration:
//
//   - Anonymous NVD rate is 5 req / 30 s ≈ one call every 6 s.
//   - The cpe phase budget the acceptance suite enforces is < 5 min
//     for the entire pipeline; on a 6406-component image this was
//     observed to wedge for 168 minutes (~1680 NVD calls) before
//     this fix.
//   - Hybrid mode early-exits when an offline source produces a
//     high-confidence answer; in practice ~50% of components fall
//     through to NVD on a real-world Node + Debian image.
//   - 50 components × 50% × 6 s = 150 s ≈ 2.5 min — within budget.
//   - 100 components × 50% × 6 s = 300 s = 5 min — at budget.
//
// We pick 50 because the user's reported regression cited
// "components > ~50" as the boundary where the wedge began; below
// that, even worst-case all-fall-through stays under the 5-minute
// cpe-phase budget.
const nvdHybridSkipThreshold = 50

// nvdAnonymousSecondsPerCall is the steady-state interval between
// anonymous NVD API requests. Used to size the warning's ETA.
const nvdAnonymousSecondsPerCall = 6.0

// shouldSkipAnonymousNVDInHybrid is the decision rule for omitting
// the NVD API source from the resolver chain.
//
// Returns true only when ALL three hold:
//
//  1. mode is ModeHybrid (ModeOnline means the operator explicitly
//     asked for network — we don't second-guess them).
//  2. nvdKey is empty (with a key the rate limit is 10× higher
//     and the wedge does not happen at realistic workloads).
//  3. componentCount exceeds nvdHybridSkipThreshold.
//
// Returns false otherwise — the NVD source stays in the chain.
func shouldSkipAnonymousNVDInHybrid(mode cpesources.Mode, nvdKey string, componentCount int) bool {
	if mode != cpesources.ModeHybrid {
		return false
	}
	if nvdKey != "" {
		return false
	}
	return componentCount > nvdHybridSkipThreshold
}

// estimateAnonymousNVDMinutes is the worst-case wall-clock estimate
// for componentCount components hitting the NVD anonymous endpoint
// at the documented rate. Used to make the skip-warning concrete
// for operators ("would take ~X min").
//
// The estimate is intentionally pessimistic — the orchestrator's
// hybrid early-exit suppresses many calls in practice, but a
// pessimistic minute-count is the right shape for an actionable
// warning ("don't wait, set the key now").
func estimateAnonymousNVDMinutes(componentCount int) int {
	if componentCount <= 0 {
		return 0
	}
	seconds := float64(componentCount) * nvdAnonymousSecondsPerCall
	minutes := int(math.Ceil(seconds / 60.0))
	if minutes < 1 {
		return 1
	}
	return minutes
}

// nvdSkipAdvice is the operator-facing advice string emitted with
// the skip warning. Centralised so the test can assert on it
// without duplicating the prose.
func nvdSkipAdvice(componentCount int) string {
	return fmt.Sprintf(
		"NVD API rate limit (5 req/30s without API key) would take ~%d min for %d components. "+
			"Skipping NVD API source. To enable: set NVD_API_KEY env var "+
			"(free: https://nvd.nist.gov/developers/request-an-api-key) "+
			"or use --cpe-mode online to force.",
		estimateAnonymousNVDMinutes(componentCount), componentCount)
}
