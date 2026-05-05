//go:build benchmark

package benchmarks

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/psyf8t/astinus/test/acceptance/helpers"
)

// build1GBTestImage synthesises a roughly 1 GiB Docker image by
// extending an Alpine base with a real package layer (so extractors
// have hits) plus a single 950 MiB random-bytes file. Tag is
// deterministic so subsequent runs reuse the docker layer cache.
func build1GBTestImage(b *testing.B) string {
	b.Helper()
	helpers.RequireDockerDaemon(b)
	df := `FROM alpine:3.19
RUN apk add --no-cache python3 nodejs
RUN dd if=/dev/urandom of=/payload.bin bs=1M count=950 status=none
`
	return helpers.BuildImage(b, df, nil)
}

// build5GBTestImage builds the same shape with a 4.7 GiB payload.
// Used by the 5GB benchmarks.
func build5GBTestImage(b *testing.B) string {
	b.Helper()
	helpers.RequireDockerDaemon(b)
	df := `FROM alpine:3.19
RUN apk add --no-cache python3 nodejs go
RUN dd if=/dev/urandom of=/payload.bin bs=1M count=4800 status=none
`
	return helpers.BuildImage(b, df, nil)
}

// gateWallClock fails the benchmark when the recorded duration
// exceeds limit. Used by the perf gates documented in the task.
func gateWallClock(b *testing.B, kind string, dur, limit time.Duration) {
	b.Helper()
	b.Logf("%s wall-clock: %v (limit %v)", kind, dur, limit)
	if dur > limit {
		b.Errorf("PERFORMANCE GATE: %s took %v (target < %v)", kind, dur, limit)
	}
}

func BenchmarkAcceptance_1GBImage(b *testing.B) {
	if testing.Short() {
		b.Skip("skip in short mode")
	}
	img := build1GBTestImage(b)
	syft := helpers.GenSyftSBOM(b, img)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_ = helpers.RunAstinusFull(b, helpers.AstinusOpts{SBOM: syft, Image: img})
		gateWallClock(b, "1GB", time.Since(start), 2*time.Minute)
	}
}

func BenchmarkAcceptance_5GBImage(b *testing.B) {
	if testing.Short() {
		b.Skip("skip in short mode")
	}
	img := build5GBTestImage(b)
	syft := helpers.GenSyftSBOM(b, img)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_ = helpers.RunAstinusFull(b, helpers.AstinusOpts{SBOM: syft, Image: img})
		gateWallClock(b, "5GB", time.Since(start), 8*time.Minute)
	}
}

// BenchmarkAcceptance_MemoryPeak captures Sys delta around a single
// enrich run on the 5GB image and fails when the peak exceeds 4 GiB.
//
// The Sys-delta approach is approximate (it reports the runtime's
// view of allocated address space, not RSS) but it is good enough
// to catch the catastrophic-regression class of bug; precise RSS
// would require an OS-level probe and is out of scope.
func BenchmarkAcceptance_MemoryPeak(b *testing.B) {
	if testing.Short() {
		b.Skip("skip in short mode")
	}
	img := build5GBTestImage(b)
	syft := helpers.GenSyftSBOM(b, img)

	for i := 0; i < b.N; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_ = helpers.RunAstinusFull(b, helpers.AstinusOpts{SBOM: syft, Image: img})
		runtime.ReadMemStats(&after)

		const limit = uint64(4) << 30 // 4 GiB
		delta := after.Sys - before.Sys
		b.Logf("memory delta: %s (limit %s)", humanBytes(delta), humanBytes(limit))
		if delta > limit {
			b.Errorf("MEMORY GATE: peak %s (target < %s)", humanBytes(delta), humanBytes(limit))
		}
	}
}

// humanBytes renders a byte count as a human-readable IEC string.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
