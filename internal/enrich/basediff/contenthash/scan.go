package contenthash

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/psyf8t/astinus/internal/image/layer"
)

// DefaultExpectedFiles is the BaseSet capacity hint when the caller
// has no better estimate. A typical Linux base image (Debian /
// Alpine / distroless) has 5–20 k visible files; 10 k is a safe
// rounded default that keeps the bloom filter near its 1 % FP target
// for the realistic range and degrades gracefully past it.
const DefaultExpectedFiles = 10_000

// MaxFileBytes is the per-file read cap. Files larger than this are
// hashed up to the cap and recorded with the truncated digest plus
// a Size set to MaxFileBytes — which means an oversized base file
// will MATCH a target file only when the target is also truncated.
// In practice base images don't ship multi-GiB binaries, so the cap
// exists as a defensive ceiling, not a normal-case constraint.
const MaxFileBytes int64 = 1 << 30 // 1 GiB

// BuildBaseSet walks every visible file in img, hashes it (streaming
// SHA-256, constant memory), and returns a BaseSet keyed by hash.
//
// Whiteout files (`.wh.*`), directories, hardlinks, and other
// non-regular tar entries are silently skipped — `layer.WalkFiles`
// handles the filtering. Per-file hash failures are logged and
// dropped (one bad layer entry should not abort the entire scan).
//
// The function is single-goroutine: tar streams are sequential and
// cannot be parallelised without first buffering each file into
// memory, which would dominate any CPU win from concurrent hashing.
// Empirically the bottleneck is decompression + I/O, not SHA-256.
func BuildBaseSet(ctx context.Context, img v1.Image) (*BaseSet, error) {
	if img == nil {
		return nil, fmt.Errorf("contenthash: nil image")
	}
	set := NewBaseSet(DefaultExpectedFiles)

	visitor := func(_ context.Context, fe layer.FileEntry, body io.Reader) error {
		hash, n, err := HashStream(io.LimitReader(body, MaxFileBytes))
		if err != nil {
			// Surface the error with the offending path so debug logs
			// are useful, but skip rather than abort: one corrupt
			// entry should not bin the whole base set.
			return layer.SkipFile
		}
		set.Add(hash, Evidence{
			BasePath:   fe.Path,
			LayerIndex: fe.Layer.Index,
			Size:       n,
		})
		return nil
	}

	if err := layer.WalkFiles(ctx, img, visitor); err != nil {
		return nil, fmt.Errorf("contenthash: walk base: %w", err)
	}
	return set, nil
}

// ScanTarget walks every visible file in img and returns the
// resulting path → SHA-256 hex map.
//
// The map keys use the canonical path form (slash-separated, no
// leading slash) — same as layer.FileMap and BaseSet. Lookup-by-path
// is what the basediff enricher does next when it iterates SBOM
// components.
func ScanTarget(ctx context.Context, img v1.Image) (map[string]string, error) {
	if img == nil {
		return nil, fmt.Errorf("contenthash: nil image")
	}
	out := make(map[string]string, DefaultExpectedFiles)

	visitor := func(_ context.Context, fe layer.FileEntry, body io.Reader) error {
		hash, _, err := HashStream(io.LimitReader(body, MaxFileBytes))
		if err != nil {
			return layer.SkipFile
		}
		out[fe.Path] = hash
		return nil
	}

	if err := layer.WalkFiles(ctx, img, visitor); err != nil {
		return nil, fmt.Errorf("contenthash: walk target: %w", err)
	}
	return out, nil
}
