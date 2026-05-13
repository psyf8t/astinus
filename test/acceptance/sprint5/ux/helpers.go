//go:build acceptance

package ux

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

// runHelp invokes `<bin> enrich --help` and returns the combined
// stdout+stderr. The astinus binary writes its flag help to
// stdout under cobra's default behaviour; we capture both for
// robustness against future I/O reroutings.
func runHelp(tb testing.TB, bin string) string {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "enrich", "--help") //nolint:gosec // bin from AstinusBinary
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		tb.Fatalf("astinus enrich --help failed: %v\noutput:\n%s", err, buf.String())
	}
	return buf.String()
}
