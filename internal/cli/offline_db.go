package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/psyf8t/astinus/internal/version"
)

// offlineDBManifestVersion is bumped when the on-disk layout changes
// in an incompatible way. Loaders compare and refuse mismatched
// versions.
const offlineDBManifestVersion = 1

// offlineDBManifest is the schema written to <root>/manifest.json.
type offlineDBManifest struct {
	Version int       `json:"version"`
	BuiltAt time.Time `json:"built_at"`
	BuiltBy string    `json:"built_by"`
	Sources []string  `json:"sources"`
	Notes   string    `json:"notes,omitempty"`
}

// offlineDBOptions are bound to the `offline-db build` flags.
type offlineDBOptions struct {
	output        string
	includeNVDCPE bool
	includeCD     bool
	includePop    bool
	notes         string
}

// newOfflineDBCommand returns the `astinus offline-db` parent
// command.
func newOfflineDBCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "offline-db",
		Short: "Manage the offline catalogue (CPE + fingerprint) for air-gapped runs",
		Long: `The offline DB is a directory of JSON entries the air-gapped
enrich workflow consults via --offline-db <path>. Stage 12 ships
the layout + scaffolding; the --include-* flags that pull data
from the public sources (NVD CPE Dictionary, ClearlyDefined,
popular-binaries hash list) are wired in Stage 13.

Today, build creates the directory structure plus a manifest.json
header. Operators populate the catalogue manually until Stage 13's
network sourcing lands.`,
	}
	cmd.AddCommand(newOfflineDBBuildCommand())
	cmd.AddCommand(newOfflineDBInfoCommand())
	return cmd
}

// newOfflineDBBuildCommand creates `astinus offline-db build`.
func newOfflineDBBuildCommand() *cobra.Command {
	opts := &offlineDBOptions{}
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Create or refresh the offline catalogue layout at --output",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runOfflineDBBuild(c.OutOrStdout(), opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.output, "output", "", "Output directory for the offline catalogue (required)")
	flags.BoolVar(&opts.includeNVDCPE, "include-nvd-cpe", false,
		"Sync NVD CPE Dictionary (Stage 13: not yet implemented)")
	flags.BoolVar(&opts.includeCD, "include-clearlydefined", false,
		"Sync ClearlyDefined catalogue (Stage 13: not yet implemented)")
	flags.BoolVar(&opts.includePop, "include-popular-binaries", false,
		"Sync popular binary hashes (Stage 13: not yet implemented)")
	flags.StringVar(&opts.notes, "notes", "",
		"Free-form note recorded in manifest.json (e.g. ticket reference)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

// newOfflineDBInfoCommand prints a summary of an existing catalogue.
func newOfflineDBInfoCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Print summary information about an existing offline catalogue",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runOfflineDBInfo(c.OutOrStdout(), path)
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Path to the offline catalogue (required)")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

// runOfflineDBBuild creates the layout + manifest.
func runOfflineDBBuild(out io.Writer, opts *offlineDBOptions) error {
	if opts.output == "" {
		return newExitError(ExitInvalidArgs, fmt.Errorf("offline-db: --output required"))
	}

	dirs := []string{
		filepath.Join(opts.output, "cpe", "by-purl"),
		filepath.Join(opts.output, "cpe", "by-name"),
		filepath.Join(opts.output, "fingerprint", "sha256"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return newExitError(ExitOutputWrite, fmt.Errorf("offline-db: mkdir %s: %w", d, err))
		}
	}

	manifest := offlineDBManifest{
		Version: offlineDBManifestVersion,
		BuiltAt: time.Now().UTC(),
		BuiltBy: "astinus-" + version.Version,
		Sources: collectSourceLabels(opts),
		Notes:   opts.notes,
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return newExitError(ExitOutputWrite, fmt.Errorf("offline-db: marshal manifest: %w", err))
	}
	mfPath := filepath.Join(opts.output, "manifest.json")
	if err := os.WriteFile(mfPath, append(body, '\n'), 0o644); err != nil { //nolint:gosec // catalogue is read-everywhere
		return newExitError(ExitOutputWrite, fmt.Errorf("offline-db: write manifest: %w", err))
	}

	if anyIncludeFlag(opts) {
		fmt.Fprintln(out, "Note: --include-* flags are recognised but not yet wired (Stage 13 follow-up).")
	}
	fmt.Fprintf(out, "Offline DB scaffold created at %s\n", opts.output)
	fmt.Fprintf(out, "Manifest:                       %s\n", mfPath)
	fmt.Fprintf(out, "Layout:\n")
	fmt.Fprintf(out, "  cpe/by-purl/                  (one JSON per PURL)\n")
	fmt.Fprintf(out, "  cpe/by-name/<type>/           (one JSON per (type, name))\n")
	fmt.Fprintf(out, "  fingerprint/<alg>/            (one JSON per (alg, digest))\n")
	return nil
}

// runOfflineDBInfo prints the manifest + counts.
func runOfflineDBInfo(out io.Writer, path string) error {
	if path == "" {
		return newExitError(ExitInvalidArgs, fmt.Errorf("offline-db: --path required"))
	}
	body, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		return newExitError(ExitOutputWrite, fmt.Errorf("offline-db: read manifest: %w", err))
	}
	var manifest offlineDBManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return newExitError(ExitOutputWrite, fmt.Errorf("offline-db: parse manifest: %w", err))
	}

	fmt.Fprintf(out, "Path:    %s\n", path)
	fmt.Fprintf(out, "Version: %d\n", manifest.Version)
	fmt.Fprintf(out, "Built:   %s\n", manifest.BuiltAt.Format(time.RFC3339))
	fmt.Fprintf(out, "By:      %s\n", manifest.BuiltBy)
	if len(manifest.Sources) > 0 {
		fmt.Fprintf(out, "Sources: %v\n", manifest.Sources)
	}
	if manifest.Notes != "" {
		fmt.Fprintf(out, "Notes:   %s\n", manifest.Notes)
	}

	cpeCount := countJSONFiles(filepath.Join(path, "cpe"))
	fpCount := countJSONFiles(filepath.Join(path, "fingerprint"))
	fmt.Fprintf(out, "Entries: cpe=%d  fingerprint=%d\n", cpeCount, fpCount)
	return nil
}

// collectSourceLabels lists the requested sources for the manifest
// header. Today we record the operator's intent even when the
// import logic isn't wired yet; Stage 13 will skip flags that
// didn't actually run.
func collectSourceLabels(opts *offlineDBOptions) []string {
	var out []string
	if opts.includeNVDCPE {
		out = append(out, "nvd-cpe")
	}
	if opts.includeCD {
		out = append(out, "clearlydefined")
	}
	if opts.includePop {
		out = append(out, "popular-binaries")
	}
	return out
}

func anyIncludeFlag(opts *offlineDBOptions) bool {
	return opts.includeNVDCPE || opts.includeCD || opts.includePop
}

// countJSONFiles returns the number of *.json files anywhere under
// root. Returns 0 when the directory does not exist; surface read
// errors are deliberately swallowed (count is informational, not
// an audit metric).
func countJSONFiles(root string) int {
	count := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, _ error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) == ".json" {
			count++
		}
		return nil
	})
	return count
}
