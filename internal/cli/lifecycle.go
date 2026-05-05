package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	cfgpkg "github.com/psyf8t/astinus/internal/config"
	"github.com/psyf8t/astinus/internal/enrich/lifecycle"
	registryenrich "github.com/psyf8t/astinus/internal/enrich/registry"
)

// lifecycleUpdateOptions are bound to the `lifecycle update` flags.
type lifecycleUpdateOptions struct {
	output        string
	mirrorsConfig string
	timeout       time.Duration
}

// newLifecycleCommand returns the `astinus lifecycle` parent
// command. Subcommands today: `update` (refreshes the snapshot
// JSON from endoflife.date).
func newLifecycleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lifecycle",
		Short: "Manage the lifecycle / EOL data snapshot",
		Long: `The lifecycle enricher consults endoflife.date for per-Component
release / active-support / end-of-life dates. An embedded seed
snapshot ships with the binary; operators can refresh a richer
copy via:

  astinus lifecycle update --output ~/.cache/astinus/lifecycle/snapshot.json

…and point the enricher at it via --lifecycle-snapshot <path>.

Mirrors are read from the same --mirrors-config YAML used by the
registry enricher (entries with ecosystem=lifecycle).`,
	}
	cmd.AddCommand(newLifecycleUpdateCommand())
	return cmd
}

// newLifecycleUpdateCommand creates `astinus lifecycle update`.
func newLifecycleUpdateCommand() *cobra.Command {
	opts := &lifecycleUpdateOptions{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Refresh the bundled endoflife.date snapshot file",
		Long: `Walks the bundled product mapping (~30 OS / runtime products),
fetches each product's cycle list from endoflife.date (or the
configured mirror for ecosystem=lifecycle), and writes a combined
JSON snapshot to --output. The output is wire-format-compatible
with the embedded seed — point --lifecycle-snapshot at it to
enrich with fresher data.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runLifecycleUpdate(c.Context(), c.OutOrStdout(), opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.output, "output", "",
		"Output JSON snapshot path (required). Parent directory created if missing.")
	flags.StringVar(&opts.mirrorsConfig, "mirrors-config", "",
		"Path to mirrors YAML — same schema as `astinus enrich --mirrors-config`. "+
			"Entries with ecosystem=lifecycle route through the corp mirror.")
	flags.DurationVar(&opts.timeout, "timeout", 5*time.Minute,
		"Total wall-clock cap for the update operation.")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

// runLifecycleUpdate iterates the bundled product mapping, fetches
// each product's cycles via EndOfLifeSource, and writes a combined
// JSON to opts.output. Per-product failures are logged + skipped
// so a single missing product (renamed upstream) doesn't abort
// the whole refresh.
func runLifecycleUpdate(ctx context.Context, out io.Writer, opts *lifecycleUpdateOptions) error {
	if opts.output == "" {
		return fmt.Errorf("--output is required")
	}
	mirrorsCfg, err := cfgpkg.LoadMirrorsConfig(opts.mirrorsConfig)
	if err != nil {
		return err
	}
	mirrors := registryenrich.MirrorsByEcosystem(mirrorsCfg)["lifecycle"]
	httpClient := &http.Client{Timeout: 30 * time.Second}
	src := lifecycle.NewEndOfLife(mirrors, httpClient)

	if opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.timeout)
		defer cancel()
	}

	products := uniqueProducts()
	combined := make(map[string][]lifecycle.Lifecycle, len(products))
	failures := []string{}
	fmt.Fprintf(out, "lifecycle update: fetching %d products\n", len(products))
	for _, p := range products {
		cycles, err := src.FetchProduct(ctx, p)
		if err != nil {
			fmt.Fprintf(out, "  - %s: %v (skipped)\n", p, err)
			failures = append(failures, p)
			continue
		}
		combined[p] = cycles
		fmt.Fprintf(out, "  - %s: %d cycles\n", p, len(cycles))
	}
	if len(combined) == 0 {
		return fmt.Errorf("no products fetched (all %d failed)", len(failures))
	}
	if err := writeLifecycleSnapshot(opts.output, combined); err != nil {
		return err
	}
	fmt.Fprintf(out, "lifecycle update: wrote %d products → %s (%d failures)\n",
		len(combined), opts.output, len(failures))
	return nil
}

// uniqueProducts collects the deduplicated set of endoflife product
// names from the bundled mapping tables.
func uniqueProducts() []string {
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		seen[p] = struct{}{}
	}
	for _, m := range lifecyclePURLProducts() {
		add(m)
	}
	for _, m := range lifecycleNameProducts() {
		add(m)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// lifecyclePURLProducts / lifecycleNameProducts read the bundled
// mapping tables via the public ProductMappingCount + a few stable
// product names baked here. Avoids exporting the full maps from
// the package while still letting the CLI walk them.
func lifecyclePURLProducts() []string {
	// The list mirrors purlToProduct values in product_mapping.go.
	// Keeping it here is mild duplication but lets the package
	// keep its maps unexported.
	return []string{
		"alpine", "debian", "ubuntu", "centos", "rhel", "rocky-linux",
		"almalinux", "fedora", "amazon-linux", "opensuse",
	}
}

func lifecycleNameProducts() []string {
	return []string{
		"nodejs", "python", "go", "openjdk", "ruby", "php", "perl", "rust", "dotnet",
		"postgresql", "mysql", "mariadb", "redis", "mongodb", "sqlite",
		"cassandra", "elasticsearch",
		"kubernetes", "docker-engine", "containerd", "podman",
		"nginx", "apache", "haproxy",
	}
}

// writeLifecycleSnapshot writes combined to path as wire-format
// JSON (one cycle list per product, RFC 3339 dates). The file
// schema is the same the BundledSource loader accepts, so the
// `--lifecycle-snapshot` flag round-trips this output.
func writeLifecycleSnapshot(path string, combined map[string][]lifecycle.Lifecycle) error {
	if err := os.MkdirAll(parentDir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for %q: %w", path, err)
	}
	body, err := json.MarshalIndent(toWireFormat(combined), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil { //nolint:gosec // 644 is right for a snapshot
		return fmt.Errorf("write %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %q: %w", path, err)
	}
	return nil
}

// toWireFormat projects parsed Lifecycle entries back to the wire
// shape the BundledSource loader accepts (`releaseDate` / `support`
// / `eol` / `latest` / `lts`).
func toWireFormat(in map[string][]lifecycle.Lifecycle) map[string][]map[string]any {
	out := make(map[string][]map[string]any, len(in))
	for product, cycles := range in {
		entries := make([]map[string]any, 0, len(cycles))
		for _, c := range cycles {
			entry := map[string]any{
				"cycle":  c.Cycle,
				"latest": c.Latest,
				"lts":    c.LTS,
			}
			if !c.ReleaseDate.IsZero() {
				entry["releaseDate"] = c.ReleaseDate.Format("2006-01-02")
			}
			switch {
			case !c.ActiveSupportEnd.IsZero():
				entry["support"] = c.ActiveSupportEnd.Format("2006-01-02")
			case c.SupportBoolean != "":
				entry["support"] = c.SupportBoolean == "true"
			}
			switch {
			case !c.EOL.IsZero():
				entry["eol"] = c.EOL.Format("2006-01-02")
			case c.EOLBoolean != "":
				entry["eol"] = c.EOLBoolean == "true"
			}
			entries = append(entries, entry)
		}
		out[product] = entries
	}
	return out
}

// parentDir returns filepath.Dir(path) without importing filepath
// at the top of this file (it's already imported elsewhere — but
// keeping the helper inlined preserves the per-function-import
// hygiene for clean reads).
func parentDir(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i]
	}
	return "."
}
