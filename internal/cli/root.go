// Package cli wires the cobra command tree.
//
// Stage 0 ships only the root command, version, and completion. Each
// later stage adds its own command file (enrich.go, validate.go, …).
package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/psyf8t/astinus/internal/telemetry"
	"github.com/psyf8t/astinus/internal/version"
)

// Exit codes — keep aligned with spec section 6.4.
const (
	ExitOK           = 0
	ExitGenericError = 1
	ExitInvalidArgs  = 2
)

// rootOptions are bound to global flags shared by all subcommands.
type rootOptions struct {
	configPath string
	logLevel   string
	logFormat  string
	noColor    bool
	quiet      bool
}

// Execute runs the root command and returns the process exit code.
//
// It deliberately does not call os.Exit itself; main() is the only place
// that does so, which keeps Execute callable from tests.
func Execute() int {
	opts := &rootOptions{}
	root := newRootCommand(opts)

	if err := root.Execute(); err != nil {
		// cobra already printed the error to stderr by default.
		var exitErr *exitError
		if asExitError(err, &exitErr) {
			return exitErr.code
		}
		return ExitGenericError
	}
	return ExitOK
}

func newRootCommand(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "astinus",
		Short: "SBOM enricher for Docker/OCI images",
		Long: `astinus enriches an existing SBOM (CycloneDX or SPDX) for a
container image with layer attribution, base-image diff, untracked
component detection, and CPE identifiers.

It is designed to run after a primary SBOM generator (Syft, cdxgen,
Microsoft sbom-tool, …) and fill the gaps those tools leave behind.`,
		Version:           version.String(),
		SilenceUsage:      true,
		SilenceErrors:     false,
		DisableAutoGenTag: true,
	}

	flags := cmd.PersistentFlags()
	flags.StringVar(&opts.configPath, "config", "", "Path to configuration file (default: ./astinus.yaml)")
	flags.StringVar(&opts.logLevel, "log-level", "info", "Log level: debug|info|warn|error")
	flags.StringVar(&opts.logFormat, "log-format", "auto", "Log format: text|json|auto")
	flags.BoolVar(&opts.noColor, "no-color", false, "Disable colored output")
	flags.BoolVar(&opts.quiet, "quiet", false, "Suppress all output except results")

	cmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		level, ok := telemetry.ParseLevel(opts.logLevel)
		if !ok {
			return newExitError(ExitInvalidArgs,
				fmt.Errorf("invalid --log-level %q (want debug|info|warn|error)", opts.logLevel))
		}
		if opts.quiet {
			level = slog.LevelError
		}

		var format telemetry.Format
		switch opts.logFormat {
		case "text":
			format = telemetry.FormatText
		case "json":
			format = telemetry.FormatJSON
		case "auto", "":
			format = telemetry.FormatAuto
		default:
			return newExitError(ExitInvalidArgs,
				fmt.Errorf("invalid --log-format %q (want text|json|auto)", opts.logFormat))
		}

		logger := telemetry.NewLogger(telemetry.Options{
			Level:   level,
			Format:  format,
			NoColor: opts.noColor,
			Writer:  os.Stderr,
		})
		c.SetContext(WithLogger(c.Context(), logger))
		return nil
	}

	// Cobra uses a fixed "{{.Version}}" template; override to print the
	// full banner from internal/version on `astinus version`.
	cmd.SetVersionTemplate("{{.Version}}\n")

	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newCompletionCommand())
	cmd.AddCommand(newEnrichCommand())

	return cmd
}
