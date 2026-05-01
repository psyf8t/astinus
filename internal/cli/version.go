package cli

import (
	"github.com/spf13/cobra"

	"github.com/psyf8t/astinus/internal/version"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write([]byte(version.String() + "\n"))
			return err
		},
	}
}
