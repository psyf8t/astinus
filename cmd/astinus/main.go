// Command astinus is the CLI entry point for the SBOM enricher.
package main

import (
	"os"

	"github.com/psyf8t/astinus/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
