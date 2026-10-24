// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/version"
)

func (a *app) versionCommand() *cobra.Command {
	var jsonOutput bool

	command := &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := version.Current()

			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), info)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "debsmith %s\n", info.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "  commit: %s\n", info.Commit)
			fmt.Fprintf(cmd.OutOrStdout(), "  built:  %s\n", info.Date)
			fmt.Fprintf(cmd.OutOrStdout(), "  go:     %s %s/%s\n", info.Go, info.OS, info.Arch)

			return nil
		},
	}

	command.Flags().BoolVar(&jsonOutput, "json", false, "print machine readable JSON")

	return command
}
