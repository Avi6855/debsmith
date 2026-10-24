// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/repro"
)

func (a *app) verifyCommand() *cobra.Command {
	var (
		manifestPath       string
		epochValue         string
		compression        string
		controlCompression string
		jsonOutput         bool
	)

	command := &cobra.Command{
		Use:   "verify-repro [project-dir]",
		Short: "Build twice and verify the artifacts are byte-identical",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			project := manifestPath
			if project == "" {
				if len(args) > 0 {
					project = args[0]
				} else {
					project = "."
				}
			}

			epoch, err := resolveEpoch(epochValue)
			if err != nil {
				return err
			}

			if !jsonOutput {
				a.ui.Step("Verifying reproducibility")
			}

			result, err := repro.Verify(repro.Options{
				ProjectPath:        project,
				Epoch:              epoch,
				Compression:        compression,
				ControlCompression: controlCompression,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				if err := writeJSON(cmd.OutOrStdout(), result); err != nil {
					return err
				}
			} else if result.Reproducible {
				a.ui.Success("reproducible: identical SHA-256 %s", result.FirstSHA256)
				a.ui.Detail("size: %s", humanSize(result.Size))
			} else {
				a.ui.Error("not reproducible")
				a.ui.Detail("first:  %s", result.FirstSHA256)
				a.ui.Detail("second: %s", result.SecondSHA256)

				for _, difference := range result.Differences {
					a.ui.Detail("- %s", difference)
				}
			}

			if !result.Reproducible {
				return &exitError{code: 1}
			}

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVarP(&manifestPath, "manifest", "f", "", "path to debsmith.yaml or project directory")
	flags.StringVar(&epochValue, "epoch", "", "build timestamp shared by both runs")
	flags.StringVar(&compression, "compression", "", "data.tar compression override")
	flags.StringVar(&controlCompression, "control-compression", "",
		"control.tar compression override")
	flags.BoolVar(&jsonOutput, "json", false, "print machine readable JSON")

	return command
}
