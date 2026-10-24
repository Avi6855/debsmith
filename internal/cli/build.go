// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/build"
)

func (a *app) buildCommand() *cobra.Command {
	var (
		manifestPath       string
		output             string
		epochValue         string
		compression        string
		controlCompression string
		sbom               bool
		jsonOutput         bool
	)

	command := &cobra.Command{
		Use:   "build [project-dir]",
		Short: "Build a binary .deb package from debsmith.yaml",
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
				a.ui.Step("Building package")
			}

			result, err := build.Run(build.Options{
				ProjectPath:        project,
				Output:             output,
				Epoch:              epoch,
				Compression:        compression,
				ControlCompression: controlCompression,
				SBOM:               sbom,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}

			a.ui.Success("%s %s (%s)", result.Package, result.Version, result.Architecture)
			a.ui.Detail("artifact: %s (%s)", result.Artifact, humanSize(result.Size))
			a.ui.Detail("sha256:   %s", result.SHA256)
			a.ui.Detail("payload:  %d files, %d KiB installed", result.Files, result.InstalledSize)
			a.ui.Detail("epoch:    %d", result.Epoch)

			if result.SBOM != "" {
				a.ui.Detail("sbom:     %s", result.SBOM)
			}

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVarP(&manifestPath, "manifest", "f", "", "path to debsmith.yaml or project directory")
	flags.StringVarP(&output, "output", "o", "", "output .deb path or directory (default: dist/)")
	flags.StringVar(&epochValue, "epoch", "", "build timestamp (unix seconds or RFC3339)")
	flags.StringVar(&compression, "compression", "", "data.tar compression: zstd, gzip or xz")
	flags.StringVar(&controlCompression, "control-compression", "",
		"control.tar compression: gzip, zstd or xz (default gzip)")
	flags.BoolVar(&sbom, "sbom", false, "write a CycloneDX 1.5 SBOM next to the artifact")
	flags.BoolVar(&jsonOutput, "json", false, "print machine readable JSON")

	return command
}
