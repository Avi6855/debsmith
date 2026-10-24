// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/manifest"
	"github.com/Avi6855/debsmith/internal/sourcepkg"
)

func (a *app) sourceCommand() *cobra.Command {
	var (
		manifestPath   string
		output         string
		epochValue     string
		signingKey     string
		passphraseFile string
		jsonOutput     bool
	)

	command := &cobra.Command{
		Use:   "source [project-dir]",
		Short: "Build a Debian 3.0 (quilt) source package (.dsc)",
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

			passphrase, err := resolvePassphrase(passphraseFile)
			if err != nil {
				return err
			}

			parsed, err := manifest.Load(project)
			if err != nil {
				return err
			}

			a.ui.Step("Building source package")

			result, err := sourcepkg.Build(parsed, sourcepkg.Options{
				OutDir:     output,
				Epoch:      epoch,
				SigningKey: signingKey,
				Passphrase: passphrase,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}

			a.ui.Success("%s %s", parsed.Name, parsed.VersionString())

			for _, file := range result.Files {
				a.ui.Detail("generated: %s", file)
			}

			if result.Signed {
				a.ui.Detail("signed:    %s", result.DSC)
			}

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVarP(&manifestPath, "manifest", "f", "", "path to debsmith.yaml or project directory")
	flags.StringVarP(&output, "output", "o", "", "output directory (default: dist/)")
	flags.StringVar(&epochValue, "epoch", "", "source package timestamp (unix seconds or RFC3339)")
	flags.StringVar(&signingKey, "sign-key", "", "OpenPGP private key used to sign the .dsc")
	flags.StringVar(&passphraseFile, "passphrase-file", "",
		"file containing the OpenPGP key passphrase")
	flags.BoolVar(&jsonOutput, "json", false, "print machine readable JSON")

	return command
}
