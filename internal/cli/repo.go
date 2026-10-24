// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/aptrepo"
)

func (a *app) repoCommand() *cobra.Command {
	var (
		suite          string
		codename       string
		component      string
		origin         string
		label          string
		description    string
		architectures  []string
		epochValue     string
		pool           bool
		signingKey     string
		passphraseFile string
		jsonOutput     bool
	)

	command := &cobra.Command{
		Use:   "repo [directory]",
		Short: "Build Packages/Release indexes and optionally sign them",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			directory := "."
			if len(args) > 0 {
				directory = args[0]
			}

			epoch, err := resolveEpoch(epochValue)
			if err != nil {
				return err
			}

			passphrase, err := resolvePassphrase(passphraseFile)
			if err != nil {
				return err
			}

			a.ui.Step("Building APT repository")

			result, err := aptrepo.Build(aptrepo.Options{
				Dir:           directory,
				Suite:         suite,
				Codename:      codename,
				Component:     component,
				Origin:        origin,
				Label:         label,
				Description:   description,
				Architectures: architectures,
				Epoch:         epoch,
				Pool:          pool,
				SigningKey:    signingKey,
				Passphrase:    passphrase,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), result)
			}

			a.ui.Success("indexed %d package(s)", result.Packages)
			a.ui.Detail("architectures: %s", strings.Join(result.Architectures, " "))
			a.ui.Detail("release:       %s", result.ReleasePath)

			if result.Signed {
				a.ui.Detail("signed:        InRelease + Release.gpg")
			} else {
				a.ui.Warn("repository is unsigned; pass --sign-key to sign Release")
			}

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVar(&suite, "suite", "stable", "APT suite name")
	flags.StringVar(&codename, "codename", "", "APT codename (default: suite)")
	flags.StringVar(&component, "component", "main", "component name")
	flags.StringVar(&origin, "origin", "DebSmith", "Origin field")
	flags.StringVar(&label, "label", "", "Label field (default: origin)")
	flags.StringVar(&description, "description", "", "repository Description field")
	flags.StringSliceVar(&architectures, "arch", nil, "extra architectures to index (repeatable)")
	flags.StringVar(&epochValue, "epoch", "", "Release timestamp (unix seconds or RFC3339)")
	flags.BoolVar(&pool, "pool", true, "copy packages into a Debian pool/ layout")
	flags.StringVar(&signingKey, "sign-key", "", "OpenPGP private key used to sign Release")
	flags.StringVar(&passphraseFile, "passphrase-file", "",
		"file containing the OpenPGP key passphrase")
	flags.BoolVar(&jsonOutput, "json", false, "print machine readable JSON")

	return command
}

func resolvePassphrase(path string) (string, error) {
	if path != "" {
		return aptrepo.ReadPassphrase(path)
	}

	return os.Getenv("DEBSMITH_GPG_PASSPHRASE"), nil
}
