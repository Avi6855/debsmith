// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/deb"
	"github.com/Avi6855/debsmith/internal/policy"
	"github.com/Avi6855/debsmith/internal/version"
)

func (a *app) lintCommand() *cobra.Command {
	var (
		jsonOutput bool
		sarif      bool
		failOn     string
		listChecks bool
	)

	command := &cobra.Command{
		Use:   "lint <package.deb>...",
		Short: "Audit binary packages against Debian Policy",
		Args: func(cmd *cobra.Command, args []string) error {
			if listChecks {
				return nil
			}

			return cobra.MinimumNArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if listChecks {
				infos := policy.CheckInfos()

				fmt.Fprintf(cmd.OutOrStdout(), "%-8s %-9s %s\n", "CODE", "SEVERITY", "CHECK")
				for _, info := range infos {
					fmt.Fprintf(cmd.OutOrStdout(), "%-8s %-9s %s\n",
						info.Code, info.Severity, info.Name)
				}

				fmt.Fprintf(cmd.OutOrStdout(), "\n%d checks\n", len(infos))

				return nil
			}

			switch strings.ToLower(strings.TrimSpace(failOn)) {
			case "", "error", "warning", "warn", "info", "any", "never", "none":
			default:
				return fmt.Errorf("invalid --fail-on %q: use error, warning, info or never", failOn)
			}

			if sarif && len(args) > 1 {
				return fmt.Errorf("--sarif accepts one artifact per report")
			}

			reports := make([]policy.Report, 0, len(args))
			failed := false

			for _, path := range args {
				a.ui.Debug("linting %s", path)

				archive, err := deb.ReadFile(path)
				if err != nil {
					return err
				}

				report := policy.Lint(archive, path)
				reports = append(reports, report)

				if report.FailOn(failOn) {
					failed = true
				}
			}

			switch {
			case sarif:
				if err := reports[0].WriteSARIF(cmd.OutOrStdout(), version.Version); err != nil {
					return err
				}
			case jsonOutput:
				if err := writeJSON(cmd.OutOrStdout(), reports); err != nil {
					return err
				}
			default:
				for _, report := range reports {
					fmt.Fprint(cmd.OutOrStdout(), report.FormatText())
					fmt.Fprintln(cmd.OutOrStdout())
				}
			}

			if failed {
				return &exitError{code: 1}
			}

			return nil
		},
	}

	command.Flags().BoolVar(&jsonOutput, "json", false, "print machine readable JSON")
	command.Flags().BoolVar(&sarif, "sarif", false, "print a SARIF 2.1.0 report")
	command.Flags().StringVar(&failOn, "fail-on", "error",
		"fail when findings reach: error, warning, info or never")
	command.Flags().BoolVar(&listChecks, "list-checks", false, "list registered checks and exit")

	return command
}
