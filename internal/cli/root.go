// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package cli implements the debsmith command line interface.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/ui"
)

type app struct {
	ui *ui.UI
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}

	return e.err.Error()
}

func (e *exitError) Unwrap() error {
	return e.err
}

// Execute runs the CLI and returns a process exit code.
func Execute(args []string) int {
	root := NewRootCommand()
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		var exit *exitError
		if errors.As(err, &exit) {
			if exit.err != nil {
				fmt.Fprintln(os.Stderr, "debsmith:", exit.err)
			}

			return exit.code
		}

		fmt.Fprintln(os.Stderr, "debsmith:", err)

		return 1
	}

	return 0
}

// NewRootCommand builds the full command tree.
func NewRootCommand() *cobra.Command {
	application := &app{ui: ui.New()}

	root := &cobra.Command{
		Use:   "debsmith",
		Short: "Deterministic Debian packaging, policy linting and signed apt repositories",
		Long: `debsmith builds reproducible Debian/Ubuntu binary packages from a single
debsmith.yaml manifest, audits them against Debian Policy, generates Debian
source packages and publishes signed APT repositories.

Everything is written in pure Go: no dpkg-deb, ar, tar, gzip or gpg binary is
required at build time.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			application.ui.Out = cmd.OutOrStdout()
			application.ui.Err = cmd.ErrOrStderr()

			noColor, err := cmd.Flags().GetBool("no-color")
			if err != nil {
				return err
			}

			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}

			quiet, err := cmd.Flags().GetBool("quiet")
			if err != nil {
				return err
			}

			if noColor {
				application.ui.Color = false
			}

			application.ui.Verbose = verbose
			application.ui.Quiet = quiet

			return nil
		},
	}

	root.PersistentFlags().BoolP("verbose", "v", false, "verbose diagnostics")
	root.PersistentFlags().Bool("no-color", false, "disable ANSI colors")
	root.PersistentFlags().BoolP("quiet", "q", false, "only print results")

	root.AddCommand(
		application.buildCommand(),
		application.inspectCommand(),
		application.lintCommand(),
		application.repoCommand(),
		application.sourceCommand(),
		application.verifyCommand(),
		application.versionCommand(),
	)

	return root
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}

func resolveEpoch(value string) (time.Time, error) {
	if value == "" {
		value = os.Getenv("SOURCE_DATE_EPOCH")
	}

	if value == "" {
		return time.Now().UTC().Truncate(time.Second), nil
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), nil
	}

	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("invalid epoch %q: use unix seconds or RFC3339", value)
}

func humanSize(bytes int64) string {
	const kib = 1024

	switch {
	case bytes < kib:
		return fmt.Sprintf("%d B", bytes)
	case bytes < kib*kib:
		return fmt.Sprintf("%.1f KiB", float64(bytes)/kib)
	case bytes < kib*kib*kib:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/(kib*kib))
	default:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/(kib*kib*kib))
	}
}
