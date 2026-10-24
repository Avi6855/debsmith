// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Avi6855/debsmith/internal/deb"
)

func (a *app) inspectCommand() *cobra.Command {
	var (
		jsonOutput bool
		contents   bool
		verify     bool
	)

	command := &cobra.Command{
		Use:   "inspect <package.deb>",
		Short: "Inspect control metadata, archive members and payload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive, err := deb.ReadFile(args[0])
			if err != nil {
				return err
			}

			audit := archive.AuditMD5()
			problems := len(audit.Mismatched) + len(audit.MissingSums) + len(audit.MissingFiles)

			if jsonOutput {
				payload := map[string]any{
					"archive": archive,
					"audit":   audit,
				}

				if err := writeJSON(cmd.OutOrStdout(), payload); err != nil {
					return err
				}
			} else {
				a.renderInspection(cmd.OutOrStdout(), archive, contents)
			}

			if verify {
				if problems == 0 {
					a.ui.Success("checksums verified")
				} else {
					a.ui.Error("checksum verification failed: %d problem(s)", problems)
				}
			}

			if verify && problems > 0 {
				return &exitError{code: 1}
			}

			return nil
		},
	}

	command.Flags().BoolVar(&jsonOutput, "json", false, "print machine readable JSON")
	command.Flags().BoolVar(&contents, "contents", false, "list every payload entry")
	command.Flags().BoolVar(&verify, "verify", false, "verify md5sums and exit non-zero on mismatch")

	return command
}

func (a *app) renderInspection(w io.Writer, archive *deb.Archive, contents bool) {
	a.ui.Step("Inspecting %s", archive.Control.Package)

	fmt.Fprintf(w, "  format:        debian-binary %s", archive.DebianBinary)
	fmt.Fprintf(w, "  control:       %s\n", archive.ControlCompression)
	fmt.Fprintf(w, "  data:          %s\n", archive.DataCompression)
	fmt.Fprintf(w, "  size:          %s\n", humanSize(archive.Size))
	fmt.Fprintf(w, "  sha256:        %s\n", archive.SHA256)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Control:")

	for _, field := range archive.Fields {
		lines := strings.Split(field.Value, "\n")
		fmt.Fprintf(w, "  %s: %s\n", field.Name, lines[0])

		for _, line := range lines[1:] {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}

	fmt.Fprintf(w, "\nMembers (%d):\n", len(archive.Members))
	for _, member := range archive.Members {
		fmt.Fprintf(w, "  %-20s %10d  %s\n", member.Name, member.Size,
			humanSize(member.Size))
	}

	if contents {
		fmt.Fprintf(w, "\nPayload (%d entries):\n", len(archive.Entries))

		for _, entry := range archive.Entries {
			fmt.Fprintf(w, "  %s %10d  %s", displayMode(entry), entry.Size, entry.Path)

			if entry.Link != "" {
				fmt.Fprintf(w, " -> %s", entry.Link)
			}

			fmt.Fprintln(w)
		}
	} else {
		files := 0

		for _, entry := range archive.Entries {
			if !entry.IsDir {
				files++
			}
		}

		fmt.Fprintf(w, "\nPayload: %d files, %d directories\n", files,
			len(archive.Entries)-files)
	}

	if len(archive.Conffiles) > 0 {
		fmt.Fprintln(w, "\nConffiles:")
		for _, conffile := range archive.Conffiles {
			fmt.Fprintf(w, "  %s\n", conffile)
		}
	}

	if len(archive.Scripts) > 0 {
		fmt.Fprintln(w, "\nMaintainer scripts:")
		for name, script := range archive.Scripts {
			fmt.Fprintf(w, "  %s (%04o, %d bytes)\n", name, script.Mode, len(script.Data))
		}
	}
}

func displayMode(entry deb.Entry) string {
	switch {
	case entry.IsDir:
		return "d" + entry.Mode.Perm().String()[1:]
	case entry.Link != "":
		return "l" + entry.Mode.Perm().String()[1:]
	default:
		return entry.Mode.Perm().String()
	}
}
