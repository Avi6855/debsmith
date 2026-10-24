// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package ui renders small, dependency-free terminal messages.
package ui

import (
	"fmt"
	"io"
	"os"
)

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

// UI writes human readable progress and diagnostics.
type UI struct {
	Out     io.Writer
	Err     io.Writer
	Color   bool
	Quiet   bool
	Verbose bool
}

// New returns a UI bound to stdout and stderr.
func New() *UI {
	return &UI{
		Out:   os.Stdout,
		Err:   os.Stderr,
		Color: colorEnabled(),
	}
}

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeCharDevice != 0
}

func (u *UI) paint(color, format string, args ...any) string {
	msg := fmt.Sprintf(format, args...)
	if !u.Color {
		return msg
	}

	return color + msg + reset
}

// Step prints a top-level step.
func (u *UI) Step(format string, args ...any) {
	if u.Quiet {
		return
	}
	fmt.Fprintln(u.Out, u.paint(bold+cyan, "==> "+format, args...))
}

// Success prints a successful result.
func (u *UI) Success(format string, args ...any) {
	if u.Quiet {
		return
	}
	fmt.Fprintln(u.Out, u.paint(green, "  ✓ "+format, args...))
}

// Info prints an informational line.
func (u *UI) Info(format string, args ...any) {
	if u.Quiet {
		return
	}
	fmt.Fprintln(u.Out, u.paint(gray, "  • "+format, args...))
}

// Detail prints an indented detail line.
func (u *UI) Detail(format string, args ...any) {
	if u.Quiet {
		return
	}
	fmt.Fprintln(u.Out, u.paint(gray, "    "+format, args...))
}

// Warn prints a warning to stderr.
func (u *UI) Warn(format string, args ...any) {
	if u.Quiet {
		return
	}
	fmt.Fprintln(u.Err, u.paint(yellow, "  ! "+format, args...))
}

// Error prints an error to stderr.
func (u *UI) Error(format string, args ...any) {
	fmt.Fprintln(u.Err, u.paint(red, "  ✗ "+format, args...))
}

// Debug prints a line only in verbose mode.
func (u *UI) Debug(format string, args ...any) {
	if !u.Verbose || u.Quiet {
		return
	}
	fmt.Fprintln(u.Err, u.paint(gray, "    · "+format, args...))
}

// Raw prints unadorned text to stdout.
func (u *UI) Raw(format string, args ...any) {
	fmt.Fprintf(u.Out, format, args...)
}
