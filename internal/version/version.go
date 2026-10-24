// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package version holds build-time metadata injected through -ldflags.
package version

import (
	"runtime"
	"runtime/debug"
)

// These variables are overridden at build time:
//
//	-ldflags "-X github.com/Avi6855/debsmith/internal/version.Version=..."
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info describes the running binary.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Current returns the build information of this binary.
func Current() Info {
	commit := Commit
	if commit == "none" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					commit = s.Value
				}
			}
		}
	}

	return Info{
		Version: Version,
		Commit:  commit,
		Date:    Date,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}
