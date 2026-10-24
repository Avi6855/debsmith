// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Avi6855/debsmith/internal/deb"
)

func sum(value string) string {
	digest := md5.Sum([]byte(value))

	return hex.EncodeToString(digest[:])
}

func cleanArchive() *deb.Archive {
	return &deb.Archive{
		Control: deb.Control{
			Package:       "hello",
			Version:       "1.0.0-1",
			Architecture:  "amd64",
			Maintainer:    "Avinash Patil <avinash@example.com>",
			InstalledSize: 4,
			Section:       "utils",
			Priority:      "optional",
			Description:   "Minimal hello utility",
			Extended:      "A tiny example package used by the test suite.",
		},
		Entries: []deb.Entry{
			{Path: "usr/bin/hello", Mode: 0o755, Size: 4, MD5: sum("binary")},
			{Path: "usr/share/doc/hello/copyright", Mode: 0o644, Size: 4, MD5: sum("license")},
			{Path: "usr/share/doc/hello/changelog.gz", Mode: 0o644, Size: 4, MD5: sum("changes")},
		},
		MD5Sums: map[string]string{
			"usr/bin/hello":                    sum("binary"),
			"usr/share/doc/hello/copyright":    sum("license"),
			"usr/share/doc/hello/changelog.gz": sum("changes"),
		},
		Scripts: map[string]deb.Script{
			"postinst": {Data: []byte("#!/bin/sh\nexit 0\n"), Mode: 0o755},
		},
	}
}

func codes(report Report) map[string]bool {
	out := make(map[string]bool, len(report.Findings))

	for _, item := range report.Findings {
		out[item.Code] = true
	}

	return out
}

func TestCleanPackage(t *testing.T) {
	t.Parallel()

	report := Lint(cleanArchive(), "hello.deb")

	if len(report.Findings) != 0 {
		t.Fatalf("expected a clean report, got:\n%s", report.FormatText())
	}

	if report.FailOn("error") || report.FailOn("warning") {
		t.Fatal("clean package must not fail thresholds")
	}
}

func TestChecksTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   string
		mutate func(*deb.Archive)
	}{
		{
			name: "invalid name",
			code: "DSM002",
			mutate: func(a *deb.Archive) {
				a.Control.Package = "Bad Name"
			},
		},
		{
			name: "invalid version",
			code: "DSM003",
			mutate: func(a *deb.Archive) {
				a.Control.Version = "broken version"
			},
		},
		{
			name: "unknown architecture",
			code: "DSM004",
			mutate: func(a *deb.Archive) {
				a.Control.Architecture = "sparc128"
			},
		},
		{
			name: "bad maintainer",
			code: "DSM005",
			mutate: func(a *deb.Archive) {
				a.Control.Maintainer = "Nobody"
			},
		},
		{
			name: "long synopsis",
			code: "DSM006",
			mutate: func(a *deb.Archive) {
				a.Control.Description = strings.Repeat("x", 81)
			},
		},
		{
			name: "empty package",
			code: "DSM008",
			mutate: func(a *deb.Archive) {
				a.Entries = nil
				a.MD5Sums = nil
			},
		},
		{
			name: "setuid",
			code: "DSM009",
			mutate: func(a *deb.Archive) {
				a.Entries[0].Mode = 0o4755
			},
		},
		{
			name: "world writable",
			code: "DSM010",
			mutate: func(a *deb.Archive) {
				a.Entries[0].Mode = 0o777
			},
		},
		{
			name: "usr local",
			code: "DSM011",
			mutate: func(a *deb.Archive) {
				a.Entries = append(a.Entries, deb.Entry{Path: "usr/local/bin/x"})
			},
		},
		{
			name: "missing md5sums",
			code: "DSM014",
			mutate: func(a *deb.Archive) {
				a.MD5Sums = nil
			},
		},
		{
			name: "md5 mismatch",
			code: "DSM015",
			mutate: func(a *deb.Archive) {
				a.Entries[0].MD5 = sum("different")
			},
		},
		{
			name: "conffile missing",
			code: "DSM017",
			mutate: func(a *deb.Archive) {
				a.Conffiles = []string{"/etc/hello/missing.conf"}
			},
		},
		{
			name: "conffile outside etc",
			code: "DSM018",
			mutate: func(a *deb.Archive) {
				a.Conffiles = []string{"/usr/share/hello.conf"}
				a.Entries = append(a.Entries, deb.Entry{
					Path: "usr/share/hello.conf", Mode: 0o644, MD5: sum("config"),
				})
				a.MD5Sums["usr/share/hello.conf"] = sum("config")
			},
		},
		{
			name: "script not executable",
			code: "DSM019",
			mutate: func(a *deb.Archive) {
				a.Scripts["postinst"] = deb.Script{
					Data: []byte("#!/bin/sh\n"), Mode: 0o644,
				}
			},
		},
		{
			name: "script without shebang",
			code: "DSM020",
			mutate: func(a *deb.Archive) {
				a.Scripts["postinst"] = deb.Script{Data: []byte("exit 0\n"), Mode: 0o755}
			},
		},
		{
			name: "missing copyright",
			code: "DSM021",
			mutate: func(a *deb.Archive) {
				a.Entries = append(a.Entries[:1], a.Entries[2:]...)
			},
		},
		{
			name: "non root owner",
			code: "DSM023",
			mutate: func(a *deb.Archive) {
				a.Entries[0].UID = 1000
			},
		},
		{
			name: "broken symlink",
			code: "DSM024",
			mutate: func(a *deb.Archive) {
				a.Entries = append(a.Entries, deb.Entry{
					Path: "usr/bin/hi", Link: "../../etc/passwd", Typeflag: 0x32,
				})
			},
		},
		{
			name: "unknown section",
			code: "DSM025",
			mutate: func(a *deb.Archive) {
				a.Control.Section = "nonsense"
			},
		},
		{
			name: "unknown priority",
			code: "DSM026",
			mutate: func(a *deb.Archive) {
				a.Control.Priority = "urgent"
			},
		},
		{
			name: "self dependency",
			code: "DSM028",
			mutate: func(a *deb.Archive) {
				a.Control.Depends = []string{"hello (>= 1.0)"}
			},
		},
		{
			name: "unknown control member",
			code: "DSM030",
			mutate: func(a *deb.Archive) {
				a.ControlFiles = map[string]deb.Script{
					"evil": {Data: []byte("x"), Mode: 0o644},
				}
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			archive := cleanArchive()
			test.mutate(archive)

			report := Lint(archive, "hello.deb")

			if !codes(report)[test.code] {
				t.Fatalf("expected %s, got:\n%s", test.code, report.FormatText())
			}
		})
	}
}

func TestFailOn(t *testing.T) {
	t.Parallel()

	report := Report{Errors: 1, Warnings: 1, Infos: 1}

	if !report.FailOn("error") || !report.FailOn("warning") || !report.FailOn("info") {
		t.Fatal("thresholds should fail")
	}

	if report.FailOn("never") {
		t.Fatal("never must not fail")
	}

	clean := Report{}
	if clean.FailOn("warning") || clean.FailOn("info") {
		t.Fatal("clean report must not fail")
	}
}

func TestSARIF(t *testing.T) {
	t.Parallel()

	report := Lint(cleanArchive(), "hello.deb")

	var buffer bytes.Buffer

	if err := report.WriteSARIF(&buffer, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var decoded struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid sarif json: %v", err)
	}

	if decoded.Version != "2.1.0" {
		t.Fatalf("version = %q", decoded.Version)
	}

	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Tool.Driver.Rules) != len(CheckInfos()) {
		t.Fatalf("rules = %d", len(decoded.Runs[0].Tool.Driver.Rules))
	}
}

func TestFormatText(t *testing.T) {
	t.Parallel()

	report := Lint(cleanArchive(), "hello.deb")

	if !strings.Contains(report.FormatText(), "0 error(s), 0 warning(s), 0 info(s)") {
		t.Fatalf("unexpected text:\n%s", report.FormatText())
	}
}
