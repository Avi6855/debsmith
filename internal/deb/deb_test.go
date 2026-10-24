// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func testPackage() *Package {
	return &Package{
		Control: Control{
			Package:      "hello",
			Version:      "1.0.0-1",
			Architecture: "amd64",
			Maintainer:   "Avinash Patil <avinash@example.com>",
			Section:      "utils",
			Priority:     "optional",
			Description:  "Minimal hello world utility",
			Extended:     "A tiny example package.\n.\nIt exercises debsmith.",
			Depends:      []string{"libc6 (>= 2.34)"},
		},
		Files: []File{
			{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n")},
			{Path: "usr/share/doc/hello/copyright", Mode: 0o644, Data: []byte("MIT\n")},
			{Path: "etc/hello/hello.conf", Mode: 0o644, Data: []byte("greeting=hello\n")},
			{Path: "usr/bin/hi", Link: "hello"},
			{Path: "var/lib/hello", IsDir: true, Mode: 0o750},
		},
		Conffiles: []string{"/etc/hello/hello.conf"},
		Scripts: map[string][]byte{
			"postinst": []byte("#!/bin/sh\nexit 0\n"),
		},
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	t.Parallel()

	for _, compression := range []Compression{CompressionGzip, CompressionZstd, CompressionXz} {
		t.Run(string(compression), func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			summary, err := Write(&buffer, testPackage(), Options{
				Compression:        compression,
				ControlCompression: CompressionGzip,
				Epoch:              time.Unix(1700000000, 0),
			})
			if err != nil {
				t.Fatalf("Write: %v", err)
			}

			if summary.Files == 0 || summary.InstalledSize == 0 {
				t.Fatalf("unexpected summary: %+v", summary)
			}

			if int64(buffer.Len()) != summary.TotalSize {
				t.Fatalf("summary size %d != archive size %d", summary.TotalSize, buffer.Len())
			}

			archive, err := Read(bytes.NewReader(buffer.Bytes()))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}

			if archive.Control.Package != "hello" {
				t.Fatalf("package = %q", archive.Control.Package)
			}

			if archive.Control.Version != "1.0.0-1" {
				t.Fatalf("version = %q", archive.Control.Version)
			}

			if archive.Control.InstalledSize == 0 {
				t.Fatal("Installed-Size was not computed")
			}

			if archive.DataCompression != compression {
				t.Fatalf("data compression = %q", archive.DataCompression)
			}

			if archive.DebianBinary != "2.0\n" {
				t.Fatalf("debian-binary = %q", archive.DebianBinary)
			}

			wantSum := md5.Sum([]byte("#!/bin/sh\necho hello\n"))
			if archive.MD5Sums["usr/bin/hello"] != hex.EncodeToString(wantSum[:]) {
				t.Fatalf("md5sums = %v", archive.MD5Sums)
			}

			if audit := archive.AuditMD5(); len(audit.Mismatched) != 0 ||
				len(audit.MissingSums) != 0 || len(audit.MissingFiles) != 0 {
				t.Fatalf("md5 audit: %+v", audit)
			}

			if _, ok := archive.Scripts["postinst"]; !ok {
				t.Fatal("postinst script was not preserved")
			}

			if len(archive.Conffiles) != 1 || archive.Conffiles[0] != "/etc/hello/hello.conf" {
				t.Fatalf("conffiles = %v", archive.Conffiles)
			}

			entry, ok := archive.File("usr/bin/hi")
			if !ok || entry.Link != "hello" || entry.Typeflag != 0x32 {
				t.Fatalf("symlink entry = %+v (%v)", entry, ok)
			}

			dir, ok := archive.File("var/lib/hello")
			if !ok || !dir.IsDir || dir.Mode != 0o750 {
				t.Fatalf("directory entry = %+v (%v)", dir, ok)
			}

			if archive.Size != int64(buffer.Len()) {
				t.Fatalf("archive.Size = %d, len = %d", archive.Size, buffer.Len())
			}

			if len(archive.SHA256) != 64 {
				t.Fatalf("sha256 = %q", archive.SHA256)
			}
		})
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	t.Parallel()

	build := func() []byte {
		var buffer bytes.Buffer

		if _, err := Write(&buffer, testPackage(), Options{
			Compression:        CompressionZstd,
			ControlCompression: CompressionGzip,
			Epoch:              time.Unix(1700000000, 0),
		}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		return buffer.Bytes()
	}

	first := build()
	second := build()

	if !bytes.Equal(first, second) {
		t.Fatal("identical inputs produced different archives")
	}
}

func TestWriteRejectsUnsafePaths(t *testing.T) {
	t.Parallel()

	pkg := testPackage()
	pkg.Files = append(pkg.Files, File{Path: "../etc/passwd", Data: []byte("x")})

	if _, err := Write(&bytes.Buffer{}, pkg, Options{}); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestWriteRejectsUnknownScript(t *testing.T) {
	t.Parallel()

	pkg := testPackage()
	pkg.Scripts["evil"] = []byte("#!/bin/sh\n")

	if _, err := Write(&bytes.Buffer{}, pkg, Options{}); err == nil {
		t.Fatal("expected unknown script error")
	}
}

func TestControlRoundTrip(t *testing.T) {
	t.Parallel()

	control := Control{
		Package:      "demo",
		Version:      "2.0-3",
		Architecture: "all",
		Maintainer:   "Demo <demo@example.com>",
		Homepage:     "https://example.com",
		Description:  "Demo package",
		Extended:     "First paragraph.\n.\nSecond paragraph.",
		Depends:      []string{"a (>= 1)"},
	}

	parsed, _, err := ParseControl(control.Render())
	if err != nil {
		t.Fatalf("ParseControl: %v", err)
	}

	if parsed.Description != control.Description {
		t.Fatalf("description = %q", parsed.Description)
	}

	if parsed.Extended != control.Extended {
		t.Fatalf("extended = %q, want %q", parsed.Extended, control.Extended)
	}

	if len(parsed.Depends) != 1 || parsed.Depends[0] != "a (>= 1)" {
		t.Fatalf("depends = %v", parsed.Depends)
	}
}

func TestRelationName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		relation string
		name     string
		version  string
	}{
		{"libc6 (>= 2.38)", "libc6", ">= 2.38"},
		{"foo | bar (>= 1)", "foo", ""},
		{"python3:any", "python3", ""},
		{"zlib1g-dev [amd64]", "zlib1g-dev", ""},
	}

	for _, test := range cases {
		name, version := RelationName(test.relation)
		if name != test.name || version != test.version {
			t.Fatalf("RelationName(%q) = %q, %q", test.relation, name, version)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1:1.0", "2.0", 1},
		{"1.0-2", "1.0-10", -1},
		{"1.0+dfsg", "1.0", 1},
		{"1.0a", "1.0", 1},
		{"1.0.0", "1.0", 1},
	}

	for _, test := range cases {
		if got := CompareVersions(test.a, test.b); got != test.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", test.a, test.b, got, test.want)
		}
	}
}

func TestReadRejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := Read(strings.NewReader("not a deb")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestMD5AuditDetectsMismatch(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	if _, err := Write(&buffer, testPackage(), Options{
		Compression:        CompressionGzip,
		ControlCompression: CompressionGzip,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	archive, err := Read(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	archive.MD5Sums["usr/bin/hello"] = strings.Repeat("0", 32)

	audit := archive.AuditMD5()
	if len(audit.Mismatched) != 1 || audit.Mismatched[0] != "usr/bin/hello" {
		t.Fatalf("audit = %+v", audit)
	}
}
