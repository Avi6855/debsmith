// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProject(t *testing.T, manifestText string, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "debsmith.yaml"), []byte(manifestText), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))

		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

const minimalManifest = `
name: hello
version: "1.2.3"
maintainer: "Avinash Patil <avinash@example.com>"
description: "Minimal hello utility"
`

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	dir := writeProject(t, minimalManifest, nil)

	parsed, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if parsed.VersionString() != "1.2.3-1" {
		t.Fatalf("version = %q", parsed.VersionString())
	}

	if parsed.Section != "utils" || parsed.Priority != "optional" {
		t.Fatalf("defaults = %q/%q", parsed.Section, parsed.Priority)
	}

	if parsed.Compression != "zstd" || parsed.ControlCompression != "gzip" {
		t.Fatalf("compression defaults = %q/%q", parsed.Compression, parsed.ControlCompression)
	}

	if parsed.ArtifactName() != "hello_1.2.3-1_amd64.deb" &&
		parsed.ArtifactName() != "hello_1.2.3-1_arm64.deb" &&
		parsed.ArtifactName() != "hello_1.2.3-1_i386.deb" &&
		parsed.ArtifactName() != "hello_1.2.3-1_armhf.deb" {
		t.Fatalf("artifact name = %q", parsed.ArtifactName())
	}
}

func TestLoadSplitsEmbeddedRevision(t *testing.T) {
	t.Parallel()

	const text = `
name: hello
version: "1.2.3-4"
maintainer: "Avinash Patil <avinash@example.com>"
description: "Minimal hello utility"
`

	parsed, err := Load(writeProject(t, text, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if parsed.Version != "1.2.3" || parsed.Revision != "4" {
		t.Fatalf("version/revision = %q/%q", parsed.Version, parsed.Revision)
	}

	if parsed.VersionString() != "1.2.3-4" {
		t.Fatalf("version string = %q", parsed.VersionString())
	}

	if parsed.UpstreamVersion() != "1.2.3" {
		t.Fatalf("upstream version = %q", parsed.UpstreamVersion())
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	dir := writeProject(t, minimalManifest+"unknownField: true\n", nil)

	if _, err := Load(dir); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		manifest string
		contains string
	}{
		{
			name: "bad name",
			manifest: `
name: Hello World
version: "1.0"
maintainer: "A <a@example.com>"
description: "x"
`,
			contains: "name must be",
		},
		{
			name: "missing maintainer email",
			manifest: `
name: hello
version: "1.0"
maintainer: "Avinash"
description: "x"
`,
			contains: "maintainer must look like",
		},
		{
			name: "version with hyphen and revision",
			manifest: `
name: hello
version: "1.0-1"
revision: "2"
maintainer: "A <a@example.com>"
description: "x"
`,
			contains: "must not contain '-'",
		},
		{
			name: "unsupported script",
			manifest: `
name: hello
version: "1.0"
maintainer: "A <a@example.com>"
description: "x"
scripts:
  evil: packaging/evil
`,
			contains: "unsupported script",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := writeProject(t, test.manifest, nil)

			_, err := Load(dir)
			if err == nil {
				t.Fatal("expected error")
			}

			if !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want %q", err, test.contains)
			}
		})
	}
}

func TestStage(t *testing.T) {
	t.Parallel()

	const text = `
name: hello
version: "1.0"
maintainer: "Avinash Patil <avinash@example.com>"
description: "Minimal hello utility"
files:
  - source: build/hello
    path: /usr/bin/hello
    mode: "0755"
  - source: LICENSE
    path: /usr/share/doc/hello/copyright
directories:
  - path: /var/lib/hello
    mode: "0750"
symlinks:
  - path: /usr/bin/hi
    target: hello
conffiles:
  - /etc/hello/hello.conf
permissions:
  /usr/share/doc/hello/copyright: "0644"
scripts:
  postinst: packaging/postinst
controlFiles:
  triggers: packaging/triggers
root: rootfs
`

	dir := writeProject(t, text, map[string]string{
		"build/hello":                 "#!/bin/sh\necho hello\n",
		"LICENSE":                     "MIT\n",
		"packaging/postinst":          "#!/bin/sh\nexit 0\n",
		"packaging/triggers":          "interest-noawait /usr/share/hello\n",
		"rootfs/etc/hello/hello.conf": "greeting=hello\n",
		"rootfs/usr/share/hello/data": "payload\n",
	})

	parsed, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	files, err := parsed.Stage()
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	index := map[string]bool{}

	for _, file := range files {
		index[file.Path] = true
	}

	for _, expected := range []string{
		"usr/bin/hello",
		"usr/share/doc/hello/copyright",
		"var/lib/hello",
		"usr/bin/hi",
		"etc/hello/hello.conf",
		"usr/share/hello/data",
	} {
		if !index[expected] {
			t.Fatalf("missing staged path %q in %v", expected, index)
		}
	}

	if string(parsed.StagedScripts()["postinst"]) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("postinst = %q", parsed.StagedScripts()["postinst"])
	}

	if _, ok := parsed.StagedControlFiles()["triggers"]; !ok {
		t.Fatal("triggers was not staged")
	}

	for _, file := range files {
		if file.Path == "usr/bin/hello" && file.Mode != 0o755 {
			t.Fatalf("hello mode = %o", file.Mode)
		}

		if file.Path == "var/lib/hello" && (!file.IsDir || file.Mode != 0o750) {
			t.Fatalf("var/lib/hello = %+v", file)
		}

		if file.Path == "usr/bin/hi" && file.Link != "hello" {
			t.Fatalf("symlink = %+v", file)
		}
	}
}

func TestStageRejectsMissingConffile(t *testing.T) {
	t.Parallel()

	const text = `
name: hello
version: "1.0"
maintainer: "A <a@example.com>"
description: "x"
conffiles:
  - /etc/hello/hello.conf
files:
  - source: LICENSE
    path: /usr/share/doc/hello/copyright
`

	dir := writeProject(t, text, map[string]string{"LICENSE": "MIT\n"})

	parsed, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if _, err := parsed.Stage(); err == nil {
		t.Fatal("expected missing conffile error")
	}
}

func TestModeUnmarshal(t *testing.T) {
	t.Parallel()

	const text = `
name: hello
version: "1.0"
maintainer: "A <a@example.com>"
description: "x"
files:
  - source: LICENSE
    path: /usr/share/doc/hello/copyright
    mode: 0755
`

	dir := writeProject(t, text, map[string]string{"LICENSE": "MIT\n"})

	parsed, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if parsed.Files[0].Mode.FileMode() != 0o755 {
		t.Fatalf("mode = %o", parsed.Files[0].Mode.FileMode())
	}
}
