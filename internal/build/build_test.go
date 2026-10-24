// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package build

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Avi6855/debsmith/internal/deb"
)

const testManifest = `
name: demo
version: "1.2.3"
revision: "4"
architecture: all
maintainer: "Avinash Patil <avinash@example.com>"
description: "Demo package for the build pipeline"
extendedDescription: |
  A small package used by the debsmith test suite.
homepage: "https://example.com/demo"
section: utils
priority: optional
license: MIT
root: rootfs
permissions:
  /usr/bin/demo: "0755"
conffiles:
  - /etc/demo/demo.conf
scripts:
  postinst: packaging/postinst
`

var fixedEpoch = time.Unix(1700000000, 0).UTC()

func project(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		"debsmith.yaml":                       testManifest,
		"rootfs/usr/bin/demo":                 "#!/bin/sh\necho demo\n",
		"rootfs/etc/demo/demo.conf":           "enabled=true\n",
		"rootfs/usr/share/doc/demo/copyright": "MIT\n",
		"packaging/postinst":                  "#!/bin/sh\nexit 0\n",
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

func TestRun(t *testing.T) {
	t.Parallel()

	dir := project(t)
	out := t.TempDir()

	result, err := Run(Options{
		ProjectPath: dir,
		Output:      out,
		Epoch:       fixedEpoch,
		SBOM:        true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Package != "demo" || result.Version != "1.2.3-4" {
		t.Fatalf("result = %+v", result)
	}

	if result.Artifact != filepath.Join(out, "demo_1.2.3-4_all.deb") {
		t.Fatalf("artifact = %q", result.Artifact)
	}

	if result.SHA256 == "" || result.Size == 0 || result.Files == 0 {
		t.Fatalf("result = %+v", result)
	}

	if _, err := os.Stat(result.SBOM); err != nil {
		t.Fatalf("SBOM: %v", err)
	}

	archive, err := deb.ReadFile(result.Artifact)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if archive.Control.Package != "demo" {
		t.Fatalf("package = %q", archive.Control.Package)
	}

	if _, ok := archive.File("usr/bin/demo"); !ok {
		t.Fatal("usr/bin/demo missing")
	}

	if audit := archive.AuditMD5(); len(audit.Mismatched) != 0 {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestRunIsDeterministic(t *testing.T) {
	t.Parallel()

	dir := project(t)
	firstDir := t.TempDir()
	secondDir := t.TempDir()

	first, err := Run(Options{ProjectPath: dir, Output: firstDir, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	second, err := Run(Options{ProjectPath: dir, Output: secondDir, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if first.SHA256 != second.SHA256 {
		t.Fatalf("sha256 differs: %s != %s", first.SHA256, second.SHA256)
	}
}

func TestRunExplicitFileOutput(t *testing.T) {
	t.Parallel()

	dir := project(t)
	target := filepath.Join(t.TempDir(), "custom.deb")

	result, err := Run(Options{ProjectPath: dir, Output: target, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Artifact != target {
		t.Fatalf("artifact = %q", result.Artifact)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsMissingProject(t *testing.T) {
	t.Parallel()

	if _, err := Run(Options{ProjectPath: t.TempDir(), Epoch: fixedEpoch}); err == nil {
		t.Fatal("expected an error")
	}
}
