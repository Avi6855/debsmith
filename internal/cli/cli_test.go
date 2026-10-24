// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliManifest = `
name: cli-demo
version: "1.0.0"
architecture: all
maintainer: "Avinash Patil <avinash@example.com>"
description: "CLI fixture"
root: rootfs
permissions:
  /usr/bin/cli-demo: "0755"
`

func project(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		"debsmith.yaml":                           cliManifest,
		"rootfs/usr/bin/cli-demo":                 "#!/bin/sh\necho cli\n",
		"rootfs/usr/share/doc/cli-demo/copyright": "MIT\n",
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

func TestBuildInspectLint(t *testing.T) {
	dir := project(t)
	out := t.TempDir()

	root := NewRootCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"build", dir, "-o", out, "--epoch", "1700000000", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("build: %v\n%s", err, stdout.String())
	}

	var result struct {
		Artifact string `json:"artifact"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("build JSON: %v\n%s", err, stdout.String())
	}

	if _, err := os.Stat(result.Artifact); err != nil {
		t.Fatal(err)
	}

	root = NewRootCommand()
	stdout.Reset()
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"lint", result.Artifact, "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("lint: %v\n%s", err, stdout.String())
	}

	if !strings.Contains(stdout.String(), `"package": "cli-demo"`) {
		t.Fatalf("lint JSON:\n%s", stdout.String())
	}

	root = NewRootCommand()
	stdout.Reset()
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"inspect", result.Artifact, "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("inspect: %v\n%s", err, stdout.String())
	}

	if !strings.Contains(stdout.String(), `"Package": "cli-demo"`) {
		t.Fatalf("inspect JSON:\n%s", stdout.String())
	}
}

func TestLintSARIF(t *testing.T) {
	dir := project(t)
	out := t.TempDir()

	buildRoot := NewRootCommand()
	buildRoot.SetArgs([]string{"build", dir, "-o", out, "--epoch", "1700000000"})
	buildRoot.SetOut(&bytes.Buffer{})
	buildRoot.SetErr(&bytes.Buffer{})

	if err := buildRoot.Execute(); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join(out, "cli-demo_1.0.0-1_all.deb")

	root := NewRootCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"lint", artifact, "--sarif"})

	if err := root.Execute(); err != nil {
		t.Fatalf("lint: %v", err)
	}

	if !strings.Contains(stdout.String(), `"version": "2.1.0"`) {
		t.Fatalf("SARIF:\n%s", stdout.String())
	}
}

func TestLintListChecks(t *testing.T) {
	root := NewRootCommand()

	var stdout bytes.Buffer

	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"lint", "--list-checks"})

	if err := root.Execute(); err != nil {
		t.Fatalf("lint --list-checks: %v", err)
	}

	if !strings.Contains(stdout.String(), "DSM001") ||
		!strings.Contains(stdout.String(), "30 checks") {
		t.Fatalf("output:\n%s", stdout.String())
	}
}

func TestLintMissingFile(t *testing.T) {
	if code := Execute([]string{"lint", filepath.Join(t.TempDir(), "missing.deb")}); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestVersionCommand(t *testing.T) {
	root := NewRootCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout.String(), "debsmith") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestResolveEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	epoch, err := resolveEpoch("")
	if err != nil || epoch.Unix() != 1700000000 {
		t.Fatalf("epoch = %v, %v", epoch, err)
	}

	epoch, err = resolveEpoch("2023-11-14T22:13:20Z")
	if err != nil || epoch.Unix() != 1700000000 {
		t.Fatalf("epoch = %v, %v", epoch, err)
	}

	if _, err := resolveEpoch("yesterday"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestHumanSize(t *testing.T) {
	if humanSize(512) != "512 B" || humanSize(2048) != "2.0 KiB" {
		t.Fatal("unexpected formatting")
	}
}
