// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package repro

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Avi6855/debsmith/internal/build"
)

const reproManifest = `
name: repro
version: "1.0.0"
architecture: all
maintainer: "Avinash Patil <avinash@example.com>"
description: "Reproducibility fixture"
root: rootfs
permissions:
  /usr/bin/repro: "0755"
`

func project(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		"debsmith.yaml":        reproManifest,
		"rootfs/usr/bin/repro": "#!/bin/sh\necho repro\n",
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

func TestVerify(t *testing.T) {
	t.Parallel()

	result, err := Verify(Options{
		ProjectPath: project(t),
		Epoch:       time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.Reproducible {
		t.Fatalf("expected reproducible: %+v", result)
	}

	if result.FirstSHA256 != result.SecondSHA256 || result.Size == 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestCompareDifferentEpochs(t *testing.T) {
	t.Parallel()

	dir := project(t)
	firstDir := t.TempDir()
	secondDir := t.TempDir()

	first, err := build.Run(build.Options{
		ProjectPath: dir, Output: firstDir,
		Epoch: time.Unix(1700000000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	second, err := build.Run(build.Options{
		ProjectPath: dir, Output: secondDir,
		Epoch: time.Unix(1700000100, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compare(first.Artifact, second.Artifact)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	if result.Reproducible {
		t.Fatal("different epochs must not be reproducible")
	}

	if len(result.Differences) == 0 {
		t.Fatal("expected differences")
	}
}

func TestCompareIdentical(t *testing.T) {
	t.Parallel()

	dir := project(t)
	firstDir := t.TempDir()
	secondDir := t.TempDir()
	epoch := time.Unix(1700000000, 0).UTC()

	first, err := build.Run(build.Options{ProjectPath: dir, Output: firstDir, Epoch: epoch})
	if err != nil {
		t.Fatal(err)
	}

	second, err := build.Run(build.Options{ProjectPath: dir, Output: secondDir, Epoch: epoch})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compare(first.Artifact, second.Artifact)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Reproducible || len(result.Differences) != 0 {
		t.Fatalf("result = %+v", result)
	}
}
