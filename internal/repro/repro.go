// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package repro verifies that two builds of the same manifest are identical.
package repro

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Avi6855/debsmith/internal/build"
	"github.com/Avi6855/debsmith/internal/deb"
)

// Options configures a reproducibility run.
type Options struct {
	ProjectPath        string
	Epoch              time.Time
	Compression        string
	ControlCompression string
}

// Result reports whether the builds matched.
type Result struct {
	Reproducible  bool     `json:"reproducible"`
	FirstSHA256   string   `json:"firstSha256"`
	SecondSHA256  string   `json:"secondSha256"`
	Size          int64    `json:"size"`
	Differences   []string `json:"differences,omitempty"`
	FirstArtifact string   `json:"firstArtifact"`
}

// Verify builds the project twice in isolated directories and compares bytes.
func Verify(options Options) (*Result, error) {
	epoch := options.Epoch
	if epoch.IsZero() {
		epoch = time.Now()
	}

	firstDir, err := os.MkdirTemp("", "debsmith-repro-a-*")
	if err != nil {
		return nil, fmt.Errorf("repro: create first workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(firstDir) }()

	secondDir, err := os.MkdirTemp("", "debsmith-repro-b-*")
	if err != nil {
		return nil, fmt.Errorf("repro: create second workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(secondDir) }()

	first, err := build.Run(build.Options{
		ProjectPath:        options.ProjectPath,
		Output:             firstDir,
		Epoch:              epoch,
		Compression:        options.Compression,
		ControlCompression: options.ControlCompression,
	})
	if err != nil {
		return nil, err
	}

	second, err := build.Run(build.Options{
		ProjectPath:        options.ProjectPath,
		Output:             secondDir,
		Epoch:              epoch,
		Compression:        options.Compression,
		ControlCompression: options.ControlCompression,
	})
	if err != nil {
		return nil, err
	}

	result, err := Compare(first.Artifact, second.Artifact)
	if err != nil {
		return nil, err
	}

	result.FirstArtifact = first.Artifact

	return result, nil
}

// Compare inspects two artifacts and lists structural differences.
func Compare(firstPath, secondPath string) (*Result, error) {
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		return nil, fmt.Errorf("repro: read first artifact: %w", err)
	}

	secondBytes, err := os.ReadFile(secondPath)
	if err != nil {
		return nil, fmt.Errorf("repro: read second artifact: %w", err)
	}

	firstArchive, err := deb.ReadFile(firstPath)
	if err != nil {
		return nil, err
	}

	secondArchive, err := deb.ReadFile(secondPath)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Reproducible: bytes.Equal(firstBytes, secondBytes),
		FirstSHA256:  firstArchive.SHA256,
		SecondSHA256: secondArchive.SHA256,
		Size:         int64(len(firstBytes)),
	}

	if result.Reproducible {
		return result, nil
	}

	result.Differences = append(result.Differences,
		structuralDifferences(firstArchive, secondArchive)...)

	if len(result.Differences) == 0 {
		result.Differences = append(result.Differences,
			"archive bytes differ but payload metadata is identical (timestamp or ordering)")
	}

	return result, nil
}

func structuralDifferences(first, second *deb.Archive) []string {
	var differences []string

	if first.Control.Package != second.Control.Package ||
		first.Control.Version != second.Control.Version ||
		first.Control.Architecture != second.Control.Architecture {
		differences = append(differences, "control metadata differs")
	}

	if len(first.Members) != len(second.Members) {
		differences = append(differences, fmt.Sprintf("ar member count %d != %d",
			len(first.Members), len(second.Members)))
	}

	for index := 0; index < len(first.Members) && index < len(second.Members); index++ {
		left, right := first.Members[index], second.Members[index]

		if left.Name != right.Name || left.Size != right.Size {
			differences = append(differences, fmt.Sprintf("ar member %d: %s/%d != %s/%d",
				index, left.Name, left.Size, right.Name, right.Size))
		}
	}

	firstEntries := entryMap(first)
	secondEntries := entryMap(second)

	paths := make([]string, 0, len(firstEntries)+len(secondEntries))
	seen := make(map[string]bool)

	for entryPath := range firstEntries {
		paths = append(paths, entryPath)
		seen[entryPath] = true
	}

	for entryPath := range secondEntries {
		if !seen[entryPath] {
			paths = append(paths, entryPath)
		}
	}

	sort.Strings(paths)

	for _, entryPath := range paths {
		left, leftOK := firstEntries[entryPath]
		right, rightOK := secondEntries[entryPath]

		switch {
		case !leftOK:
			differences = append(differences, "only in second: "+entryPath)
		case !rightOK:
			differences = append(differences, "only in first: "+entryPath)
		case left.Mode != right.Mode:
			differences = append(differences, fmt.Sprintf("%s: mode %04o != %04o",
				entryPath, left.Mode, right.Mode))
		case left.Size != right.Size:
			differences = append(differences, fmt.Sprintf("%s: size %d != %d",
				entryPath, left.Size, right.Size))
		case left.MD5 != right.MD5:
			differences = append(differences, entryPath+": content differs")
		case left.Link != right.Link:
			differences = append(differences, fmt.Sprintf("%s: link %q != %q",
				entryPath, left.Link, right.Link))
		}

		if len(differences) >= 25 {
			differences = append(differences, "further differences suppressed")
			break
		}
	}

	return differences
}

func entryMap(archive *deb.Archive) map[string]deb.Entry {
	entries := make(map[string]deb.Entry, len(archive.Entries))

	for _, entry := range archive.Entries {
		entries[entry.Path] = entry
	}

	return entries
}
