// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package build wires the manifest, staging, writer and SBOM stages together.
package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Avi6855/debsmith/internal/deb"
	"github.com/Avi6855/debsmith/internal/manifest"
	"github.com/Avi6855/debsmith/internal/sbom"
)

// Options configures one binary package build.
type Options struct {
	ProjectPath        string
	Output             string
	Epoch              time.Time
	Compression        string
	ControlCompression string
	SBOM               bool
}

// Result describes a finished build.
type Result struct {
	Artifact      string `json:"artifact"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Files         int    `json:"files"`
	InstalledSize int64  `json:"installedSize"`
	Epoch         int64  `json:"epoch"`
	SBOM          string `json:"sbom,omitempty"`
}

// Run executes the complete binary package pipeline.
func Run(options Options) (*Result, error) {
	project := options.ProjectPath
	if project == "" {
		project = "."
	}

	parsed, err := manifest.Load(project)
	if err != nil {
		return nil, err
	}

	files, err := parsed.Stage()
	if err != nil {
		return nil, err
	}

	compressionValue := options.Compression
	if compressionValue == "" {
		compressionValue = parsed.Compression
	}

	controlCompressionValue := options.ControlCompression
	if controlCompressionValue == "" {
		controlCompressionValue = parsed.ControlCompression
	}

	compression, err := deb.ParseCompression(compressionValue)
	if err != nil {
		return nil, err
	}

	controlCompression, err := deb.ParseCompression(controlCompressionValue)
	if err != nil {
		return nil, err
	}

	epoch := options.Epoch
	if epoch.IsZero() {
		epoch = time.Now()
	}

	epoch = epoch.UTC().Truncate(time.Second)

	pkg := &deb.Package{
		Control:      parsed.Control(),
		Files:        files,
		Conffiles:    parsed.Conffiles,
		Scripts:      parsed.StagedScripts(),
		ControlFiles: parsed.StagedControlFiles(),
	}

	artifact := resolveOutput(parsed, options.Output)

	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		return nil, fmt.Errorf("build: create output directory: %w", err)
	}

	summary, err := writeArtifact(artifact, pkg, deb.Options{
		Compression:        compression,
		ControlCompression: controlCompression,
		Epoch:              epoch,
	})
	if err != nil {
		return nil, err
	}

	digest, size, err := fileDigest(artifact)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Artifact:      artifact,
		Package:       parsed.Name,
		Version:       parsed.VersionString(),
		Architecture:  parsed.Architecture,
		SHA256:        digest,
		Size:          size,
		Files:         summary.Files,
		InstalledSize: summary.InstalledSize,
		Epoch:         epoch.Unix(),
	}

	if options.SBOM {
		archive, err := deb.ReadFile(artifact)
		if err != nil {
			return nil, err
		}

		document, err := sbom.Generate(archive, filepath.Base(artifact), epoch)
		if err != nil {
			return nil, err
		}

		sbomPath := artifact + ".cdx.json"
		if err := os.WriteFile(sbomPath, document, 0o644); err != nil {
			return nil, fmt.Errorf("build: write SBOM: %w", err)
		}

		result.SBOM = sbomPath
	}

	return result, nil
}

func resolveOutput(parsed *manifest.Manifest, output string) string {
	if output == "" {
		return filepath.Join(parsed.Dir(), "dist", parsed.ArtifactName())
	}

	info, err := os.Stat(output)
	if err == nil && info.IsDir() {
		return filepath.Join(output, parsed.ArtifactName())
	}

	if strings.EqualFold(filepath.Ext(output), ".deb") {
		return output
	}

	return filepath.Join(output, parsed.ArtifactName())
}

func writeArtifact(path string, pkg *deb.Package, options deb.Options) (deb.Summary, error) {
	var summary deb.Summary

	directory := filepath.Dir(path)

	temporary, err := os.CreateTemp(directory, ".debsmith-build-*")
	if err != nil {
		return summary, fmt.Errorf("build: create temporary artifact: %w", err)
	}

	name := temporary.Name()

	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}

	summary, err = deb.Write(temporary, pkg, options)
	if err != nil {
		cleanup()

		return summary, err
	}

	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)

		return summary, fmt.Errorf("build: close artifact: %w", err)
	}

	// os.Rename cannot replace an existing file on Windows.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(name)

		return summary, fmt.Errorf("build: replace %s: %w", path, err)
	}

	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)

		return summary, fmt.Errorf("build: install %s: %w", path, err)
	}

	return summary, nil
}

func fileDigest(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("build: open artifact: %w", err)
	}
	defer file.Close()

	hash := sha256.New()

	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("build: hash artifact: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
