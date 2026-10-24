// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package aptrepo builds signed, deterministic flat APT repositories.
package aptrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Avi6855/debsmith/internal/deb"
)

// Options configures repository generation.
type Options struct {
	Dir           string
	Suite         string
	Codename      string
	Component     string
	Origin        string
	Label         string
	Description   string
	Architectures []string
	Epoch         time.Time
	Pool          bool
	SigningKey    string
	Passphrase    string
}

// Package is one indexed binary package.
type Package struct {
	Path         string
	Name         string
	Version      string
	Architecture string
	Size         int64
	MD5          string
	SHA1         string
	SHA256       string
	Stanza       []byte
}

// Result reports what was generated.
type Result struct {
	Packages      int
	Architectures []string
	IndexFiles    []string
	ReleasePath   string
	Signed        bool
}

type indexFile struct {
	relative string
	content  []byte
}

// Build scans a directory for .deb files and writes a signed repository.
func Build(options Options) (*Result, error) {
	if options.Dir == "" {
		options.Dir = "."
	}

	root, err := filepath.Abs(options.Dir)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: resolve repository path: %w", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("aptrepo: %s is not a directory", root)
	}

	options.applyDefaults()

	epoch := options.Epoch
	if epoch.IsZero() {
		epoch = time.Now().UTC()
	}

	epoch = epoch.UTC().Truncate(time.Second)

	files, err := findPackages(root)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, errors.New("aptrepo: no .deb files found")
	}

	packages := make([]Package, 0, len(files))
	seen := make(map[string]string, len(files))

	for _, file := range files {
		archive, err := deb.ReadFile(file)
		if err != nil {
			return nil, err
		}

		if archive.Control.Package == "" || archive.Control.Version == "" {
			return nil, fmt.Errorf("aptrepo: %s has no Package or Version", file)
		}

		basename := filepath.Base(file)
		if previous, ok := seen[basename]; ok {
			if previous != archive.SHA256 {
				return nil, fmt.Errorf("aptrepo: conflicting packages named %q", basename)
			}

			continue
		}

		seen[basename] = archive.SHA256

		relative, err := filepath.Rel(root, file)
		if err != nil {
			return nil, err
		}

		relative = filepath.ToSlash(relative)

		if options.Pool {
			relative = filepath.ToSlash(poolPath(options.Component,
				archive.Control.Package, basename))

			if err := copyPackage(file, filepath.Join(root, filepath.FromSlash(relative))); err != nil {
				return nil, err
			}
		}

		stanza := packageStanza(archive, relative)

		packages = append(packages, Package{
			Path:         relative,
			Name:         archive.Control.Package,
			Version:      archive.Control.Version,
			Architecture: archive.Control.Architecture,
			Size:         archive.Size,
			MD5:          archive.MD5,
			SHA1:         archive.SHA1,
			SHA256:       archive.SHA256,
			Stanza:       stanza,
		})
	}

	architectures := resolveArchitectures(packages, options.Architectures)

	indexes, err := buildIndexes(root, options, packages, architectures)
	if err != nil {
		return nil, err
	}

	releasePath, signed, err := writeRelease(root, options, indexes, architectures, epoch)
	if err != nil {
		return nil, err
	}

	indexPaths := make([]string, 0, len(indexes))
	for _, index := range indexes {
		indexPaths = append(indexPaths, index.relative)
	}

	return &Result{
		Packages:      len(packages),
		Architectures: architectures,
		IndexFiles:    indexPaths,
		ReleasePath:   releasePath,
		Signed:        signed,
	}, nil
}

func (o *Options) applyDefaults() {
	if o.Suite == "" {
		o.Suite = "stable"
	}

	if o.Codename == "" {
		o.Codename = o.Suite
	}

	if o.Component == "" {
		o.Component = "main"
	}

	if o.Origin == "" {
		o.Origin = "DebSmith"
	}

	if o.Label == "" {
		o.Label = o.Origin
	}

	if o.Description == "" {
		o.Description = o.Origin + " package repository"
	}
}

func findPackages(root string) ([]string, error) {
	var candidates []string

	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			if current != root && (entry.Name() == ".git" || entry.Name() == "dists") {
				return filepath.SkipDir
			}

			return nil
		}

		if strings.EqualFold(filepath.Ext(current), ".deb") {
			candidates = append(candidates, current)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("aptrepo: scan repository: %w", err)
	}

	sort.Strings(candidates)

	return candidates, nil
}

func poolPath(component, name, filename string) string {
	prefix := name

	switch {
	case len(name) >= 4 && strings.HasPrefix(name, "lib"):
		prefix = name[:4]
	case name != "":
		prefix = name[:1]
	}

	return filepath.Join("pool", component, prefix, name, filename)
}

func copyPackage(source, destination string) error {
	if filepath.Clean(source) == filepath.Clean(destination) {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("aptrepo: create pool directory: %w", err)
	}

	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("aptrepo: open %s: %w", source, err)
	}
	defer input.Close()

	temporary, err := os.CreateTemp(filepath.Dir(destination), ".debsmith-pool-*")
	if err != nil {
		return fmt.Errorf("aptrepo: create pool file: %w", err)
	}

	name := temporary.Name()

	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(name)
	}

	if _, err := io.Copy(temporary, input); err != nil {
		cleanup()

		return fmt.Errorf("aptrepo: copy %s: %w", source, err)
	}

	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)

		return fmt.Errorf("aptrepo: close pool file: %w", err)
	}

	if err := os.Chmod(name, 0o644); err != nil {
		_ = os.Remove(name)

		return fmt.Errorf("aptrepo: chmod pool file: %w", err)
	}

	// os.Rename cannot replace an existing file on Windows; remove first.
	if err := os.Remove(destination); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = os.Remove(name)

		return fmt.Errorf("aptrepo: replace %s: %w", destination, err)
	}

	if err := os.Rename(name, destination); err != nil {
		_ = os.Remove(name)

		return fmt.Errorf("aptrepo: install %s: %w", destination, err)
	}

	return nil
}

func packageStanza(archive *deb.Archive, relative string) []byte {
	fields := archive.Control.Fields()

	fields.Set("Filename", "./"+relative)
	fields.Set("Size", strconv.FormatInt(archive.Size, 10))
	fields.Set("MD5sum", archive.MD5)
	fields.Set("SHA1", archive.SHA1)
	fields.Set("SHA256", archive.SHA256)

	return fields.Render()
}

func resolveArchitectures(packages []Package, requested []string) []string {
	found := make(map[string]bool)

	for _, pkg := range packages {
		if pkg.Architecture != "" && pkg.Architecture != "all" {
			found[pkg.Architecture] = true
		}
	}

	for _, architecture := range requested {
		if architecture != "" {
			found[architecture] = true
		}
	}

	architectures := make([]string, 0, len(found))
	for architecture := range found {
		architectures = append(architectures, architecture)
	}

	sort.Strings(architectures)

	if len(architectures) == 0 {
		architectures = []string{"all"}
	}

	return architectures
}

func buildIndexes(root string, options Options, packages []Package,
	architectures []string,
) ([]indexFile, error) {
	dists := filepath.Join(root, "dists", options.Suite)
	if err := os.RemoveAll(dists); err != nil {
		return nil, fmt.Errorf("aptrepo: clean dists: %w", err)
	}

	indexes := make([]indexFile, 0, len(architectures)*2)

	for _, architecture := range architectures {
		selected := make([]Package, 0, len(packages))

		for _, pkg := range packages {
			if architecture == "all" {
				if pkg.Architecture == "all" {
					selected = append(selected, pkg)
				}

				continue
			}

			if pkg.Architecture == architecture || pkg.Architecture == "all" {
				selected = append(selected, pkg)
			}
		}

		sort.Slice(selected, func(i, j int) bool {
			if selected[i].Name != selected[j].Name {
				return selected[i].Name < selected[j].Name
			}

			return deb.CompareVersions(selected[i].Version, selected[j].Version) < 0
		})

		var packagesFile bytes.Buffer

		for _, pkg := range selected {
			packagesFile.Write(pkg.Stanza)
			packagesFile.WriteByte('\n')
		}

		relative := filepath.ToSlash(filepath.Join(
			options.Component, "binary-"+architecture, "Packages"))

		compressed, err := gzipBytes(packagesFile.Bytes())
		if err != nil {
			return nil, err
		}

		indexes = append(indexes,
			indexFile{relative: relative, content: packagesFile.Bytes()},
			indexFile{relative: relative + ".gz", content: compressed},
		)
	}

	for _, index := range indexes {
		full := filepath.Join(dists, filepath.FromSlash(index.relative))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, fmt.Errorf("aptrepo: create index directory: %w", err)
		}

		if err := os.WriteFile(full, index.content, 0o644); err != nil {
			return nil, fmt.Errorf("aptrepo: write %s: %w", index.relative, err)
		}
	}

	return indexes, nil
}

func writeRelease(root string, options Options, indexes []indexFile,
	architectures []string, epoch time.Time,
) (string, bool, error) {
	release := renderRelease(options, indexes, architectures, epoch)

	dists := filepath.Join(root, "dists", options.Suite)
	releasePath := filepath.Join(dists, "Release")

	if err := os.WriteFile(releasePath, release, 0o644); err != nil {
		return "", false, fmt.Errorf("aptrepo: write Release: %w", err)
	}

	inRelease, detached, err := Sign(release, options.SigningKey, options.Passphrase, epoch)
	if err != nil {
		return "", false, err
	}

	if inRelease == nil {
		return releasePath, false, nil
	}

	if err := os.WriteFile(filepath.Join(dists, "InRelease"), inRelease, 0o644); err != nil {
		return "", false, fmt.Errorf("aptrepo: write InRelease: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dists, "Release.gpg"), detached, 0o644); err != nil {
		return "", false, fmt.Errorf("aptrepo: write Release.gpg: %w", err)
	}

	return releasePath, true, nil
}

func renderRelease(options Options, indexes []indexFile, architectures []string,
	epoch time.Time,
) []byte {
	var builder strings.Builder

	fmt.Fprintf(&builder, "Origin: %s\n", options.Origin)
	fmt.Fprintf(&builder, "Label: %s\n", options.Label)
	fmt.Fprintf(&builder, "Suite: %s\n", options.Suite)
	fmt.Fprintf(&builder, "Codename: %s\n", options.Codename)
	fmt.Fprintf(&builder, "Date: %s\n", epoch.Format("Mon, 02 Jan 2006 15:04:05 UTC"))
	fmt.Fprintf(&builder, "Architectures: %s\n", strings.Join(architectures, " "))
	fmt.Fprintf(&builder, "Components: %s\n", options.Component)
	fmt.Fprintf(&builder, "Description: %s\n", options.Description)

	blocks := []struct {
		title string
		hash  func([]byte) string
	}{
		{"MD5Sum", func(data []byte) string {
			sum := md5.Sum(data)
			return hex.EncodeToString(sum[:])
		}},
		{"SHA1", func(data []byte) string {
			sum := sha1.Sum(data)
			return hex.EncodeToString(sum[:])
		}},
		{"SHA256", func(data []byte) string {
			sum := sha256.Sum256(data)
			return hex.EncodeToString(sum[:])
		}},
	}

	for _, block := range blocks {
		fmt.Fprintf(&builder, "%s:\n", block.title)

		sorted := append([]indexFile(nil), indexes...)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].relative < sorted[j].relative
		})

		for _, index := range sorted {
			fmt.Fprintf(&builder, " %s %d %s\n",
				block.hash(index.content), len(index.content), index.relative)
		}
	}

	return []byte(builder.String())
}

func gzipBytes(data []byte) ([]byte, error) {
	var buffer bytes.Buffer

	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: create gzip writer: %w", err)
	}

	writer.Header = gzip.Header{OS: 255}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("aptrepo: compress index: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("aptrepo: finish index: %w", err)
	}

	return buffer.Bytes(), nil
}
