// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package sourcepkg builds Debian source packages in 3.0 (quilt) format.
package sourcepkg

import (
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/Avi6855/debsmith/internal/aptrepo"
	"github.com/Avi6855/debsmith/internal/manifest"
	"github.com/Avi6855/debsmith/internal/tarutil"
)

// Options configures source package generation.
type Options struct {
	OutDir     string
	Epoch      time.Time
	SigningKey string
	Passphrase string
}

// Result lists the generated files.
type Result struct {
	DSC    string
	Files  []string
	Signed bool
}

type checksum struct {
	Name   string
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string
}

// Build generates an .orig tarball, a .debian tarball and a .dsc file.
func Build(m *manifest.Manifest, options Options) (*Result, error) {
	if strings.TrimSpace(m.Source.Upstream) == "" {
		return nil, fmt.Errorf("source: %s needs source.upstream to point at the upstream tree",
			m.Path)
	}

	epoch := options.Epoch
	if epoch.IsZero() {
		epoch = time.Now()
	}

	epoch = epoch.UTC().Truncate(time.Second)

	base := m.Dir()
	outDir := options.OutDir
	if outDir == "" {
		outDir = filepath.Join(base, "dist")
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("source: create output directory: %w", err)
	}

	upstreamDir := filepath.Join(base, filepath.FromSlash(m.Source.Upstream))

	info, err := os.Stat(upstreamDir)
	if err != nil {
		return nil, fmt.Errorf("source: upstream tree: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("source: upstream %s is not a directory", upstreamDir)
	}

	debianDir := filepath.Join(base, filepath.FromSlash(m.Source.Debian))
	cleanup := func() {}

	if stat, err := os.Stat(debianDir); err != nil || !stat.IsDir() {
		generated, err := generateDebian(m, epoch)
		if err != nil {
			return nil, err
		}

		debianDir = generated
		cleanup = func() { _ = os.RemoveAll(generated) }
	}

	defer cleanup()

	if err := validateDebianDir(debianDir); err != nil {
		return nil, err
	}

	upstreamVersion := m.UpstreamVersion()
	fullVersion := m.VersionString()

	filenameVersion := sanitizeVersion(fullVersion)
	origName := fmt.Sprintf("%s_%s.orig.tar.gz", m.Name, sanitizeVersion(upstreamVersion))
	debianName := fmt.Sprintf("%s_%s.debian.tar.xz", m.Name, filenameVersion)
	dscName := fmt.Sprintf("%s_%s.dsc", m.Name, filenameVersion)

	exclusions := []string{".git", "debian", ".debsmith", "debsmith.yaml", "debsmith.yml"}

	if relative, err := filepath.Rel(upstreamDir, outDir); err == nil &&
		relative != "." && !strings.HasPrefix(relative, "..") {
		exclusions = append(exclusions, filepath.ToSlash(relative))
	}

	origEntries, err := tarutil.CollectDir(upstreamDir, m.Name+"-"+upstreamVersion, tarutil.Options{
		Exclude: exclusions,
	})
	if err != nil {
		return nil, fmt.Errorf("source: collect upstream tree: %w", err)
	}

	origPath := filepath.Join(outDir, origName)
	if err := writeGzipTar(origPath, origEntries, epoch); err != nil {
		return nil, err
	}

	debianEntries, err := tarutil.CollectDir(debianDir, "debian", tarutil.Options{
		Modes: map[string]fs.FileMode{"debian/rules": 0o755},
	})
	if err != nil {
		return nil, fmt.Errorf("source: collect debian directory: %w", err)
	}

	debianPath := filepath.Join(outDir, debianName)
	if err := writeXzTar(debianPath, debianEntries, epoch); err != nil {
		return nil, err
	}

	origSum, err := checksumFile(origPath, origName)
	if err != nil {
		return nil, err
	}

	debianSum, err := checksumFile(debianPath, debianName)
	if err != nil {
		return nil, err
	}

	dsc := renderDSC(m, []checksum{origSum, debianSum})

	signed, err := aptrepo.Clearsign(dsc, options.SigningKey, options.Passphrase, epoch)
	if err != nil {
		return nil, err
	}

	dscPath := filepath.Join(outDir, dscName)
	if err := os.WriteFile(dscPath, signed, 0o644); err != nil {
		return nil, fmt.Errorf("source: write .dsc: %w", err)
	}

	return &Result{
		DSC:    dscPath,
		Files:  []string{origPath, debianPath, dscPath},
		Signed: options.SigningKey != "",
	}, nil
}

func writeGzipTar(path string, entries []tarutil.Entry, epoch time.Time) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("source: create %s: %w", filepath.Base(path), err)
	}

	writer, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("source: create gzip writer: %w", err)
	}

	writer.Header = gzip.Header{OS: 255}

	if err := tarutil.Write(writer, entries, epoch); err != nil {
		_ = writer.Close()
		_ = file.Close()

		return err
	}

	if err := writer.Close(); err != nil {
		_ = file.Close()

		return fmt.Errorf("source: finish gzip stream: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("source: close %s: %w", filepath.Base(path), err)
	}

	return nil
}

func writeXzTar(path string, entries []tarutil.Entry, epoch time.Time) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("source: create %s: %w", filepath.Base(path), err)
	}

	writer, err := xz.NewWriter(file)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("source: create xz writer: %w", err)
	}

	if err := tarutil.Write(writer, entries, epoch); err != nil {
		_ = writer.Close()
		_ = file.Close()

		return err
	}

	if err := writer.Close(); err != nil {
		_ = file.Close()

		return fmt.Errorf("source: finish xz stream: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("source: close %s: %w", filepath.Base(path), err)
	}

	return nil
}

func checksumFile(path, name string) (checksum, error) {
	file, err := os.Open(path)
	if err != nil {
		return checksum{}, fmt.Errorf("source: open %s: %w", name, err)
	}
	defer file.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	size, err := io.Copy(io.MultiWriter(md5Hash, sha1Hash, sha256Hash), file)
	if err != nil {
		return checksum{}, fmt.Errorf("source: hash %s: %w", name, err)
	}

	return checksum{
		Name:   name,
		Size:   size,
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

func renderDSC(m *manifest.Manifest, files []checksum) []byte {
	architecture := "any"
	packageListArch := "any"

	if m.Architecture == "all" {
		architecture = "all"
		packageListArch = "all"
	}

	var builder strings.Builder

	builder.WriteString("Format: 3.0 (quilt)\n")
	fmt.Fprintf(&builder, "Source: %s\n", m.Name)
	fmt.Fprintf(&builder, "Binary: %s\n", strings.Join(m.Source.Binaries, ", "))
	fmt.Fprintf(&builder, "Architecture: %s\n", architecture)
	fmt.Fprintf(&builder, "Version: %s\n", m.VersionString())
	fmt.Fprintf(&builder, "Maintainer: %s\n", m.Maintainer)

	if m.Homepage != "" {
		fmt.Fprintf(&builder, "Homepage: %s\n", m.Homepage)
	}

	fmt.Fprintf(&builder, "Standards-Version: %s\n", m.Source.StandardsVersion)
	fmt.Fprintf(&builder, "Build-Depends: %s\n", strings.Join(m.Source.BuildDepends, ", "))

	builder.WriteString("Package-List:\n")
	fmt.Fprintf(&builder, " %s deb %s %s arch=%s\n",
		m.Name, m.Section, m.Priority, packageListArch)

	builder.WriteString("Checksums-Sha1:\n")
	for _, file := range files {
		fmt.Fprintf(&builder, " %s %d %s\n", file.SHA1, file.Size, file.Name)
	}

	builder.WriteString("Checksums-Sha256:\n")
	for _, file := range files {
		fmt.Fprintf(&builder, " %s %d %s\n", file.SHA256, file.Size, file.Name)
	}

	builder.WriteString("Files:\n")
	for _, file := range files {
		fmt.Fprintf(&builder, " %s %d %s\n", file.MD5, file.Size, file.Name)
	}

	return []byte(builder.String())
}

func sanitizeVersion(version string) string {
	return strings.ReplaceAll(version, ":", "%3a")
}

func validateDebianDir(dir string) error {
	for _, required := range []string{"control", "rules", filepath.Join("source", "format")} {
		if _, err := os.Stat(filepath.Join(dir, required)); err != nil {
			return fmt.Errorf("source: debian/%s is missing: %w", filepath.ToSlash(required), err)
		}
	}

	format, err := os.ReadFile(filepath.Join(dir, "source", "format"))
	if err != nil {
		return fmt.Errorf("source: read debian/source/format: %w", err)
	}

	if !strings.Contains(string(format), "3.0") {
		return fmt.Errorf("source: debian/source/format must be \"3.0 (quilt)\", got %q",
			strings.TrimSpace(string(format)))
	}

	return nil
}

func generateDebian(m *manifest.Manifest, epoch time.Time) (string, error) {
	directory, err := os.MkdirTemp("", "debsmith-debian-*")
	if err != nil {
		return "", fmt.Errorf("source: create debian scaffold: %w", err)
	}

	files := map[string]string{
		"control":       renderControl(m),
		"changelog":     renderChangelog(m, epoch),
		"copyright":     renderCopyright(m, epoch),
		"rules":         renderRules(),
		"source/format": "3.0 (quilt)\n",
	}

	for name, content := range files {
		full := filepath.Join(directory, filepath.FromSlash(name))

		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			_ = os.RemoveAll(directory)

			return "", fmt.Errorf("source: create debian scaffold: %w", err)
		}

		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			_ = os.RemoveAll(directory)

			return "", fmt.Errorf("source: write debian/%s: %w", name, err)
		}
	}

	if err := os.Chmod(filepath.Join(directory, "rules"), 0o755); err != nil {
		_ = os.RemoveAll(directory)

		return "", fmt.Errorf("source: chmod debian/rules: %w", err)
	}

	return directory, nil
}

func renderControl(m *manifest.Manifest) string {
	architecture := "any"
	if m.Architecture == "all" {
		architecture = "all"
	}

	var builder strings.Builder

	fmt.Fprintf(&builder, "Source: %s\n", m.Name)
	fmt.Fprintf(&builder, "Section: %s\n", m.Section)
	fmt.Fprintf(&builder, "Priority: %s\n", m.Priority)
	fmt.Fprintf(&builder, "Maintainer: %s\n", m.Maintainer)
	fmt.Fprintf(&builder, "Build-Depends: %s\n", strings.Join(m.Source.BuildDepends, ", "))
	fmt.Fprintf(&builder, "Standards-Version: %s\n", m.Source.StandardsVersion)

	if m.Homepage != "" {
		fmt.Fprintf(&builder, "Homepage: %s\n", m.Homepage)
	}

	builder.WriteString("Rules-Requires-Root: no\n\n")
	fmt.Fprintf(&builder, "Package: %s\n", m.Name)
	fmt.Fprintf(&builder, "Architecture: %s\n", architecture)
	builder.WriteString("Depends: ${shlibs:Depends}, ${misc:Depends}\n")
	fmt.Fprintf(&builder, "Description: %s\n", m.Description)

	extended := strings.TrimSpace(m.ExtendedDescription)
	if extended == "" {
		extended = m.Description
	}

	for _, line := range strings.Split(extended, "\n") {
		if line == "" {
			builder.WriteString(" .\n")
		} else {
			builder.WriteString(" " + line + "\n")
		}
	}

	return builder.String()
}

func renderChangelog(m *manifest.Manifest, epoch time.Time) string {
	return fmt.Sprintf(`%s (%s) unstable; urgency=medium

  * Initial release generated by debsmith.

 -- %s  %s
`, m.Name, m.VersionString(), m.Maintainer,
		epoch.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

func renderCopyright(m *manifest.Manifest, epoch time.Time) string {
	license := m.License
	if license == "" {
		license = "MIT"
	}

	copyright := m.Copyright
	if copyright == "" {
		copyright = epoch.UTC().Format("2006") + ", " + m.Maintainer
	}

	var builder strings.Builder

	builder.WriteString("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")
	fmt.Fprintf(&builder, "Upstream-Name: %s\n", m.Name)

	if m.Homepage != "" {
		fmt.Fprintf(&builder, "Source: %s\n", m.Homepage)
	}

	builder.WriteString("\nFiles: *\n")
	fmt.Fprintf(&builder, "Copyright: %s\n", copyright)
	fmt.Fprintf(&builder, "License: %s\n", license)

	return builder.String()
}

func renderRules() string {
	return `#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_configure:
override_dh_auto_build:
override_dh_auto_test:
override_dh_auto_install:
`
}
