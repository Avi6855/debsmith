// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// File is a single payload entry of a binary package.
type File struct {
	Path  string
	IsDir bool
	Mode  fs.FileMode
	Data  []byte
	Link  string
}

// Package is the complete input of a .deb build.
type Package struct {
	Control      Control
	Files        []File
	Conffiles    []string
	Scripts      map[string][]byte
	ControlFiles map[string][]byte
}

// Options controls archive layout and compression.
type Options struct {
	Compression        Compression
	ControlCompression Compression
	Epoch              time.Time
}

// Summary reports what was written.
type Summary struct {
	Files         int
	InstalledSize int64
	DataSize      int64
	ControlSize   int64
	TotalSize     int64
	MD5Sums       map[string]string
}

// MaintainerScripts are the only executable control members accepted.
var MaintainerScripts = []string{"preinst", "postinst", "prerm", "postrm", "config"}

// AdditionalControlFiles are non-executable control members accepted.
var AdditionalControlFiles = []string{"templates", "triggers", "shlibs", "symbols"}

// IsMaintainerScript reports whether name is a known maintainer script.
func IsMaintainerScript(name string) bool {
	for _, script := range MaintainerScripts {
		if name == script {
			return true
		}
	}

	return false
}

func isAdditionalControlFile(name string) bool {
	for _, file := range AdditionalControlFiles {
		if name == file {
			return true
		}
	}

	return false
}

type payloadEntry struct {
	path  string
	isDir bool
	mode  fs.FileMode
	data  []byte
	link  string
}

// Write builds a binary package and writes it to w.
func Write(w io.Writer, pkg *Package, opts Options) (Summary, error) {
	var summary Summary

	if err := validatePackage(pkg); err != nil {
		return summary, err
	}

	dataCompression := opts.Compression
	if dataCompression == "" {
		dataCompression = CompressionZstd
	}

	controlCompression := opts.ControlCompression
	if controlCompression == "" {
		controlCompression = CompressionGzip
	}

	if !dataCompression.Writable() || !controlCompression.Writable() {
		return summary, errors.New("deb: bzip2 cannot be used for new packages")
	}

	epoch := opts.Epoch
	if epoch.IsZero() {
		epoch = time.Unix(0, 0)
	}

	epoch = epoch.UTC().Truncate(time.Second)

	entries, err := collectEntries(pkg.Files)
	if err != nil {
		return summary, err
	}

	summary.Files = len(entries)
	summary.InstalledSize = installedSize(entries)

	controlBytes, sums, err := buildControl(pkg, entries, summary.InstalledSize)
	if err != nil {
		return summary, err
	}

	summary.MD5Sums = sums

	dataArchive, err := buildArchive(dataCompression, func(tw *tar.Writer) error {
		return writeDataTar(tw, entries, epoch)
	})
	if err != nil {
		return summary, fmt.Errorf("deb: build data archive: %w", err)
	}
	defer dataArchive.remove()

	summary.DataSize = dataArchive.size

	controlArchive, err := buildArchive(controlCompression, func(tw *tar.Writer) error {
		return writeControlTar(tw, pkg, controlBytes, sums, epoch)
	})
	if err != nil {
		return summary, fmt.Errorf("deb: build control archive: %w", err)
	}
	defer controlArchive.remove()

	summary.ControlSize = controlArchive.size

	debianBinary := []byte("2.0\n")

	members := []arWriteMember{
		{
			Name:    "debian-binary",
			ModTime: epoch.Unix(),
			Mode:    0o100644,
			Size:    int64(len(debianBinary)),
			Reader:  bytes.NewReader(debianBinary),
		},
	}

	controlReader, err := controlArchive.open()
	if err != nil {
		return summary, err
	}
	defer controlReader.Close()

	members = append(members, arWriteMember{
		Name:    controlCompression.TarName("control"),
		ModTime: epoch.Unix(),
		Mode:    0o100644,
		Size:    controlArchive.size,
		Reader:  controlReader,
	})

	dataReader, err := dataArchive.open()
	if err != nil {
		return summary, err
	}
	defer dataReader.Close()

	members = append(members, arWriteMember{
		Name:    dataCompression.TarName("data"),
		ModTime: epoch.Unix(),
		Mode:    0o100644,
		Size:    dataArchive.size,
		Reader:  dataReader,
	})

	counter := &countingWriter{w: w}

	if err := writeAr(counter, members); err != nil {
		return summary, fmt.Errorf("deb: write archive: %w", err)
	}

	summary.TotalSize = counter.n

	return summary, nil
}

func validatePackage(pkg *Package) error {
	if pkg == nil {
		return errors.New("deb: nil package")
	}

	required := []struct {
		name  string
		value string
	}{
		{"Package", pkg.Control.Package},
		{"Version", pkg.Control.Version},
		{"Architecture", pkg.Control.Architecture},
		{"Maintainer", pkg.Control.Maintainer},
		{"Description", pkg.Control.Description},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("deb: control field %s is required", field.name)
		}
	}

	for name := range pkg.Scripts {
		if !IsMaintainerScript(name) {
			return fmt.Errorf("deb: unknown maintainer script %q", name)
		}
	}

	for name := range pkg.ControlFiles {
		if !isAdditionalControlFile(name) {
			return fmt.Errorf("deb: unsupported control file %q", name)
		}
	}

	return nil
}

func collectEntries(files []File) (map[string]*payloadEntry, error) {
	entries := make(map[string]*payloadEntry, len(files))

	for _, file := range files {
		entryPath, err := normalizePackagePath(file.Path)
		if err != nil {
			return nil, err
		}

		if _, exists := entries[entryPath]; exists {
			return nil, fmt.Errorf("deb: duplicate package path %q", entryPath)
		}

		entry := &payloadEntry{path: entryPath, mode: file.Mode & 0o7777}

		switch {
		case file.IsDir:
			entry.isDir = true
			if entry.mode == 0 {
				entry.mode = 0o755
			}
		case file.Link != "":
			entry.link = file.Link
			entry.mode = 0o777
		default:
			entry.data = file.Data
			if entry.mode == 0 {
				entry.mode = 0o644
			}
		}

		entries[entryPath] = entry
	}

	addParentDirectories(entries)

	return entries, nil
}

func addParentDirectories(entries map[string]*payloadEntry) {
	for entryPath := range entries {
		current := entryPath

		for {
			parent := path.Dir(current)
			if parent == "." || parent == "/" || parent == "" {
				break
			}

			if _, ok := entries[parent]; !ok {
				entries[parent] = &payloadEntry{path: parent, isDir: true, mode: 0o755}
			}

			current = parent
		}
	}
}

func installedSize(entries map[string]*payloadEntry) int64 {
	var kib int64

	for _, entry := range entries {
		if entry.isDir || entry.link != "" || len(entry.data) == 0 {
			continue
		}

		kib += int64((len(entry.data) + 1023) / 1024)
	}

	if kib == 0 && len(entries) > 0 {
		kib = 1
	}

	return kib
}

func buildControl(pkg *Package, entries map[string]*payloadEntry,
	size int64,
) ([]byte, map[string]string, error) {
	control := pkg.Control
	control.InstalledSize = size

	sums := make(map[string]string)

	for entryPath, entry := range entries {
		if entry.isDir || entry.link != "" {
			continue
		}

		sum := md5.Sum(entry.data)
		sums[entryPath] = hex.EncodeToString(sum[:])
	}

	for name, script := range pkg.Scripts {
		if len(script) == 0 {
			return nil, nil, fmt.Errorf("deb: maintainer script %q is empty", name)
		}
	}

	for name, content := range pkg.ControlFiles {
		if len(content) == 0 {
			return nil, nil, fmt.Errorf("deb: control file %q is empty", name)
		}
	}

	return control.Render(), sums, nil
}

func writeDataTar(tw *tar.Writer, entries map[string]*payloadEntry, epoch time.Time) error {
	if err := writeRootDir(tw, epoch); err != nil {
		return err
	}

	paths := make([]string, 0, len(entries))
	for entryPath := range entries {
		paths = append(paths, entryPath)
	}

	sort.Strings(paths)

	for _, entryPath := range paths {
		entry := entries[entryPath]
		name := "./" + entryPath
		header := &tar.Header{
			ModTime: epoch,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
			Format:  tar.FormatPAX,
		}

		switch {
		case entry.isDir:
			name += "/"
			header.Typeflag = tar.TypeDir
			header.Mode = int64(entry.mode)
		case entry.link != "":
			header.Typeflag = tar.TypeSymlink
			header.Linkname = entry.link
			header.Mode = 0o777
		default:
			header.Typeflag = tar.TypeReg
			header.Mode = int64(entry.mode)
			header.Size = int64(len(entry.data))
		}

		header.Name = name

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}

		if header.Typeflag == tar.TypeReg && len(entry.data) > 0 {
			if _, err := tw.Write(entry.data); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}
	}

	return nil
}

func writeControlTar(tw *tar.Writer, pkg *Package, controlBytes []byte,
	sums map[string]string, epoch time.Time,
) error {
	if err := writeRootDir(tw, epoch); err != nil {
		return err
	}

	if err := writeControlEntry(tw, "control", controlBytes, 0o644, epoch); err != nil {
		return err
	}

	if len(sums) > 0 {
		paths := make([]string, 0, len(sums))
		for entryPath := range sums {
			paths = append(paths, entryPath)
		}

		sort.Strings(paths)

		var b strings.Builder

		for _, entryPath := range paths {
			b.WriteString(sums[entryPath])
			b.WriteString("  ")
			b.WriteString(entryPath)
			b.WriteByte('\n')
		}

		if err := writeControlEntry(tw, "md5sums", []byte(b.String()), 0o644, epoch); err != nil {
			return err
		}
	}

	if conffiles := renderConffiles(pkg.Conffiles); conffiles != nil {
		if err := writeControlEntry(tw, "conffiles", conffiles, 0o644, epoch); err != nil {
			return err
		}
	}

	scriptNames := make([]string, 0, len(pkg.Scripts))
	for name := range pkg.Scripts {
		scriptNames = append(scriptNames, name)
	}

	sort.Strings(scriptNames)

	for _, name := range scriptNames {
		if err := writeControlEntry(tw, name, pkg.Scripts[name], 0o755, epoch); err != nil {
			return err
		}
	}

	fileNames := make([]string, 0, len(pkg.ControlFiles))
	for name := range pkg.ControlFiles {
		fileNames = append(fileNames, name)
	}

	sort.Strings(fileNames)

	for _, name := range fileNames {
		if err := writeControlEntry(tw, name, pkg.ControlFiles[name], 0o644, epoch); err != nil {
			return err
		}
	}

	return nil
}

func writeRootDir(tw *tar.Writer, epoch time.Time) error {
	header := &tar.Header{
		Name:     "./",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  epoch,
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		Format:   tar.FormatPAX,
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write root directory: %w", err)
	}

	return nil
}

func writeControlEntry(tw *tar.Writer, name string, content []byte, mode int64,
	epoch time.Time,
) error {
	header := &tar.Header{
		Name:     "./" + name,
		Mode:     mode,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
		ModTime:  epoch,
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		Format:   tar.FormatPAX,
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write control file %s: %w", name, err)
	}

	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("write control file %s: %w", name, err)
	}

	return nil
}

func renderConffiles(conffiles []string) []byte {
	if len(conffiles) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(conffiles))
	paths := make([]string, 0, len(conffiles))

	for _, conffile := range conffiles {
		conffile = strings.TrimSpace(conffile)
		if conffile == "" {
			continue
		}

		if !strings.HasPrefix(conffile, "/") {
			conffile = "/" + conffile
		}

		if !seen[conffile] {
			seen[conffile] = true
			paths = append(paths, conffile)
		}
	}

	sort.Strings(paths)

	var b strings.Builder

	for _, conffile := range paths {
		b.WriteString(conffile)
		b.WriteByte('\n')
	}

	return []byte(b.String())
}

// normalizePackagePath turns a manifest path into a safe archive path.
func normalizePackagePath(value string) (string, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("deb: package path contains NUL: %q", value)
	}

	cleaned := strings.ReplaceAll(value, "\\", "/")
	cleaned = strings.TrimPrefix(cleaned, "/")
	cleaned = path.Clean(cleaned)

	if cleaned == "." || cleaned == "" || cleaned == "/" {
		return "", fmt.Errorf("deb: empty package path %q", value)
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("deb: package path escapes root: %q", value)
	}

	return cleaned, nil
}

type tempArchive struct {
	path string
	size int64
}

func (t *tempArchive) open() (*os.File, error) {
	file, err := os.Open(t.path)
	if err != nil {
		return nil, fmt.Errorf("deb: open temporary archive: %w", err)
	}

	return file, nil
}

func (t *tempArchive) remove() {
	_ = os.Remove(t.path)
}

func buildArchive(compression Compression, fill func(*tar.Writer) error) (*tempArchive, error) {
	file, err := os.CreateTemp("", "debsmith-*.tar")
	if err != nil {
		return nil, fmt.Errorf("deb: create temporary archive: %w", err)
	}

	name := file.Name()

	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(name)
	}

	compressor, err := newCompressor(file, compression)
	if err != nil {
		cleanup()

		return nil, err
	}

	writer := tar.NewWriter(compressor)

	if err := fill(writer); err != nil {
		cleanup()

		return nil, err
	}

	if err := writer.Close(); err != nil {
		cleanup()

		return nil, fmt.Errorf("deb: close tar stream: %w", err)
	}

	if err := compressor.Close(); err != nil {
		cleanup()

		return nil, fmt.Errorf("deb: close compressor: %w", err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(name)

		return nil, fmt.Errorf("deb: close temporary archive: %w", err)
	}

	info, err := os.Stat(name)
	if err != nil {
		_ = os.Remove(name)

		return nil, fmt.Errorf("deb: stat temporary archive: %w", err)
	}

	return &tempArchive{path: name, size: info.Size()}, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	written, err := c.w.Write(p)
	c.n += int64(written)

	return written, err
}
