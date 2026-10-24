// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package tarutil provides deterministic tar creation with fixed ownership.
package tarutil

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one tar member.
type Entry struct {
	Path  string
	Mode  fs.FileMode
	Data  []byte
	Link  string
	IsDir bool
}

// Options controls deterministic collection.
type Options struct {
	Prefix  string
	Exclude []string
	Modes   map[string]fs.FileMode
}

// Write emits entries as a reproducible PAX tar stream.
func Write(w io.Writer, entries []Entry, epoch time.Time) error {
	epoch = epoch.UTC().Truncate(time.Second)

	sorted := make([]Entry, len(entries))
	copy(sorted, entries)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	writer := tar.NewWriter(w)

	for _, entry := range sorted {
		name := entry.Path
		mode := int64(entry.Mode & 0o7777)
		size := int64(len(entry.Data))
		typeflag := byte(tar.TypeReg)

		switch {
		case entry.IsDir:
			name = strings.TrimSuffix(name, "/") + "/"
			mode = int64(entry.Mode & 0o7777)
			size = 0
			typeflag = tar.TypeDir
		case entry.Link != "":
			mode = 0o777
			size = 0
			typeflag = tar.TypeSymlink
		}

		header := &tar.Header{
			Name:     name,
			Mode:     mode,
			Size:     size,
			Typeflag: typeflag,
			Linkname: entry.Link,
			ModTime:  epoch,
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			Format:   tar.FormatPAX,
		}

		if err := writer.WriteHeader(header); err != nil {
			return fmt.Errorf("tarutil: write %s: %w", name, err)
		}

		if typeflag == tar.TypeReg && len(entry.Data) > 0 {
			if _, err := writer.Write(entry.Data); err != nil {
				return fmt.Errorf("tarutil: write %s: %w", name, err)
			}
		}
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("tarutil: close tar writer: %w", err)
	}

	return nil
}

// CollectDir reads a directory tree into deterministic tar entries.
func CollectDir(root, prefix string, options Options) ([]Entry, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("tarutil: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("tarutil: %s is not a directory", root)
	}

	var entries []Entry

	if prefix != "" {
		entries = append(entries, Entry{
			Path:  path.Clean(strings.TrimPrefix(prefix, "./")),
			Mode:  0o755,
			IsDir: true,
		})
	}

	err = filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}

		if relative == "." {
			return nil
		}

		relative = filepath.ToSlash(relative)

		if excluded(relative, options.Exclude) {
			if entry.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		target := relative
		if prefix != "" {
			target = path.Join(prefix, relative)
		}

		mode := fs.FileMode(0o644)

		if info, err := entry.Info(); err == nil {
			mode = info.Mode().Perm()
		}

		// Normalise platform-specific modes (notably Windows) so archives are
		// identical everywhere: directories 0755, files 0644 or 0755.
		switch {
		case entry.IsDir():
			mode = 0o755
		case mode&0o111 != 0:
			mode = 0o755
		default:
			mode = 0o644
		}

		if override, ok := options.Modes[target]; ok {
			mode = override
		}

		switch {
		case entry.IsDir():
			if mode == 0 {
				mode = 0o755
			}

			entries = append(entries, Entry{Path: target, Mode: mode, IsDir: true})
		case entry.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(current)
			if err != nil {
				return err
			}

			entries = append(entries, Entry{Path: target, Link: link})
		default:
			content, err := os.ReadFile(current)
			if err != nil {
				return err
			}

			if mode == 0 {
				mode = 0o644
			}

			entries = append(entries, Entry{Path: target, Mode: mode, Data: content})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("tarutil: collect %s: %w", root, err)
	}

	return entries, nil
}

func excluded(relative string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.Trim(filepath.ToSlash(pattern), "/")

		if pattern == "" {
			continue
		}

		if relative == pattern || strings.HasPrefix(relative, pattern+"/") {
			return true
		}
	}

	return false
}
