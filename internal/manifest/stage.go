// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Avi6855/debsmith/internal/deb"
)

// Stage turns the manifest payload rules into binary package files.
func (m *Manifest) Stage() ([]deb.File, error) {
	files := make(map[string]deb.File)

	if m.Root != "" {
		if err := m.stageRoot(files); err != nil {
			return nil, err
		}
	}

	for _, directory := range m.Directories {
		target, err := cleanTarget(directory.Path)
		if err != nil {
			return nil, fmt.Errorf("directories: %w", err)
		}

		mode := directory.Mode.FileMode()
		if mode == 0 {
			mode = 0o755
		}

		files[target] = deb.File{Path: target, IsDir: true, Mode: mode}
	}

	for _, file := range m.Files {
		target, err := cleanTarget(file.Path)
		if err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}

		content, sourceMode, err := m.readSource(file.Source)
		if err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}

		mode := file.Mode.FileMode()
		if mode == 0 {
			mode = sourceMode
		}

		files[target] = deb.File{Path: target, Mode: mode, Data: content}
	}

	for _, link := range m.Symlinks {
		target, err := cleanTarget(link.Path)
		if err != nil {
			return nil, fmt.Errorf("symlinks: %w", err)
		}

		if strings.Contains(link.Target, "\n") {
			return nil, fmt.Errorf("symlinks: target for %q contains a newline", link.Path)
		}

		files[target] = deb.File{Path: target, Link: link.Target}
	}

	for rawPath, mode := range m.Permissions {
		target, err := cleanTarget(rawPath)
		if err != nil {
			return nil, fmt.Errorf("permissions: %w", err)
		}

		entry, ok := files[target]
		if !ok {
			return nil, fmt.Errorf("permissions: unknown path %q", rawPath)
		}

		if mode == 0 {
			return nil, fmt.Errorf("permissions: mode for %q is empty", rawPath)
		}

		entry.Mode = mode.FileMode()
		files[target] = entry
	}

	for _, conffile := range m.Conffiles {
		target, err := cleanTarget(conffile)
		if err != nil {
			return nil, fmt.Errorf("conffiles: %w", err)
		}

		if _, ok := files[target]; !ok {
			return nil, fmt.Errorf("conffiles: %q is not part of the package payload", conffile)
		}
	}

	scripts := make(map[string][]byte, len(m.Scripts))

	for name, source := range m.Scripts {
		content, err := m.readControlSource(source)
		if err != nil {
			return nil, fmt.Errorf("scripts.%s: %w", name, err)
		}

		scripts[name] = content
	}

	controlFiles := make(map[string][]byte, len(m.ControlFiles))

	for name, source := range m.ControlFiles {
		content, err := m.readControlSource(source)
		if err != nil {
			return nil, fmt.Errorf("controlFiles.%s: %w", name, err)
		}

		controlFiles[name] = content
	}

	ordered := make([]deb.File, 0, len(files))
	for _, file := range files {
		ordered = append(ordered, file)
	}

	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Path < ordered[j].Path
	})

	stage := &stagedFiles{files: ordered, scripts: scripts, controlFiles: controlFiles}
	m.staged = stage

	return ordered, nil
}

// stagedFiles keeps control members produced while staging.
type stagedFiles struct {
	files        []deb.File
	scripts      map[string][]byte
	controlFiles map[string][]byte
}

// StagedScripts returns the staged maintainer scripts.
func (m *Manifest) StagedScripts() map[string][]byte {
	if m.staged == nil {
		return nil
	}

	return m.staged.scripts
}

// StagedControlFiles returns the staged extra control members.
func (m *Manifest) StagedControlFiles() map[string][]byte {
	if m.staged == nil {
		return nil
	}

	return m.staged.controlFiles
}

func (m *Manifest) stageRoot(files map[string]deb.File) error {
	root := filepath.Join(m.dir, filepath.FromSlash(m.Root))

	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("root %q: %w", m.Root, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("root %q is not a directory", m.Root)
	}

	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
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

		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}

		target, err := cleanTarget(relative)
		if err != nil {
			return err
		}

		if entry.IsDir() {
			files[target] = deb.File{Path: target, IsDir: true, Mode: 0o755}

			return nil
		}

		if entry.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(current)
			if err != nil {
				return err
			}

			files[target] = deb.File{Path: target, Link: link}

			return nil
		}

		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}

		// Normalise platform-specific modes so a checkout on Windows and a
		// checkout on Linux produce identical packages.
		mode := fs.FileMode(0o644)

		if info, err := entry.Info(); err == nil && info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}

		files[target] = deb.File{Path: target, Mode: mode, Data: content}

		return nil
	})
}

func (m *Manifest) readSource(source string) ([]byte, fs.FileMode, error) {
	if strings.TrimSpace(source) == "" {
		return nil, 0, fmt.Errorf("source path is empty")
	}

	full := filepath.Join(m.dir, filepath.FromSlash(source))

	info, err := os.Stat(full)
	if err != nil {
		return nil, 0, fmt.Errorf("source %q: %w", source, err)
	}

	if info.IsDir() {
		return nil, 0, fmt.Errorf("source %q is a directory; use root or directories", source)
	}

	content, err := os.ReadFile(full)
	if err != nil {
		return nil, 0, fmt.Errorf("source %q: %w", source, err)
	}

	mode := fs.FileMode(0o644)
	if info.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}

	return content, mode, nil
}

func (m *Manifest) readControlSource(source string) ([]byte, error) {
	content, _, err := m.readSource(source)

	return content, err
}

func cleanTarget(value string) (string, error) {
	cleaned := strings.ReplaceAll(value, "\\", "/")
	cleaned = strings.TrimPrefix(cleaned, "/")
	cleaned = path.Clean(cleaned)

	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("invalid target path %q", value)
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("target path escapes package root: %q", value)
	}

	if strings.IndexByte(cleaned, 0) >= 0 {
		return "", fmt.Errorf("target path contains NUL: %q", value)
	}

	return cleaned, nil
}
