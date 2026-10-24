// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
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

const (
	maxControlArchive = 64 << 20
	maxControlFile    = 16 << 20
)

// Member describes one ar member of a .deb file.
type Member struct {
	Name    string
	Size    int64
	Mode    int64
	ModTime int64
}

// Entry is one data.tar member.
type Entry struct {
	Path     string
	IsDir    bool
	Mode     fs.FileMode
	Size     int64
	Link     string
	Typeflag byte
	UID      int
	GID      int
	Uname    string
	Gname    string
	MD5      string
	ModTime  time.Time
}

// Script is a control member with its mode.
type Script struct {
	Data []byte
	Mode fs.FileMode
}

// Archive is a parsed binary package.
type Archive struct {
	Control            Control
	Fields             []Field
	RawControl         []byte
	Members            []Member
	Entries            []Entry
	MD5Sums            map[string]string
	Conffiles          []string
	Scripts            map[string]Script
	ControlFiles       map[string]Script
	ControlCompression Compression
	DataCompression    Compression
	DebianBinary       string
	Size               int64
	MD5                string
	SHA1               string
	SHA256             string
}

// MDAudit lists checksum integrity problems.
type MDAudit struct {
	MissingSums  []string
	MissingFiles []string
	Mismatched   []string
}

// Read parses a .deb stream.
func Read(r io.Reader) (*Archive, error) {
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	counter := &countingReader{r: r}
	stream := io.TeeReader(counter, io.MultiWriter(md5Hash, sha1Hash, sha256Hash))

	reader, err := newArReader(stream)
	if err != nil {
		return nil, err
	}

	archive := &Archive{
		MD5Sums:      map[string]string{},
		Scripts:      map[string]Script{},
		ControlFiles: map[string]Script{},
	}

	var controlStanza []byte

	seenControl := false

	for {
		member, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		archive.Members = append(archive.Members, Member{
			Name:    member.Name,
			Size:    member.Size,
			Mode:    member.Mode,
			ModTime: member.ModTime,
		})

		switch {
		case member.Name == "debian-binary":
			content, err := io.ReadAll(io.LimitReader(member.Body, 64))
			if err != nil {
				return nil, fmt.Errorf("deb: read debian-binary: %w", err)
			}

			archive.DebianBinary = string(content)
		case strings.HasPrefix(member.Name, "control.tar"):
			compression, ok := CompressionFromMember(member.Name)
			if !ok {
				return nil, fmt.Errorf("deb: unsupported control compression %q", member.Name)
			}

			archive.ControlCompression = compression
			seenControl = true

			content, err := io.ReadAll(io.LimitReader(member.Body, maxControlArchive+1))
			if err != nil {
				return nil, fmt.Errorf("deb: read control archive: %w", err)
			}

			if len(content) > maxControlArchive {
				return nil, fmt.Errorf("deb: control archive exceeds %d bytes", maxControlArchive)
			}

			controlStanza = content
		case strings.HasPrefix(member.Name, "data.tar"):
			compression, ok := CompressionFromMember(member.Name)
			if !ok {
				return nil, fmt.Errorf("deb: unsupported data compression %q", member.Name)
			}

			archive.DataCompression = compression

			if err := readDataTar(member.Body, compression, archive); err != nil {
				return nil, err
			}
		}
	}

	if !seenControl || controlStanza == nil {
		return nil, errors.New("deb: missing control.tar member")
	}

	if err := parseControlArchive(controlStanza, archive.ControlCompression, archive); err != nil {
		return nil, err
	}

	archive.Size = counter.n
	archive.MD5 = hex.EncodeToString(md5Hash.Sum(nil))
	archive.SHA1 = hex.EncodeToString(sha1Hash.Sum(nil))
	archive.SHA256 = hex.EncodeToString(sha256Hash.Sum(nil))

	return archive, nil
}

// ReadFile parses a .deb from disk.
func ReadFile(name string) (*Archive, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("deb: open %s: %w", name, err)
	}
	defer file.Close()

	archive, err := Read(file)
	if err != nil {
		return nil, fmt.Errorf("deb: %s: %w", name, err)
	}

	return archive, nil
}

func readDataTar(body io.Reader, compression Compression, archive *Archive) error {
	decompressor, err := newDecompressor(body, compression)
	if err != nil {
		return err
	}
	defer decompressor.Close()

	reader := tar.NewReader(decompressor)
	seen := make(map[string]bool)

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("deb: read data archive: %w", err)
		}

		entryPath, err := normalizeDataPath(header.Name)
		if err != nil {
			return fmt.Errorf("deb: unsafe data path %q: %w", header.Name, err)
		}

		if entryPath == "" {
			continue
		}

		if seen[entryPath] {
			return fmt.Errorf("deb: duplicate data path %q", entryPath)
		}

		seen[entryPath] = true

		entry := Entry{
			Path:     entryPath,
			Mode:     fs.FileMode(header.Mode & 0o7777),
			Size:     header.Size,
			Link:     header.Linkname,
			Typeflag: header.Typeflag,
			UID:      header.Uid,
			GID:      header.Gid,
			Uname:    header.Uname,
			Gname:    header.Gname,
			ModTime:  header.ModTime,
		}

		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}

		switch header.Typeflag {
		case tar.TypeDir:
			entry.IsDir = true
			entry.Size = 0
		case tar.TypeReg:
			hash := md5.New()

			written, err := io.Copy(hash, reader)
			if err != nil {
				return fmt.Errorf("deb: hash %s: %w", entryPath, err)
			}

			if written != header.Size {
				return fmt.Errorf("deb: %s: declared %d bytes, read %d",
					entryPath, header.Size, written)
			}

			entry.MD5 = hex.EncodeToString(hash.Sum(nil))
		case tar.TypeSymlink:
			entry.Size = 0
		}

		archive.Entries = append(archive.Entries, entry)
	}

	if _, err := io.Copy(io.Discard, decompressor); err != nil {
		return fmt.Errorf("deb: finish data archive: %w", err)
	}

	return nil
}

func parseControlArchive(compressed []byte, compression Compression, archive *Archive) error {
	decompressor, err := newDecompressor(bytes.NewReader(compressed), compression)
	if err != nil {
		return fmt.Errorf("deb: open control archive: %w", err)
	}
	defer decompressor.Close()

	reader := tar.NewReader(decompressor)

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("deb: read control archive: %w", err)
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		name, err := normalizeDataPath(header.Name)
		if err != nil {
			return fmt.Errorf("deb: unsafe control path %q: %w", header.Name, err)
		}

		if name == "" {
			continue
		}

		if header.Size > maxControlFile {
			return fmt.Errorf("deb: control member %q exceeds %d bytes", name, maxControlFile)
		}

		content, err := io.ReadAll(io.LimitReader(reader, maxControlFile+1))
		if err != nil {
			return fmt.Errorf("deb: read control member %q: %w", name, err)
		}

		if len(content) > maxControlFile {
			return fmt.Errorf("deb: control member %q exceeds %d bytes", name, maxControlFile)
		}

		mode := fs.FileMode(header.Mode & 0o7777)

		switch name {
		case "control":
			archive.RawControl = content
		case "md5sums":
			sums, err := parseMD5Sums(content)
			if err != nil {
				return fmt.Errorf("deb: %w", err)
			}

			archive.MD5Sums = sums
		case "conffiles":
			archive.Conffiles = parseConffiles(content)
		default:
			if IsMaintainerScript(name) {
				archive.Scripts[name] = Script{Data: content, Mode: mode}
			} else {
				archive.ControlFiles[name] = Script{Data: content, Mode: mode}
			}
		}
	}

	if archive.RawControl == nil {
		return errors.New("deb: control archive has no control file")
	}

	control, fields, err := ParseControl(archive.RawControl)
	if err != nil {
		return fmt.Errorf("deb: %w", err)
	}

	archive.Control = *control
	archive.Fields = fields.All()

	return nil
}

func parseMD5Sums(data []byte) (map[string]string, error) {
	sums := map[string]string{}

	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		idx := strings.IndexAny(line, " \t")
		if idx != 32 || len(line) < 34 {
			return nil, fmt.Errorf("invalid md5sums line %q", line)
		}

		if _, err := hex.DecodeString(line[:idx]); err != nil {
			return nil, fmt.Errorf("invalid md5sums hash in %q", line)
		}

		entryPath := strings.TrimLeft(line[idx:], " \t")
		entryPath = strings.TrimPrefix(entryPath, "*")
		entryPath = strings.TrimPrefix(entryPath, "./")

		if entryPath == "" {
			return nil, fmt.Errorf("invalid md5sums path in %q", line)
		}

		sums[entryPath] = strings.ToLower(line[:idx])
	}

	return sums, nil
}

func parseConffiles(data []byte) []string {
	var conffiles []string

	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		conffiles = append(conffiles, line)
	}

	return conffiles
}

// AuditMD5 compares declared checksums with the payload.
func (a *Archive) AuditMD5() MDAudit {
	var audit MDAudit

	files := make(map[string]bool, len(a.Entries))
	for _, entry := range a.Entries {
		if entry.IsDir {
			continue
		}

		files[entry.Path] = true

		if entry.MD5 == "" {
			continue
		}

		declared, ok := a.MD5Sums[entry.Path]
		if !ok {
			audit.MissingSums = append(audit.MissingSums, entry.Path)

			continue
		}

		if !strings.EqualFold(declared, entry.MD5) {
			audit.Mismatched = append(audit.Mismatched, entry.Path)
		}
	}

	for entryPath := range a.MD5Sums {
		if !files[entryPath] {
			audit.MissingFiles = append(audit.MissingFiles, entryPath)
		}
	}

	sort.Strings(audit.MissingSums)
	sort.Strings(audit.MissingFiles)
	sort.Strings(audit.Mismatched)

	return audit
}

// File returns the payload entry at path, if present.
func (a *Archive) File(entryPath string) (Entry, bool) {
	for _, entry := range a.Entries {
		if entry.Path == entryPath {
			return entry, true
		}
	}

	return Entry{}, false
}

// Script returns a maintainer script by name.
func (a *Archive) Script(name string) (Script, bool) {
	script, ok := a.Scripts[name]

	return script, ok
}

func normalizeDataPath(value string) (string, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("path contains NUL: %q", value)
	}

	cleaned := strings.ReplaceAll(value, "\\", "/")
	cleaned = strings.TrimPrefix(cleaned, "./")
	cleaned = strings.TrimPrefix(cleaned, "/")
	cleaned = path.Clean(cleaned)

	if cleaned == "." || cleaned == "" {
		return "", nil
	}

	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path escapes package root: %q", value)
	}

	return cleaned, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	read, err := c.r.Read(p)
	c.n += int64(read)

	return read, err
}
