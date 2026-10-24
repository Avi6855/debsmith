// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	arMagic      = "!<arch>\n"
	arHeaderSize = 60
)

// ErrInvalidArchive reports a malformed Unix ar archive.
var ErrInvalidArchive = errors.New("invalid ar archive")

// arWriteMember is one member of an archive being written.
type arWriteMember struct {
	Name    string
	ModTime int64
	Mode    int64
	Size    int64
	Reader  io.Reader
}

// writeAr writes a System V ar archive with deterministic headers.
func writeAr(w io.Writer, members []arWriteMember) error {
	bw := bufio.NewWriter(w)

	if _, err := bw.WriteString(arMagic); err != nil {
		return fmt.Errorf("write ar magic: %w", err)
	}

	for _, m := range members {
		if m.Name == "" || len(m.Name) > 16 {
			return fmt.Errorf("%w: invalid member name %q", ErrInvalidArchive, m.Name)
		}

		if m.Size < 0 {
			return fmt.Errorf("%w: negative size for %q", ErrInvalidArchive, m.Name)
		}

		mode := m.Mode
		if mode == 0 {
			mode = 0o100644
		}

		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n",
			m.Name, m.ModTime, 0, 0, mode, m.Size)
		if len(header) != arHeaderSize {
			return fmt.Errorf("%w: header width for %q", ErrInvalidArchive, m.Name)
		}

		if _, err := bw.WriteString(header); err != nil {
			return fmt.Errorf("write ar header for %q: %w", m.Name, err)
		}

		n, err := io.Copy(bw, io.LimitReader(m.Reader, m.Size))
		if err != nil {
			return fmt.Errorf("write ar member %q: %w", m.Name, err)
		}

		if n != m.Size {
			return fmt.Errorf("%w: member %q declared %d bytes, wrote %d",
				ErrInvalidArchive, m.Name, m.Size, n)
		}

		if m.Size%2 == 1 {
			if err := bw.WriteByte('\n'); err != nil {
				return fmt.Errorf("write ar padding: %w", err)
			}
		}
	}

	if err := bw.Flush(); err != nil {
		return fmt.Errorf("flush ar archive: %w", err)
	}

	return nil
}

// arMember is one member returned while streaming an ar archive.
type arMember struct {
	Name    string
	Size    int64
	Mode    int64
	ModTime int64
	Body    io.Reader
}

// arReader streams members without buffering whole archives.
type arReader struct {
	r     *bufio.Reader
	body  *io.LimitedReader
	pad   int64
	count int
}

func newArReader(r io.Reader) (*arReader, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(arMagic))

	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}

	if string(magic) != arMagic {
		return nil, ErrInvalidArchive
	}

	return &arReader{r: br}, nil
}

// Next drains the previous member and returns the next one, or io.EOF.
func (a *arReader) Next() (*arMember, error) {
	if err := a.drain(); err != nil {
		return nil, err
	}

	header := make([]byte, arHeaderSize)

	if _, err := io.ReadFull(a.r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}

		return nil, fmt.Errorf("%w: truncated member header", ErrInvalidArchive)
	}

	if string(header[58:60]) != "`\n" {
		return nil, fmt.Errorf("%w: bad member header magic", ErrInvalidArchive)
	}

	name := strings.TrimSuffix(strings.TrimSpace(string(header[0:16])), "/")
	if name == "" {
		return nil, fmt.Errorf("%w: empty member name", ErrInvalidArchive)
	}

	size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("%w: invalid size for member %q", ErrInvalidArchive, name)
	}

	mode, _ := strconv.ParseInt(strings.TrimSpace(string(header[40:48])), 8, 64)

	modTime, _ := strconv.ParseInt(strings.TrimSpace(string(header[16:28])), 10, 64)

	a.body = &io.LimitedReader{R: a.r, N: size}
	a.pad = size % 2
	a.count++

	return &arMember{
		Name:    name,
		Size:    size,
		Mode:    mode,
		ModTime: modTime,
		Body:    a.body,
	}, nil
}

func (a *arReader) drain() error {
	if a.body != nil {
		if _, err := io.Copy(io.Discard, a.body); err != nil {
			return fmt.Errorf("drain ar member: %w", err)
		}

		a.body = nil
	}

	if a.pad != 0 {
		if _, err := a.r.Discard(int(a.pad)); err != nil {
			return fmt.Errorf("skip ar padding: %w", err)
		}

		a.pad = 0
	}

	return nil
}
