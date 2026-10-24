// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Compression identifies a tar payload compressor supported by dpkg.
type Compression string

// Supported compressors. bzip2 is accepted when reading but never written.
const (
	CompressionGzip  Compression = "gzip"
	CompressionZstd  Compression = "zstd"
	CompressionXz    Compression = "xz"
	CompressionBzip2 Compression = "bzip2"
)

// ParseCompression validates a user supplied compressor name.
func ParseCompression(value string) (Compression, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "gzip", "gz":
		return CompressionGzip, nil
	case "zstd", "zst":
		return CompressionZstd, nil
	case "xz":
		return CompressionXz, nil
	case "bzip2", "bz2":
		return CompressionBzip2, nil
	default:
		return "", fmt.Errorf("unsupported compression %q (use gzip, zstd or xz)", value)
	}
}

// Ext returns the file extension used in member names.
func (c Compression) Ext() string {
	switch c {
	case CompressionZstd:
		return "zst"
	case CompressionXz:
		return "xz"
	case CompressionBzip2:
		return "bz2"
	default:
		return "gz"
	}
}

// TarName returns a member name such as "data.tar.zst".
func (c Compression) TarName(base string) string {
	return base + ".tar." + c.Ext()
}

// Writable reports whether this compressor can be used for new packages.
func (c Compression) Writable() bool {
	return c != CompressionBzip2
}

func newCompressor(w io.Writer, c Compression) (io.WriteCloser, error) {
	switch c {
	case CompressionGzip:
		gw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("create gzip writer: %w", err)
		}

		// Zero mtime and OS=255 keep output reproducible.
		gw.Header = gzip.Header{OS: 255}

		return gw, nil
	case CompressionZstd:
		zw, err := zstd.NewWriter(w,
			zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(1<<20),
		)
		if err != nil {
			return nil, fmt.Errorf("create zstd writer: %w", err)
		}

		return zw, nil
	case CompressionXz:
		xw, err := xz.NewWriter(w)
		if err != nil {
			return nil, fmt.Errorf("create xz writer: %w", err)
		}

		return xw, nil
	case CompressionBzip2:
		return nil, errors.New("bzip2 compression is read-only")
	default:
		return nil, fmt.Errorf("unsupported compression %q", c)
	}
}

func newDecompressor(r io.Reader, c Compression) (io.ReadCloser, error) {
	switch c {
	case CompressionGzip:
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("read gzip stream: %w", err)
		}

		return gr, nil
	case CompressionZstd:
		zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("read zstd stream: %w", err)
		}

		return zr.IOReadCloser(), nil
	case CompressionXz:
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("read xz stream: %w", err)
		}

		return io.NopCloser(xr), nil
	case CompressionBzip2:
		return io.NopCloser(bzip2.NewReader(r)), nil
	default:
		return nil, fmt.Errorf("unsupported compression %q", c)
	}
}

// CompressionFromMember detects the compressor from a tar member name.
func CompressionFromMember(name string) (Compression, bool) {
	for _, c := range []Compression{CompressionGzip, CompressionZstd, CompressionXz, CompressionBzip2} {
		if strings.HasSuffix(name, "."+c.Ext()) {
			return c, true
		}
	}

	return "", false
}
