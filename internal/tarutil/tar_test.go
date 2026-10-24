// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package tarutil

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectAndWrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"main.go":      "package main\n",
		"sub/data.txt": "payload\n",
		".git/config":  "secret\n",
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)),
			[]byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := CollectDir(root, "demo-1.0", Options{Exclude: []string{".git"}})
	if err != nil {
		t.Fatalf("CollectDir: %v", err)
	}

	index := map[string]Entry{}
	for _, entry := range entries {
		index[entry.Path] = entry
	}

	if _, ok := index["demo-1.0/main.go"]; !ok {
		t.Fatalf("entries = %v", index)
	}

	if _, ok := index["demo-1.0/.git"]; ok {
		t.Fatal(".git was not excluded")
	}

	if index["demo-1.0/main.go"].Mode != 0o644 {
		t.Fatalf("mode = %o", index["demo-1.0/main.go"].Mode)
	}

	if index["demo-1.0"].Mode != 0o755 {
		t.Fatalf("prefix mode = %o", index["demo-1.0"].Mode)
	}

	var first bytes.Buffer
	if err := Write(&first, entries, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	var second bytes.Buffer
	if err := Write(&second, entries, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("tar output is not deterministic")
	}

	reader := tar.NewReader(bytes.NewReader(first.Bytes()))

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if header.Uid != 0 || header.Uname != "root" {
			t.Fatalf("%s owner = %d/%s", header.Name, header.Uid, header.Uname)
		}

		if header.ModTime.UTC() != time.Unix(1700000000, 0).UTC() {
			t.Fatalf("%s mtime = %s", header.Name, header.ModTime)
		}
	}
}

func TestCollectRejectsMissingDirectory(t *testing.T) {
	t.Parallel()

	if _, err := CollectDir(filepath.Join(t.TempDir(), "missing"), "", Options{}); err == nil {
		t.Fatal("expected an error")
	}
}
