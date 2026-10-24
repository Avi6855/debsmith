// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package sourcepkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"

	"github.com/Avi6855/debsmith/internal/deb"
	"github.com/Avi6855/debsmith/internal/manifest"
)

var fixedEpoch = time.Unix(1700000000, 0).UTC()

func writeProject(t *testing.T, withDebian bool) string {
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		"debsmith.yaml": `
name: demo
version: "1.2.3"
revision: "4"
architecture: all
maintainer: "Avinash Patil <avinash@example.com>"
description: "Demo source package"
extendedDescription: "A small source package used by tests."
homepage: "https://example.com/demo"
section: utils
priority: optional
license: MIT
source:
  upstream: src
`,
		"src/hello.c":  "#include <stdio.h>\nint main(void) { return 0; }\n",
		"src/Makefile": "all:\n\tcc -o hello hello.c\n",
	}

	if withDebian {
		files["debian/control"] = `Source: demo
Section: utils
Priority: optional
Maintainer: Avinash Patil <avinash@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.7.0

Package: demo
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: Demo source package
 A small source package used by tests.
`
		files["debian/rules"] = "#!/usr/bin/make -f\n%:\n\tdh $@\n"
		files["debian/source/format"] = "3.0 (quilt)\n"
	}

	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))

		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func load(t *testing.T, dir string) *manifest.Manifest {
	t.Helper()

	parsed, err := manifest.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	return parsed
}

func TestBuild(t *testing.T) {
	t.Parallel()

	dir := writeProject(t, true)
	out := t.TempDir()

	result, err := Build(load(t, dir), Options{OutDir: out, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(result.Files) != 3 || result.Signed {
		t.Fatalf("result = %+v", result)
	}

	dsc, err := os.ReadFile(result.DSC)
	if err != nil {
		t.Fatal(err)
	}

	fields, err := deb.ParseFields(dsc)
	if err != nil {
		t.Fatalf("parse dsc: %v", err)
	}

	if fields.Get("Format") != "3.0 (quilt)" {
		t.Fatalf("format = %q", fields.Get("Format"))
	}

	if fields.Get("Version") != "1.2.3-4" {
		t.Fatalf("version = %q", fields.Get("Version"))
	}

	origPath := filepath.Join(out, "demo_1.2.3.orig.tar.gz")
	debianPath := filepath.Join(out, "demo_1.2.3-4.debian.tar.xz")
	orig, err := os.ReadFile(origPath)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(orig)
	if !strings.Contains(fields.Get("Checksums-Sha256"), hex.EncodeToString(digest[:])) {
		t.Fatal("dsc is missing the orig sha256")
	}

	origEntries := readTarGz(t, orig)
	if _, ok := origEntries["demo-1.2.3/hello.c"]; !ok {
		t.Fatalf("orig entries = %v", keys(origEntries))
	}

	if _, ok := origEntries["demo-1.2.3/debian/control"]; ok {
		t.Fatal("debian/ leaked into the orig tarball")
	}

	debianEntries := readTarXz(t, debianPath)
	if _, ok := debianEntries["debian/control"]; !ok {
		t.Fatalf("debian entries = %v", keys(debianEntries))
	}

	if debianEntries["debian/rules"].Mode != 0o755 {
		t.Fatalf("debian/rules mode = %o", debianEntries["debian/rules"].Mode)
	}
}

func TestBuildSignsDSC(t *testing.T) {
	t.Parallel()

	entity, err := openpgp.NewEntity("DebSmith Test", "", "test@example.com", &packet.Config{
		RSABits: 2048,
		Time: func() time.Time {
			return fixedEpoch.Add(-time.Hour)
		},
	})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	var key bytes.Buffer

	armorWriter, err := armor.Encode(&key, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := entity.SerializePrivate(armorWriter, nil); err != nil {
		t.Fatal(err)
	}

	if err := armorWriter.Close(); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(t.TempDir(), "test.asc")
	if err := os.WriteFile(keyPath, key.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := writeProject(t, true)

	result, err := Build(load(t, dir), Options{
		OutDir: t.TempDir(), Epoch: fixedEpoch, SigningKey: keyPath,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !result.Signed {
		t.Fatal("expected a signed .dsc")
	}

	content, err := os.ReadFile(result.DSC)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := clearsign.Decode(content)
	if block == nil {
		t.Fatal(".dsc is not clearsigned")
	}

	if !strings.Contains(string(block.Plaintext), "Format: 3.0 (quilt)") {
		t.Fatalf("signed plaintext:\n%s", block.Plaintext)
	}

	if _, err := block.VerifySignature(openpgp.EntityList{entity}, nil); err != nil {
		t.Fatalf("verify .dsc signature: %v", err)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	t.Parallel()

	dir := writeProject(t, true)
	firstDir := t.TempDir()
	secondDir := t.TempDir()

	first, err := Build(load(t, dir), Options{OutDir: firstDir, Epoch: fixedEpoch})
	if err != nil {
		t.Fatal(err)
	}

	second, err := Build(load(t, dir), Options{OutDir: secondDir, Epoch: fixedEpoch})
	if err != nil {
		t.Fatal(err)
	}

	for index := range first.Files {
		left, err := os.ReadFile(first.Files[index])
		if err != nil {
			t.Fatal(err)
		}

		right, err := os.ReadFile(second.Files[index])
		if err != nil {
			t.Fatal(err)
		}

		if index < 2 && !bytes.Equal(left, right) {
			t.Fatalf("%s is not deterministic", filepath.Base(first.Files[index]))
		}
	}
}

func TestBuildGeneratesDebianScaffold(t *testing.T) {
	t.Parallel()

	dir := writeProject(t, false)
	out := t.TempDir()

	result, err := Build(load(t, dir), Options{OutDir: out, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	entries := readTarXz(t, filepath.Join(out, "demo_1.2.3-4.debian.tar.xz"))

	for _, expected := range []string{
		"debian/control", "debian/changelog", "debian/copyright",
		"debian/rules", "debian/source/format",
	} {
		if _, ok := entries[expected]; !ok {
			t.Fatalf("missing %q in scaffold", expected)
		}
	}

	if entries["debian/rules"].Mode != 0o755 {
		t.Fatalf("rules mode = %o", entries["debian/rules"].Mode)
	}

	if result.DSC == "" {
		t.Fatal("no dsc")
	}
}

func TestBuildRequiresUpstream(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "debsmith.yaml"), []byte(`
name: demo
version: "1.0"
maintainer: "A <a@example.com>"
description: "x"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	parsed := load(t, dir)

	if _, err := Build(parsed, Options{OutDir: t.TempDir(), Epoch: fixedEpoch}); err == nil {
		t.Fatal("expected source.upstream error")
	}
}

type tarEntry struct {
	Mode int64
	Data []byte
}

func readTarGz(t *testing.T, content []byte) map[string]tarEntry {
	t.Helper()

	reader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}

	return readTar(t, reader)
}

func readTarXz(t *testing.T, path string) map[string]tarEntry {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := xz.NewReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}

	return readTar(t, reader)
}

func readTar(t *testing.T, reader io.Reader) map[string]tarEntry {
	t.Helper()

	entries := map[string]tarEntry{}
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		data, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}

		entries[header.Name] = tarEntry{Mode: header.Mode, Data: data}
	}

	return entries
}

func keys(values map[string]tarEntry) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}

	return out
}
