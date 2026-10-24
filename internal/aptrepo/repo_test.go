// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package aptrepo

import (
	"bytes"
	"compress/gzip"
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

	"github.com/Avi6855/debsmith/internal/deb"
)

var fixedEpoch = time.Unix(1700000000, 0).UTC()

func buildPackage(t *testing.T, directory, filename string) {
	t.Helper()

	pkg := &deb.Package{
		Control: deb.Control{
			Package:      "hello",
			Version:      "1.0.0-1",
			Architecture: "amd64",
			Maintainer:   "Avinash Patil <avinash@example.com>",
			Section:      "utils",
			Priority:     "optional",
			Description:  "Minimal hello utility",
		},
		Files: []deb.File{
			{Path: "usr/bin/hello", Mode: 0o755, Data: []byte("#!/bin/sh\necho hello\n")},
		},
	}

	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}

	file, err := os.Create(filepath.Join(directory, filename))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := deb.Write(file, pkg, deb.Options{
		Compression:        deb.CompressionGzip,
		ControlCompression: deb.CompressionGzip,
		Epoch:              fixedEpoch,
	}); err != nil {
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRepository(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	buildPackage(t, root, "hello_1.0.0-1_amd64.deb")

	result, err := Build(Options{
		Dir: root, Suite: "stable", Component: "main",
		Pool: true, Epoch: fixedEpoch,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if result.Packages != 1 || result.Signed {
		t.Fatalf("result = %+v", result)
	}

	releasePath := filepath.Join(root, "dists", "stable", "Release")
	if result.ReleasePath != releasePath {
		t.Fatalf("release path = %q", result.ReleasePath)
	}

	indexPath := filepath.Join(root, "dists", "stable", "main", "binary-amd64", "Packages")

	content, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read Packages: %v", err)
	}

	text := string(content)

	for _, expected := range []string{
		"Package: hello",
		"Version: 1.0.0-1",
		"Architecture: amd64",
		"Filename: ./pool/main/h/hello/hello_1.0.0-1_amd64.deb",
		"MD5sum:",
		"SHA256:",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Packages missing %q:\n%s", expected, text)
		}
	}

	if _, err := os.Stat(filepath.Join(root, "pool", "main", "h", "hello",
		"hello_1.0.0-1_amd64.deb")); err != nil {
		t.Fatalf("pool copy: %v", err)
	}

	release, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"Origin: DebSmith",
		"Suite: stable",
		"Codename: stable",
		"Architectures: amd64",
		"Components: main",
		"Date: Tue, 14 Nov 2023 22:13:20 UTC",
		"MD5Sum:",
		"SHA1:",
		"SHA256:",
		"main/binary-amd64/Packages.gz",
	} {
		if !strings.Contains(string(release), expected) {
			t.Fatalf("Release missing %q:\n%s", expected, release)
		}
	}

	compressed, err := os.ReadFile(indexPath + ".gz")
	if err != nil {
		t.Fatal(err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	if string(decompressed) != text {
		t.Fatal("Packages.gz does not round-trip")
	}
}

func TestBuildIsDeterministicAndIdempotent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	buildPackage(t, root, "hello_1.0.0-1_amd64.deb")

	first, err := Build(Options{Dir: root, Pool: true, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	releasePath := filepath.Join(root, "dists", "stable", "Release")

	firstRelease, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Build(Options{Dir: root, Pool: true, Epoch: fixedEpoch})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	secondRelease, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(firstRelease, secondRelease) {
		t.Fatal("Release changed between identical builds")
	}

	if first.Packages != second.Packages {
		t.Fatalf("package count changed: %d -> %d", first.Packages, second.Packages)
	}

	packages, err := os.ReadFile(filepath.Join(root, "dists", "stable", "main",
		"binary-amd64", "Packages"))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(string(packages), "Package: hello") != 1 {
		t.Fatalf("duplicate package entries:\n%s", packages)
	}
}

func TestSignedRepository(t *testing.T) {
	t.Parallel()

	keyConfig := &packet.Config{
		RSABits: 2048,
		Time: func() time.Time {
			return fixedEpoch.Add(-time.Hour)
		},
	}

	entity, err := openpgp.NewEntity("DebSmith Test", "", "test@example.com", keyConfig)
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

	root := t.TempDir()
	buildPackage(t, root, "hello_1.0.0-1_amd64.deb")

	result, err := Build(Options{
		Dir: root, Pool: true, Epoch: fixedEpoch, SigningKey: keyPath,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !result.Signed {
		t.Fatal("expected a signed repository")
	}

	release, err := os.ReadFile(filepath.Join(root, "dists", "stable", "Release"))
	if err != nil {
		t.Fatal(err)
	}

	signature, err := os.ReadFile(filepath.Join(root, "dists", "stable", "Release.gpg"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := openpgp.CheckArmoredDetachedSignature(
		openpgp.EntityList{entity}, bytes.NewReader(release), bytes.NewReader(signature),
		nil,
	); err != nil {
		t.Fatalf("verify Release.gpg: %v", err)
	}

	inRelease, err := os.ReadFile(filepath.Join(root, "dists", "stable", "InRelease"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatal("InRelease is not clearsigned")
	}

	if !bytes.Equal(block.Plaintext, release) {
		t.Fatal("InRelease plaintext differs from Release")
	}
}

func TestNoPackages(t *testing.T) {
	t.Parallel()

	if _, err := Build(Options{Dir: t.TempDir(), Pool: true}); err == nil {
		t.Fatal("expected an error for an empty directory")
	}
}
