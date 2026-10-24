// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package sbom

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Avi6855/debsmith/internal/deb"
)

func archive() *deb.Archive {
	return &deb.Archive{
		Control: deb.Control{
			Package:      "demo",
			Version:      "1.2.3-4",
			Architecture: "amd64",
			Depends:      []string{"libc6 (>= 2.38)", "zlib1g"},
			PreDepends:   []string{"dpkg (>= 1.19)"},
		},
		SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	epoch := time.Unix(1700000000, 0).UTC()

	encoded, err := Generate(archive(), "demo.deb", epoch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var document Document
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.5" {
		t.Fatalf("document = %+v", document)
	}

	if document.Metadata.Component.Name != "demo" {
		t.Fatalf("component = %+v", document.Metadata.Component)
	}

	if document.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Fatalf("timestamp = %q", document.Metadata.Timestamp)
	}

	if len(document.Components) != 3 {
		t.Fatalf("components = %d", len(document.Components))
	}

	if len(document.Dependencies) != 1 || len(document.Dependencies[0].DependsOn) != 3 {
		t.Fatalf("dependencies = %+v", document.Dependencies)
	}

	if document.SerialNumber == "" {
		t.Fatal("serial number is empty")
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	t.Parallel()

	epoch := time.Unix(1700000000, 0).UTC()

	first, err := Generate(archive(), "demo.deb", epoch)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Generate(archive(), "demo.deb", epoch)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("SBOM output is not deterministic")
	}
}

func TestConstraintVersion(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"(>= 2.38)": "2.38",
		"(= 1:1.0)": "1:1.0",
		"":          "",
	}

	for input, expected := range cases {
		if got := constraintVersion(input); got != expected {
			t.Fatalf("constraintVersion(%q) = %q, want %q", input, got, expected)
		}
	}
}
