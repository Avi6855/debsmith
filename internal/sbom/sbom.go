// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package sbom emits CycloneDX 1.5 software bills of materials.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Avi6855/debsmith/internal/deb"
)

// Document is a CycloneDX 1.5 BOM.
type Document struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies"`
}

// Metadata describes the subject of the BOM.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Component Component `json:"component"`
}

// Component is a software component.
type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a checksum of a component.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Property is an arbitrary key/value annotation.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency links a component to the components it needs.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Generate builds a deterministic SBOM for a parsed binary package.
func Generate(archive *deb.Archive, artifact string, epoch time.Time) ([]byte, error) {
	if archive.Control.Package == "" {
		return nil, fmt.Errorf("sbom: package name is empty")
	}

	if epoch.IsZero() {
		epoch = time.Now()
	}

	epoch = epoch.UTC().Truncate(time.Second)

	rootRef := purl(archive.Control.Package, archive.Control.Version, archive.Control.Architecture)

	root := Component{
		Type:    "application",
		BOMRef:  rootRef,
		Name:    archive.Control.Package,
		Version: archive.Control.Version,
		PURL:    rootRef,
		Hashes:  []Hash{{Alg: "SHA-256", Content: archive.SHA256}},
		Properties: []Property{
			{Name: "debsmith:architecture", Value: archive.Control.Architecture},
			{Name: "debsmith:artifact", Value: artifact},
		},
	}

	components := make(map[string]Component)
	dependsOn := make(map[string]bool)

	relations := append([]string{}, archive.Control.PreDepends...)
	relations = append(relations, archive.Control.Depends...)

	for _, relation := range relations {
		name, constraint := deb.RelationName(relation)
		if name == "" {
			continue
		}

		version := constraintVersion(constraint)
		ref := purl(name, version, "")

		if _, exists := components[ref]; !exists {
			component := Component{
				Type:    "library",
				BOMRef:  ref,
				Name:    name,
				Version: version,
				PURL:    ref,
			}

			if constraint != "" && version == "" {
				component.Properties = []Property{
					{Name: "debsmith:version-constraint", Value: constraint},
				}
			}

			components[ref] = component
		}

		dependsOn[ref] = true
	}

	refs := make([]string, 0, len(dependsOn))
	for ref := range dependsOn {
		refs = append(refs, ref)
	}

	sort.Strings(refs)

	ordered := make([]Component, 0, len(components))
	for _, ref := range refs {
		ordered = append(ordered, components[ref])
	}

	document := Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: serialNumber(archive.SHA256 + "|" + rootRef),
		Version:      1,
		Metadata: Metadata{
			Timestamp: epoch.Format(time.RFC3339),
			Component: root,
		},
		Components: ordered,
		Dependencies: []Dependency{
			{Ref: rootRef, DependsOn: refs},
		},
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sbom: encode document: %w", err)
	}

	return append(encoded, '\n'), nil
}

// Write encodes a BOM to w.
func Write(w io.Writer, archive *deb.Archive, artifact string, epoch time.Time) error {
	encoded, err := Generate(archive, artifact, epoch)
	if err != nil {
		return err
	}

	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("sbom: write document: %w", err)
	}

	return nil
}

func purl(name, version, architecture string) string {
	var builder strings.Builder

	builder.WriteString("pkg:deb/")
	builder.WriteString(name)

	if version != "" {
		builder.WriteString("@")
		builder.WriteString(strings.ReplaceAll(version, " ", "%20"))
	}

	if architecture != "" {
		builder.WriteString("?arch=")
		builder.WriteString(architecture)
	}

	return builder.String()
}

func constraintVersion(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	constraint = strings.TrimPrefix(constraint, "(")
	constraint = strings.TrimSuffix(constraint, ")")

	for _, field := range strings.Fields(constraint) {
		switch field {
		case ">=", "<=", "=", ">>", "<<", ">", "<", "~":
			continue
		default:
			return strings.Trim(field, "()")
		}
	}

	return ""
}

func serialNumber(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	digest[6] = (digest[6] & 0x0f) | 0x50
	digest[8] = (digest[8] & 0x3f) | 0x80

	hexValue := hex.EncodeToString(digest[:16])

	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s",
		hexValue[0:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:32])
}
