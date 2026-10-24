// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// FormatText renders a human readable report.
func (r *Report) FormatText() string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "%s %s (%s)\n", r.Package, r.Version, r.Architecture)

	for _, item := range r.Findings {
		location := ""

		if item.Path != "" {
			location = "  " + item.Path
		}

		fmt.Fprintf(&builder, "  %-7s %s  %s%s\n", item.Severity, item.Code, item.Message, location)
	}

	fmt.Fprintf(&builder, "\n%d error(s), %d warning(s), %d info(s) from %d checks\n",
		r.Errors, r.Warnings, r.Infos, r.Checks)

	return builder.String()
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(r); err != nil {
		return fmt.Errorf("encode lint report: %w", err)
	}

	return nil
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool `json:"tool"`
	Results []result  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	HelpURI              string            `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig       `json:"defaultConfiguration"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF writes a SARIF 2.1.0 report usable by code scanning.
func (r *Report) WriteSARIF(w io.Writer, version string) error {
	infos := CheckInfos()
	rules := make([]sarifRule, 0, len(infos))
	index := make(map[string]int, len(infos))

	for position, info := range infos {
		index[info.Code] = position
		rules = append(rules, sarifRule{
			ID:               info.Code,
			Name:             info.Name,
			ShortDescription: sarifText{Text: info.Description},
			FullDescription:  sarifText{Text: info.Description},
			HelpURI:          info.Reference,
			DefaultConfiguration: sarifConfig{
				Level: sarifLevel(info.Severity),
			},
		})
	}

	results := make([]result, 0, len(r.Findings))
	artifact := filepath.ToSlash(r.Artifact)

	for _, item := range r.Findings {
		location := artifact
		if item.Path != "" {
			location = artifact + "#" + item.Path
		}

		results = append(results, result{
			RuleID:    item.Code,
			RuleIndex: index[item.Code],
			Level:     sarifLevel(item.Severity),
			Message:   sarifText{Text: item.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: location},
				},
			}},
		})
	}

	document := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "debsmith",
				InformationURI: "https://github.com/Avi6855/debsmith",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode sarif report: %w", err)
	}

	return nil
}

func sarifLevel(severity Severity) string {
	switch severity {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}
