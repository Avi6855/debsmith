// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package manifest loads and validates debsmith.yaml project files and turns
// them into staged package payloads.
package manifest

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Avi6855/debsmith/internal/deb"
)

// DefaultFile is the canonical manifest filename.
const DefaultFile = "debsmith.yaml"

// Candidates are tried in order when a directory is given.
var Candidates = []string{"debsmith.yaml", "debsmith.yml", "manifest.yaml", "manifest.yml"}

// Mode is a file mode written in octal in YAML ("0644" or 0644).
type Mode fs.FileMode

// FileMode converts the manifest mode to an fs.FileMode.
func (m Mode) FileMode() fs.FileMode {
	return fs.FileMode(m)
}

// UnmarshalYAML accepts octal strings and integers.
func (m *Mode) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!null" {
		*m = 0

		return nil
	}

	raw := strings.TrimSpace(value.Value)
	raw = strings.TrimPrefix(raw, "0o")
	raw = strings.TrimPrefix(raw, "0O")

	if raw == "" {
		*m = 0

		return nil
	}

	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid mode %q: use octal such as \"0644\"", value.Value)
	}

	*m = Mode(parsed)

	return nil
}

// FileSpec copies a file into the package.
type FileSpec struct {
	Source string `yaml:"source"`
	Path   string `yaml:"path"`
	Mode   Mode   `yaml:"mode"`
}

// DirectorySpec creates a directory in the package.
type DirectorySpec struct {
	Path string `yaml:"path"`
	Mode Mode   `yaml:"mode"`
}

// SymlinkSpec creates a symbolic link in the package.
type SymlinkSpec struct {
	Path   string `yaml:"path"`
	Target string `yaml:"target"`
}

// SourceSpec configures Debian source package generation.
type SourceSpec struct {
	Upstream         string   `yaml:"upstream"`
	Debian           string   `yaml:"debian"`
	BuildDepends     []string `yaml:"buildDepends"`
	StandardsVersion string   `yaml:"standardsVersion"`
	Binaries         []string `yaml:"binaries"`
}

// Manifest is the declarative package definition.
type Manifest struct {
	Name                string `yaml:"name"`
	Version             string `yaml:"version"`
	Revision            string `yaml:"revision"`
	Architecture        string `yaml:"architecture"`
	Maintainer          string `yaml:"maintainer"`
	Description         string `yaml:"description"`
	ExtendedDescription string `yaml:"extendedDescription"`
	Homepage            string `yaml:"homepage"`
	Section             string `yaml:"section"`
	Priority            string `yaml:"priority"`
	License             string `yaml:"license"`
	Copyright           string `yaml:"copyright"`
	MultiArch           string `yaml:"multiArch"`
	Essential           bool   `yaml:"essential"`

	PreDepends []string `yaml:"preDepends"`
	Depends    []string `yaml:"depends"`
	Recommends []string `yaml:"recommends"`
	Suggests   []string `yaml:"suggests"`
	Enhances   []string `yaml:"enhances"`
	Breaks     []string `yaml:"breaks"`
	Conflicts  []string `yaml:"conflicts"`
	Replaces   []string `yaml:"replaces"`
	Provides   []string `yaml:"provides"`

	Root         string            `yaml:"root"`
	Files        []FileSpec        `yaml:"files"`
	Directories  []DirectorySpec   `yaml:"directories"`
	Symlinks     []SymlinkSpec     `yaml:"symlinks"`
	Permissions  map[string]Mode   `yaml:"permissions"`
	Conffiles    []string          `yaml:"conffiles"`
	Scripts      map[string]string `yaml:"scripts"`
	ControlFiles map[string]string `yaml:"controlFiles"`

	Compression        string `yaml:"compression"`
	ControlCompression string `yaml:"controlCompression"`
	SBOM               bool   `yaml:"sbom"`

	Source SourceSpec `yaml:"source"`

	// Path is the absolute manifest filename, set by Load.
	Path string `yaml:"-"`
	dir  string

	staged *stagedFiles
}

// Dir returns the directory that contains the manifest.
func (m *Manifest) Dir() string {
	return m.dir
}

// Load reads and validates a manifest file or a directory containing one.
func Load(path string) (*Manifest, error) {
	if path == "" {
		path = "."
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest path: %w", err)
	}

	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	if info.IsDir() {
		found := ""

		for _, candidate := range Candidates {
			stat, err := os.Stat(filepath.Join(absolute, candidate))
			if err == nil && !stat.IsDir() {
				found = filepath.Join(absolute, candidate)

				break
			}
		}

		if found == "" {
			return nil, fmt.Errorf("no manifest found in %s (expected %s)", absolute, DefaultFile)
		}

		absolute = found
	}

	content, err := os.ReadFile(absolute)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var parsed Manifest

	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)

	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", absolute, err)
	}

	parsed.Path = absolute
	parsed.dir = filepath.Dir(absolute)

	// Without an explicit revision, a trailing -N is the Debian revision.
	if parsed.Revision == "" {
		if index := strings.LastIndex(parsed.Version, "-"); index > 0 && index < len(parsed.Version)-1 {
			parsed.Revision = parsed.Version[index+1:]
			parsed.Version = parsed.Version[:index]
		}
	}

	parsed.applyDefaults()

	if err := parsed.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", absolute, err)
	}

	return &parsed, nil
}

func (m *Manifest) applyDefaults() {
	if m.Revision == "" {
		m.Revision = "1"
	}

	if m.Architecture == "" {
		m.Architecture = HostArchitecture()
	}

	if m.Section == "" {
		m.Section = "utils"
	}

	if m.Priority == "" {
		m.Priority = "optional"
	}

	if m.Compression == "" {
		m.Compression = string(deb.CompressionZstd)
	}

	if m.ControlCompression == "" {
		m.ControlCompression = string(deb.CompressionGzip)
	}

	if m.Source.Debian == "" {
		m.Source.Debian = "debian"
	}

	if m.Source.StandardsVersion == "" {
		m.Source.StandardsVersion = "4.7.0"
	}

	if len(m.Source.BuildDepends) == 0 {
		m.Source.BuildDepends = []string{"debhelper-compat (= 13)"}
	}

	if len(m.Source.Binaries) == 0 {
		m.Source.Binaries = []string{m.Name}
	}
}

var (
	packageNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionPattern     = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)
	revisionPattern    = regexp.MustCompile(`^[A-Za-z0-9.+~]+$`)
	archPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	maintainerPattern  = regexp.MustCompile(`^.+ <[^<>@\s]+@[^<>@\s]+>$`)
)

// Validate checks the manifest against Debian policy basics.
func (m *Manifest) Validate() error {
	var problems []string

	if !packageNamePattern.MatchString(m.Name) {
		problems = append(problems,
			"name must be at least two characters of lowercase letters, digits, '+', '-' or '.'")
	} else if !strings.ContainsAny(m.Name, "abcdefghijklmnopqrstuvwxyz") {
		problems = append(problems, "name must contain a lowercase letter")
	}

	if m.Version == "" {
		problems = append(problems, "version is required")
	} else if !versionPattern.MatchString(m.Version) {
		problems = append(problems,
			"version must start with a digit and contain only [A-Za-z0-9.+~:-]")
	}

	if m.Revision != "" {
		if !revisionPattern.MatchString(m.Revision) {
			problems = append(problems, "revision may contain only [A-Za-z0-9.+~]")
		}

		if strings.Contains(m.Version, "-") {
			problems = append(problems,
				"version must not contain '-' when revision is set")
		}
	}

	if m.Architecture != "all" && !archPattern.MatchString(m.Architecture) {
		problems = append(problems, "architecture must be a dpkg architecture or \"all\"")
	}

	if !maintainerPattern.MatchString(m.Maintainer) {
		problems = append(problems, "maintainer must look like \"Name <email@example.com>\"")
	}

	if strings.TrimSpace(m.Description) == "" {
		problems = append(problems, "description is required")
	} else if strings.Contains(m.Description, "\n") {
		problems = append(problems, "description must be a single synopsis line")
	}

	switch m.MultiArch {
	case "", "no", "same", "foreign", "allowed":
	default:
		problems = append(problems, "multiArch must be same, foreign, allowed or no")
	}

	if _, err := deb.ParseCompression(m.Compression); err != nil {
		problems = append(problems, err.Error())
	}

	if _, err := deb.ParseCompression(m.ControlCompression); err != nil {
		problems = append(problems, err.Error())
	}

	for _, name := range sortedKeys(m.Scripts) {
		if !deb.IsMaintainerScript(name) {
			problems = append(problems, fmt.Sprintf("scripts: unsupported script %q", name))
		}
	}

	for _, name := range sortedKeys(m.ControlFiles) {
		valid := false

		for _, allowed := range deb.AdditionalControlFiles {
			if name == allowed {
				valid = true
			}
		}

		if !valid {
			problems = append(problems, fmt.Sprintf("controlFiles: unsupported file %q", name))
		}
	}

	for _, file := range m.Files {
		if strings.TrimSpace(file.Source) == "" {
			problems = append(problems, "files: every entry needs a source")
		}

		if strings.TrimSpace(file.Path) == "" {
			problems = append(problems, "files: every entry needs a path")
		}
	}

	for _, dir := range m.Directories {
		if strings.TrimSpace(dir.Path) == "" {
			problems = append(problems, "directories: every entry needs a path")
		}
	}

	for _, link := range m.Symlinks {
		if strings.TrimSpace(link.Path) == "" || strings.TrimSpace(link.Target) == "" {
			problems = append(problems, "symlinks: every entry needs path and target")
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid manifest: %s", strings.Join(problems, "; "))
	}

	return nil
}

// VersionString returns the full Debian version (upstream[-revision]).
func (m *Manifest) VersionString() string {
	if m.Revision == "" {
		return m.Version
	}

	return m.Version + "-" + m.Revision
}

// ArtifactName is the conventional binary package filename.
func (m *Manifest) ArtifactName() string {
	return fmt.Sprintf("%s_%s_%s.deb", m.Name, m.VersionString(), m.Architecture)
}

// Control builds the binary package control stanza.
func (m *Manifest) Control() deb.Control {
	return deb.Control{
		Package:      m.Name,
		Version:      m.VersionString(),
		Architecture: m.Architecture,
		Maintainer:   m.Maintainer,
		Section:      m.Section,
		Priority:     m.Priority,
		MultiArch:    m.MultiArch,
		Essential:    m.Essential,
		Homepage:     m.Homepage,
		Description:  m.Description,
		Extended:     strings.TrimSpace(m.ExtendedDescription),
		PreDepends:   m.PreDepends,
		Depends:      m.Depends,
		Recommends:   m.Recommends,
		Suggests:     m.Suggests,
		Enhances:     m.Enhances,
		Breaks:       m.Breaks,
		Conflicts:    m.Conflicts,
		Replaces:     m.Replaces,
		Provides:     m.Provides,
	}
}

// HostArchitecture maps the Go host architecture to a dpkg architecture.
func HostArchitecture() string {
	switch runtime.GOARCH {
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	default:
		return runtime.GOARCH
	}
}

// Version sanitised for filenames (epoch removed).
func (m *Manifest) VersionForFilename() string {
	version := m.VersionString()

	if idx := strings.IndexByte(version, ':'); idx >= 0 {
		version = version[idx+1:]
	}

	return version
}

// UpstreamVersion is the version used for .orig tarballs.
func (m *Manifest) UpstreamVersion() string {
	version := m.Version

	if idx := strings.IndexByte(version, ':'); idx >= 0 {
		version = version[idx+1:]
	}

	return version
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
