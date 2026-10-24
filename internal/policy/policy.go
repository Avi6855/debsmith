// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

// Package policy implements a Debian Policy focused linter for binary packages.
package policy

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Avi6855/debsmith/internal/deb"
)

// Severity ranks a finding.
type Severity string

// Finding severities.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Rank returns a comparable weight for a severity.
func (s Severity) Rank() int {
	switch s {
	case SeverityError:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Finding is one policy violation.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Path     string   `json:"path,omitempty"`
	Advice   string   `json:"advice,omitempty"`
}

// Report is the complete lint result for one artifact.
type Report struct {
	Artifact     string    `json:"artifact"`
	Package      string    `json:"package"`
	Version      string    `json:"version"`
	Architecture string    `json:"architecture"`
	Checks       int       `json:"checks"`
	Errors       int       `json:"errors"`
	Warnings     int       `json:"warnings"`
	Infos        int       `json:"infos"`
	Findings     []Finding `json:"findings"`
}

// CheckInfo is the public description of a check.
type CheckInfo struct {
	Code        string   `json:"code"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Reference   string   `json:"reference,omitempty"`
}

type check struct {
	CheckInfo
	run func(*deb.Archive) []Finding
}

func finding(message string, path string, advice string) Finding {
	return Finding{Message: message, Path: path, Advice: advice}
}

var (
	packagePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionPattern    = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)
	maintainerPattern = regexp.MustCompile(`^.+ <[^<>@\s]+@[^<>@\s]+>$`)
)

const policyControlURL = "https://www.debian.org/doc/debian-policy/ch-controlfields.html"
const policyFilesURL = "https://www.debian.org/doc/debian-policy/ch-files.html"
const policyMaintainerURL = "https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html"
const lintianURL = "https://lintian.debian.org/tags.html"

var knownArchitectures = map[string]bool{
	"all": true, "amd64": true, "arm64": true, "armel": true, "armhf": true,
	"i386": true, "ia64": true, "mips64el": true, "mipsel": true, "powerpc": true,
	"ppc64": true, "ppc64el": true, "riscv64": true, "s390x": true, "loong64": true,
	"m68k": true, "sh4": true, "alpha": true, "hppa": true, "sparc64": true, "x32": true,
}

var knownPriorities = map[string]bool{
	"required": true, "important": true, "standard": true, "optional": true, "extra": true,
}

var knownSections = map[string]bool{
	"admin": true, "cli-mono": true, "comm": true, "database": true, "debug": true,
	"devel": true, "doc": true, "editors": true, "education": true, "electronics": true,
	"embedded": true, "fonts": true, "games": true, "gnome": true, "gnu-r": true,
	"gnustep": true, "graphics": true, "hamradio": true, "haskell": true, "httpd": true,
	"interpreters": true, "introspection": true, "java": true, "javascript": true,
	"kde": true, "kernel": true, "libdevel": true, "libs": true, "lisp": true,
	"localization": true, "mail": true, "math": true, "metapackages": true, "misc": true,
	"net": true, "news": true, "ocaml": true, "oldlibs": true, "otherosfs": true,
	"perl": true, "php": true, "python": true, "ruby": true, "rust": true,
	"science": true, "shells": true, "sound": true, "tasks": true, "tex": true,
	"text": true, "utils": true, "vcs": true, "video": true, "web": true,
	"x11": true, "xfce": true, "zope": true,
}

// checks is the ordered registry executed by Lint.
var checks = []check{
	{
		CheckInfo: CheckInfo{
			Code: "DSM001", Name: "control-required-fields", Severity: SeverityError,
			Description: "Package, Version, Architecture, Maintainer and Description must be set.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			required := []struct {
				name  string
				value string
			}{
				{"Package", a.Control.Package},
				{"Version", a.Control.Version},
				{"Architecture", a.Control.Architecture},
				{"Maintainer", a.Control.Maintainer},
				{"Description", a.Control.Description},
			}

			var out []Finding
			for _, field := range required {
				if strings.TrimSpace(field.value) == "" {
					out = append(out, finding(
						fmt.Sprintf("control field %s is missing", field.name), "",
						"Add the field to the package control stanza."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM002", Name: "package-name", Severity: SeverityError,
			Description: "Package names must be at least two lowercase alphanumeric characters, '+', '-' or '.'.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			name := a.Control.Package
			if name == "" || packagePattern.MatchString(name) {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("invalid package name %q", name), "",
				"Use lowercase letters, digits, '+', '-' and '.'.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM003", Name: "package-version", Severity: SeverityError,
			Description: "Versions must start with a digit and use [A-Za-z0-9.+~:-].",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			version := a.Control.Version
			if version == "" || versionPattern.MatchString(version) {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("invalid version %q", version), "",
				"Start the version with a digit; separate a Debian revision with '-'.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM004", Name: "architecture", Severity: SeverityWarning,
			Description: "Architecture should be a known dpkg architecture or 'all'.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			architecture := a.Control.Architecture
			if architecture == "" || knownArchitectures[architecture] {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("unknown architecture %q", architecture), "",
				"Use a dpkg architecture such as amd64, arm64 or all.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM005", Name: "maintainer", Severity: SeverityError,
			Description: "The Maintainer field must be 'Name <email>'.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			maintainer := a.Control.Maintainer
			if maintainer == "" || maintainerPattern.MatchString(maintainer) {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("invalid maintainer %q", maintainer), "",
				"Use \"Name <email@example.com>\".")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM006", Name: "description-synopsis", Severity: SeverityWarning,
			Description: "The synopsis should fit on one short line of at most 80 characters.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			if len(a.Control.Description) <= 80 {
				return nil
			}

			return []Finding{finding(
				fmt.Sprintf("synopsis is %d characters", len(a.Control.Description)), "",
				"Keep the first Description line at 80 characters or less.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM007", Name: "description-lines", Severity: SeverityWarning,
			Description: "Extended description lines should stay within 80 characters.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, line := range strings.Split(a.Control.Extended, "\n") {
				if len(line) > 80 {
					out = append(out, finding(
						fmt.Sprintf("description line is %d characters", len(line)), "",
						"Wrap extended description lines at 80 characters."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM008", Name: "empty-package", Severity: SeverityError,
			Description: "A binary package must ship at least one file or symlink.",
		},
		run: func(a *deb.Archive) []Finding {
			for _, entry := range a.Entries {
				if !entry.IsDir {
					return nil
				}
			}

			return []Finding{finding("package contains no files", "",
				"Stage payload files or declare directories explicitly.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM009", Name: "setuid", Severity: SeverityError,
			Description: "Packages should not ship setuid or setgid files.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return forEntries(a, func(entry deb.Entry) *Finding {
				if entry.IsDir || entry.Mode&0o6000 == 0 {
					return nil
				}

				found := finding(fmt.Sprintf("mode %04o", entry.Mode), entry.Path,
					"Avoid setuid/setgid; use capabilities or a privileged daemon instead.")

				return &found
			})
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM010", Name: "world-writable", Severity: SeverityWarning,
			Description: "Packages should not ship world-writable files.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return forEntries(a, func(entry deb.Entry) *Finding {
				if entry.IsDir || entry.Link != "" || entry.Mode&0o002 == 0 {
					return nil
				}

				found := finding(fmt.Sprintf("mode %04o", entry.Mode), entry.Path,
					"Install files as 0644 or 0755.")

				return &found
			})
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM011", Name: "usr-local", Severity: SeverityWarning,
			Description: "Packages must not install into /usr/local.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return prefixFindings(a, []string{"usr/local/"}, "Files must not be installed under /usr/local.")
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM012", Name: "transient-paths", Severity: SeverityWarning,
			Description: "Packages must not ship files in /home, /tmp or /var/tmp.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return prefixFindings(a, []string{"home/", "tmp/", "var/tmp/"},
				"Create transient directories at runtime instead.")
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM013", Name: "debian-dir", Severity: SeverityWarning,
			Description: "Packaging metadata must not leak into the payload.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return prefixFindings(a, []string{"debian/"}, "Remove the debian/ directory from the payload.")
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM014", Name: "missing-md5sums", Severity: SeverityWarning,
			Description: "Binary packages should ship an md5sums control member.",
			Reference:   lintianURL,
		},
		run: func(a *deb.Archive) []Finding {
			if len(a.MD5Sums) > 0 {
				return nil
			}

			return []Finding{finding("control archive has no md5sums", "",
				"debsmith writes md5sums automatically; do not strip it.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM015", Name: "md5sum-mismatch", Severity: SeverityError,
			Description: "Declared md5sums must match the payload.",
			Reference:   lintianURL,
		},
		run: func(a *deb.Archive) []Finding {
			audit := a.AuditMD5()
			out := make([]Finding, 0, len(audit.Mismatched))

			for _, entryPath := range audit.Mismatched {
				out = append(out, finding("md5sum does not match payload", entryPath,
					"Rebuild the package; a mismatch means the archive is corrupt."))
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM016", Name: "md5sum-coverage", Severity: SeverityWarning,
			Description: "Every payload file needs an md5sums entry and vice versa.",
			Reference:   lintianURL,
		},
		run: func(a *deb.Archive) []Finding {
			audit := a.AuditMD5()
			out := make([]Finding, 0, len(audit.MissingSums)+len(audit.MissingFiles))

			for _, entryPath := range audit.MissingSums {
				out = append(out, finding("file has no md5sums entry", entryPath,
					"Regenerate md5sums with debsmith build."))
			}

			for _, entryPath := range audit.MissingFiles {
				out = append(out, finding("md5sums entry has no payload file", entryPath,
					"Remove stale md5sums entries."))
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM017", Name: "conffile-missing", Severity: SeverityError,
			Description: "Conffiles must exist in the package payload.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, conffile := range a.Conffiles {
				normalized := strings.TrimPrefix(conffile, "/")
				if _, ok := a.File(normalized); !ok {
					out = append(out, finding("conffile is not present in the payload", conffile,
						"Ship the configuration file or remove it from conffiles."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM018", Name: "conffile-location", Severity: SeverityWarning,
			Description: "Conffiles belong in /etc.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, conffile := range a.Conffiles {
				if !strings.HasPrefix(conffile, "/etc/") {
					out = append(out, finding("conffile outside /etc", conffile,
						"Move configuration files to /etc or stop marking them as conffiles."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM019", Name: "script-executable", Severity: SeverityError,
			Description: "Maintainer scripts must be executable.",
			Reference:   policyMaintainerURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, name := range sortedScriptNames(a) {
				script := a.Scripts[name]
				if script.Mode&0o111 == 0 {
					out = append(out, finding(fmt.Sprintf("%s is not executable", name), "",
						"Install maintainer scripts with mode 0755."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM020", Name: "script-shebang", Severity: SeverityWarning,
			Description: "Maintainer scripts must start with #!/bin/sh.",
			Reference:   policyMaintainerURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, name := range sortedScriptNames(a) {
				script := a.Scripts[name]
				if !strings.HasPrefix(string(script.Data), "#!") {
					out = append(out, finding(fmt.Sprintf("%s has no shebang", name), "",
						"Start maintainer scripts with #!/bin/sh and set -e."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM021", Name: "copyright", Severity: SeverityWarning,
			Description: "Every binary package should ship its copyright file.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			if a.Control.Package == "" {
				return nil
			}

			doc := "usr/share/doc/" + a.Control.Package + "/copyright"
			if _, ok := a.File(doc); ok {
				return nil
			}

			return []Finding{finding("copyright file is missing", doc,
				"Install the license text as usr/share/doc/<package>/copyright.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM022", Name: "changelog", Severity: SeverityInfo,
			Description: "Binary packages normally ship a Debian changelog.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			if a.Control.Package == "" {
				return nil
			}

			prefix := "usr/share/doc/" + a.Control.Package + "/changelog"

			for _, entry := range a.Entries {
				if strings.HasPrefix(entry.Path, prefix) {
					return nil
				}
			}

			return []Finding{finding("Debian changelog is missing", prefix,
				"Ship usr/share/doc/<package>/changelog.gz generated from debian/changelog.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM023", Name: "ownership", Severity: SeverityError,
			Description: "Package payload must be owned by root:root.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			return forEntries(a, func(entry deb.Entry) *Finding {
				if entry.UID == 0 && entry.GID == 0 {
					return nil
				}

				found := finding(fmt.Sprintf("owned by %d:%d", entry.UID, entry.GID), entry.Path,
					"Package archives must use uid 0 and gid 0.")

				return &found
			})
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM024", Name: "broken-symlink", Severity: SeverityWarning,
			Description: "Relative symlinks must resolve inside the package.",
			Reference:   policyFilesURL,
		},
		run: func(a *deb.Archive) []Finding {
			existing := make(map[string]bool, len(a.Entries))
			for _, entry := range a.Entries {
				existing[entry.Path] = true
			}

			var out []Finding

			for _, entry := range a.Entries {
				if entry.Link == "" || strings.HasPrefix(entry.Link, "/") {
					continue
				}

				target := joinLink(entry.Path, entry.Link)
				if target == "" || strings.HasPrefix(target, "../") {
					out = append(out, finding("symlink escapes the package root", entry.Path,
						"Point the link at a path inside the package."))

					continue
				}

				if !existing[target] {
					out = append(out, finding("relative symlink target is missing", entry.Path,
						"Ship the target or link to a path provided by a dependency."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM025", Name: "section", Severity: SeverityWarning,
			Description: "Section should be a known Debian archive section.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			section := a.Control.Section
			if section == "" {
				return []Finding{finding("Section field is empty", "",
					"Set section to a value such as utils, net or libs.")}
			}

			if knownSections[section] {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("unknown section %q", section), "",
				"Use a section listed in Debian Policy.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM026", Name: "priority", Severity: SeverityWarning,
			Description: "Priority must be required, important, standard, optional or extra.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			priority := a.Control.Priority
			if priority == "" {
				return []Finding{finding("Priority field is empty", "",
					"Set priority to optional for ordinary packages.")}
			}

			if knownPriorities[priority] {
				return nil
			}

			return []Finding{finding(fmt.Sprintf("unknown priority %q", priority), "",
				"Use required, important, standard, optional or extra.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM027", Name: "installed-size", Severity: SeverityInfo,
			Description: "Installed-Size should be present and greater than zero.",
			Reference:   policyControlURL,
		},
		run: func(a *deb.Archive) []Finding {
			if a.Control.InstalledSize > 0 {
				return nil
			}

			return []Finding{finding("Installed-Size is missing or zero", "",
				"debsmith computes Installed-Size; declare payload files.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM028", Name: "self-dependency", Severity: SeverityWarning,
			Description: "A package must not depend on itself.",
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			relations := append([]string{}, a.Control.PreDepends...)
			relations = append(relations, a.Control.Depends...)

			for _, relation := range relations {
				name, _ := deb.RelationName(relation)
				if name != "" && name == a.Control.Package {
					out = append(out, finding("package depends on itself", "",
						"Remove the self-referencing dependency."))
				}
			}

			return out
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM029", Name: "extended-description", Severity: SeverityInfo,
			Description: "Packages should explain themselves in an extended description.",
		},
		run: func(a *deb.Archive) []Finding {
			if strings.TrimSpace(a.Control.Extended) != "" {
				return nil
			}

			return []Finding{finding("extended description is empty", "",
				"Add a longer description after the synopsis line.")}
		},
	},
	{
		CheckInfo: CheckInfo{
			Code: "DSM030", Name: "unknown-control-member", Severity: SeverityError,
			Description: "Only known control members are allowed in control.tar.",
			Reference:   lintianURL,
		},
		run: func(a *deb.Archive) []Finding {
			var out []Finding

			for _, name := range sortedControlFileNames(a) {
				known := false

				for _, additional := range deb.AdditionalControlFiles {
					if name == additional {
						known = true
					}
				}

				if !known {
					out = append(out, finding(fmt.Sprintf("unexpected control member %q", name), "",
						"Remove it or add support to debsmith."))
				}
			}

			return out
		},
	},
}

// Lint runs every registered policy check against a package.
func Lint(archive *deb.Archive, artifact string) Report {
	report := Report{
		Artifact:     artifact,
		Package:      archive.Control.Package,
		Version:      archive.Control.Version,
		Architecture: archive.Control.Architecture,
		Checks:       len(checks),
	}

	for _, current := range checks {
		findings := current.run(archive)

		if len(findings) > 50 {
			hidden := len(findings) - 50
			findings = findings[:50]
			findings = append(findings, finding(
				fmt.Sprintf("%d further findings suppressed", hidden), "", ""))
		}

		for _, item := range findings {
			item.Code = current.Code

			if item.Severity == "" {
				item.Severity = current.Severity
			}

			switch item.Severity {
			case SeverityError:
				report.Errors++
			case SeverityWarning:
				report.Warnings++
			default:
				report.Infos++
			}

			report.Findings = append(report.Findings, item)
		}
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		left, right := report.Findings[i], report.Findings[j]

		if left.Severity.Rank() != right.Severity.Rank() {
			return left.Severity.Rank() > right.Severity.Rank()
		}

		if left.Code != right.Code {
			return left.Code < right.Code
		}

		if left.Path != right.Path {
			return left.Path < right.Path
		}

		return left.Message < right.Message
	})

	return report
}

// FailOn reports whether the report meets the given threshold.
func (r *Report) FailOn(threshold string) bool {
	switch strings.ToLower(strings.TrimSpace(threshold)) {
	case "", "error":
		return r.Errors > 0
	case "warning", "warn":
		return r.Errors > 0 || r.Warnings > 0
	case "info", "any":
		return r.Errors+r.Warnings+r.Infos > 0
	case "never", "none":
		return false
	default:
		return r.Errors > 0
	}
}

// CheckInfos returns the metadata of every registered check.
func CheckInfos() []CheckInfo {
	out := make([]CheckInfo, 0, len(checks))

	for _, current := range checks {
		out = append(out, current.CheckInfo)
	}

	return out
}

func forEntries(a *deb.Archive, fn func(deb.Entry) *Finding) []Finding {
	var out []Finding

	for _, entry := range a.Entries {
		if found := fn(entry); found != nil {
			out = append(out, *found)
		}
	}

	return out
}

func prefixFindings(a *deb.Archive, prefixes []string, message string) []Finding {
	var out []Finding

	for _, entry := range a.Entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Path, prefix) {
				out = append(out, finding(message, entry.Path,
					"Choose a policy compliant installation path."))

				break
			}
		}
	}

	return out
}

func sortedScriptNames(a *deb.Archive) []string {
	names := make([]string, 0, len(a.Scripts))

	for name := range a.Scripts {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func sortedControlFileNames(a *deb.Archive) []string {
	names := make([]string, 0, len(a.ControlFiles))

	for name := range a.ControlFiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func joinLink(linkPath, target string) string {
	return path.Clean(path.Join(path.Dir(linkPath), target))
}
