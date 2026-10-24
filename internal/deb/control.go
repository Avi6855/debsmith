// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Field is a single deb822 control field.
type Field struct {
	Name  string
	Value string
}

// Fields preserves the order of deb822 fields.
type Fields struct {
	list []Field
}

// NewFields returns an empty field set.
func NewFields() *Fields {
	return &Fields{}
}

// Len reports the number of fields.
func (f *Fields) Len() int {
	return len(f.list)
}

// All returns a copy of the fields in order.
func (f *Fields) All() []Field {
	out := make([]Field, len(f.list))
	copy(out, f.list)

	return out
}

// Get returns the value of a field, case-insensitively.
func (f *Fields) Get(name string) string {
	for _, field := range f.list {
		if strings.EqualFold(field.Name, name) {
			return field.Value
		}
	}

	return ""
}

// Has reports whether a field exists.
func (f *Fields) Has(name string) bool {
	for _, field := range f.list {
		if strings.EqualFold(field.Name, name) {
			return true
		}
	}

	return false
}

// Set inserts or replaces a field, preserving its position.
func (f *Fields) Set(name, value string) {
	for i := range f.list {
		if strings.EqualFold(f.list[i].Name, name) {
			f.list[i].Value = value

			return
		}
	}

	f.list = append(f.list, Field{Name: name, Value: value})
}

// Delete removes a field.
func (f *Fields) Delete(name string) {
	out := f.list[:0]

	for _, field := range f.list {
		if !strings.EqualFold(field.Name, name) {
			out = append(out, field)
		}
	}

	f.list = out
}

// Render serialises the fields as a deb822 stanza.
func (f *Fields) Render() []byte {
	var b strings.Builder

	for _, field := range f.list {
		lines := strings.Split(field.Value, "\n")

		b.WriteString(field.Name)
		b.WriteString(": ")
		b.WriteString(lines[0])
		b.WriteByte('\n')

		for _, line := range lines[1:] {
			if line == "" || line == "." {
				b.WriteString(" .\n")
			} else {
				b.WriteByte(' ')
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}

	return []byte(b.String())
}

// ParseFields parses the first deb822 stanza in data. Any trailing stanzas are
// ignored; every caller in debsmith works with single-stanza documents.
func ParseFields(data []byte) (*Fields, error) {
	f := NewFields()

	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	current := -1

	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			if f.Len() == 0 {
				continue
			}

			break
		}

		if line[0] == ' ' || line[0] == '\t' {
			if current < 0 {
				return nil, fmt.Errorf("deb822: continuation line before any field: %q", line)
			}

			f.list[current].Value += "\n" + strings.TrimRight(line[1:], " \t")

			continue
		}

		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			return nil, fmt.Errorf("deb822: invalid line %q", line)
		}

		name := strings.TrimSpace(line[:idx])
		if name == "" || strings.ContainsAny(name, " \t") {
			return nil, fmt.Errorf("deb822: invalid field name %q", name)
		}

		value := strings.TrimLeft(line[idx+1:], " \t")

		f.list = append(f.list, Field{Name: name, Value: strings.TrimRight(value, " \t")})
		current = len(f.list) - 1
	}

	if f.Len() == 0 {
		return nil, errors.New("deb822: empty control stanza")
	}

	return f, nil
}

// Control is the binary package metadata kept in control.tar.
type Control struct {
	Package       string
	Source        string
	Version       string
	Architecture  string
	Maintainer    string
	InstalledSize int64
	Section       string
	Priority      string
	MultiArch     string
	Essential     bool
	Homepage      string
	Description   string
	Extended      string
	PreDepends    []string
	Depends       []string
	Recommends    []string
	Suggests      []string
	Enhances      []string
	Breaks        []string
	Conflicts     []string
	Replaces      []string
	Provides      []string
	BuiltUsing    string
	Extra         map[string]string
}

// Fields renders the control stanza in canonical field order.
func (c *Control) Fields() *Fields {
	f := NewFields()
	add := func(name, value string) {
		if strings.TrimSpace(value) != "" {
			f.Set(name, value)
		}
	}

	add("Package", c.Package)
	add("Source", c.Source)
	add("Version", c.Version)
	add("Architecture", c.Architecture)
	add("Maintainer", c.Maintainer)

	if c.InstalledSize > 0 {
		add("Installed-Size", strconv.FormatInt(c.InstalledSize, 10))
	}

	add("Section", c.Section)
	add("Priority", c.Priority)

	if c.MultiArch != "" && c.MultiArch != "no" {
		add("Multi-Arch", c.MultiArch)
	}

	if c.Essential {
		add("Essential", "yes")
	}

	add("Pre-Depends", strings.Join(c.PreDepends, ", "))
	add("Depends", strings.Join(c.Depends, ", "))
	add("Recommends", strings.Join(c.Recommends, ", "))
	add("Suggests", strings.Join(c.Suggests, ", "))
	add("Enhances", strings.Join(c.Enhances, ", "))
	add("Breaks", strings.Join(c.Breaks, ", "))
	add("Conflicts", strings.Join(c.Conflicts, ", "))
	add("Replaces", strings.Join(c.Replaces, ", "))
	add("Provides", strings.Join(c.Provides, ", "))
	add("Built-Using", c.BuiltUsing)
	add("Homepage", c.Homepage)

	if c.Description != "" {
		description := c.Description
		if c.Extended != "" {
			description += "\n" + c.Extended
		}

		add("Description", description)
	}

	keys := make([]string, 0, len(c.Extra))
	for key := range c.Extra {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		if !f.Has(key) && strings.TrimSpace(c.Extra[key]) != "" {
			f.Set(key, c.Extra[key])
		}
	}

	return f
}

// Render serialises the control stanza.
func (c *Control) Render() []byte {
	return c.Fields().Render()
}

// ParseControl parses a control stanza into typed fields.
func ParseControl(data []byte) (*Control, *Fields, error) {
	fields, err := ParseFields(data)
	if err != nil {
		return nil, nil, err
	}

	c := &Control{
		Package:      fields.Get("Package"),
		Source:       fields.Get("Source"),
		Version:      fields.Get("Version"),
		Architecture: fields.Get("Architecture"),
		Maintainer:   fields.Get("Maintainer"),
		Section:      fields.Get("Section"),
		Priority:     fields.Get("Priority"),
		MultiArch:    fields.Get("Multi-Arch"),
		Essential:    strings.EqualFold(fields.Get("Essential"), "yes"),
		Homepage:     fields.Get("Homepage"),
		PreDepends:   SplitRelations(fields.Get("Pre-Depends")),
		Depends:      SplitRelations(fields.Get("Depends")),
		Recommends:   SplitRelations(fields.Get("Recommends")),
		Suggests:     SplitRelations(fields.Get("Suggests")),
		Enhances:     SplitRelations(fields.Get("Enhances")),
		Breaks:       SplitRelations(fields.Get("Breaks")),
		Conflicts:    SplitRelations(fields.Get("Conflicts")),
		Replaces:     SplitRelations(fields.Get("Replaces")),
		Provides:     SplitRelations(fields.Get("Provides")),
		BuiltUsing:   fields.Get("Built-Using"),
		Extra:        map[string]string{},
	}

	if value := fields.Get("Installed-Size"); value != "" {
		size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("control: invalid Installed-Size %q", value)
		}

		c.InstalledSize = size
	}

	c.Description, c.Extended = SplitDescription(fields.Get("Description"))

	known := map[string]bool{
		"Package": true, "Source": true, "Version": true, "Architecture": true,
		"Maintainer": true, "Installed-Size": true, "Section": true, "Priority": true,
		"Multi-Arch": true, "Essential": true, "Pre-Depends": true, "Depends": true,
		"Recommends": true, "Suggests": true, "Enhances": true, "Breaks": true,
		"Conflicts": true, "Replaces": true, "Provides": true, "Built-Using": true,
		"Homepage": true, "Description": true,
	}

	for _, field := range fields.All() {
		if !known[field.Name] {
			c.Extra[field.Name] = field.Value
		}
	}

	return c, fields, nil
}

// SplitDescription separates the synopsis from the extended description.
func SplitDescription(value string) (string, string) {
	rows := strings.Split(value, "\n")
	synopsis := strings.TrimSpace(rows[0])

	if len(rows) == 1 {
		return synopsis, ""
	}

	return synopsis, strings.TrimRight(strings.Join(rows[1:], "\n"), "\n")
}

// SplitRelations splits a comma separated dependency field.
func SplitRelations(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))

	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// RelationName extracts the package name and version constraint from a
// dependency relation such as "libc6 (>= 2.38) [amd64]" or "foo | bar".
func RelationName(relation string) (string, string) {
	first := strings.TrimSpace(strings.SplitN(relation, "|", 2)[0])

	name := first
	for _, sep := range []string{" ", "(", "[", "<", ":"} {
		if idx := strings.Index(name, sep); idx >= 0 {
			name = name[:idx]
		}
	}

	version := ""
	if start := strings.Index(first, "("); start >= 0 {
		if end := strings.Index(first[start:], ")"); end >= 0 {
			version = strings.TrimSpace(first[start+1 : start+end])
		}
	}

	return strings.TrimSpace(name), version
}
