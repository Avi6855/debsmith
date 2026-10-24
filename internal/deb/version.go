// SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
// SPDX-License-Identifier: MIT

package deb

import (
	"strconv"
	"strings"
)

// CompareVersions compares two Debian versions using dpkg semantics.
// It returns -1, 0 or 1 when a is lower than, equal to or greater than b.
func CompareVersions(a, b string) int {
	aEpoch, aUpstream, aRevision := splitVersion(a)
	bEpoch, bUpstream, bRevision := splitVersion(b)

	switch {
	case aEpoch < bEpoch:
		return -1
	case aEpoch > bEpoch:
		return 1
	}

	if cmp := verrevcmp(aUpstream, bUpstream); cmp != 0 {
		return cmp
	}

	return verrevcmp(aRevision, bRevision)
}

func splitVersion(version string) (int, string, string) {
	epoch := 0
	rest := version

	if idx := strings.IndexByte(rest, ':'); idx >= 0 {
		if parsed, err := strconv.Atoi(rest[:idx]); err == nil {
			epoch = parsed
			rest = rest[idx+1:]
		}
	}

	revision := ""
	if idx := strings.LastIndexByte(rest, '-'); idx >= 0 {
		revision = rest[idx+1:]
		rest = rest[:idx]
	}

	return epoch, rest, revision
}

// verrevcmp mirrors dpkg's version comparison for a single component.
func verrevcmp(a, b string) int {
	i, j := 0, 0

	for i < len(a) || j < len(b) {
		firstDiff := 0

		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int

			if i < len(a) {
				ac = versionOrder(a[i])
			}

			if j < len(b) {
				bc = versionOrder(b[j])
			}

			if ac != bc {
				return sign(ac - bc)
			}

			i++
			j++
		}

		for i < len(a) && a[i] == '0' {
			i++
		}

		for j < len(b) && b[j] == '0' {
			j++
		}

		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}

			i++
			j++
		}

		if i < len(a) && isDigit(a[i]) {
			return 1
		}

		if j < len(b) && isDigit(b[j]) {
			return -1
		}

		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}

	return 0
}

func versionOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func sign(value int) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	default:
		return 0
	}
}
