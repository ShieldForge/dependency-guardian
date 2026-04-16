// Package vercmp provides ecosystem-aware version comparison functions.
// It supports semver (npm, Go), PEP 440 (PyPI), and Maven versioning
// using the same underlying libraries throughout the codebase.
package vercmp

import (
	"fmt"
	"strconv"
	"strings"

	pepversion "github.com/aquasecurity/go-pep440-version"
	goversion "github.com/hashicorp/go-version"
	mvnversion "github.com/masahiro331/go-mvn-version"
)

// --- Version parsing and manipulation ------------------------------------

// ParsedVersion holds the parsed components of a version string.
type ParsedVersion struct {
	Prefix     string // optional "v" prefix
	Major      int
	Minor      int
	Patch      int
	PreRelease string // everything after the patch number (e.g., "-beta.1")
	Segments   int    // how many numeric segments were present (1, 2, or 3+)
}

// ParseVersion extracts version components from a version string using
// ecosystem-specific parsers. For semver (npm, Go) it uses
// hashicorp/go-version to extract segments and pre-release. For PyPI
// it validates with go-pep440-version and extracts release segments. For
// Maven it validates with go-mvn-version and extracts numeric segments.
// Returns the parsed components and true, or a zero value and false.
func ParseVersion(v, ecosystem string) (ParsedVersion, bool) {
	if v == "" {
		return ParsedVersion{}, false
	}

	switch strings.ToLower(ecosystem) {
	case "pypi":
		return parsePyPIVersion(v)
	case "maven":
		return parseMavenVersion(v)
	default: // npm, go, and anything else
		return parseSemver(v)
	}
}

// parseSemver parses a version using hashicorp/go-version and extracts
// the major/minor/patch segments and pre-release string.
func parseSemver(v string) (ParsedVersion, bool) {
	gv, err := goversion.NewVersion(v)
	if err != nil {
		return ParsedVersion{}, false
	}

	pv := ParsedVersion{}

	// Detect "v" prefix from the original string.
	if strings.HasPrefix(v, "v") {
		pv.Prefix = "v"
	}

	segs := gv.Segments()
	pv.Segments = len(segs)
	if pv.Segments > 3 {
		pv.Segments = 3
	}
	if len(segs) >= 1 {
		pv.Major = segs[0]
	}
	if len(segs) >= 2 {
		pv.Minor = segs[1]
	}
	if len(segs) >= 3 {
		pv.Patch = segs[2]
	}

	if pr := gv.Prerelease(); pr != "" {
		pv.PreRelease = "-" + pr
	}
	if md := gv.Metadata(); md != "" {
		pv.PreRelease += "+" + md
	}

	return pv, true
}

// parsePyPIVersion validates a version with go-pep440-version, then
// extracts the numeric release segments and any pre/post/dev suffix.
func parsePyPIVersion(v string) (ParsedVersion, bool) {
	pep, err := pepversion.Parse(v)
	if err != nil {
		return ParsedVersion{}, false
	}

	// BaseVersion() returns the release portion (e.g. "1.2.3") without
	// pre/post/dev suffixes.
	base := pep.BaseVersion()
	pv := extractSegments(base)

	// Everything after the base release is the pre-release/suffix.
	if len(v) > len(base) {
		pv.PreRelease = v[len(base):]
	}

	return pv, true
}

// parseMavenVersion validates a version with go-mvn-version, then
// extracts the numeric segments and any qualifier suffix.
func parseMavenVersion(v string) (ParsedVersion, bool) {
	_, err := mvnversion.NewVersion(v)
	if err != nil {
		return ParsedVersion{}, false
	}

	return extractSegments(v), true
}

// extractSegments is a helper that splits a version string into numeric
// major/minor/patch components and a trailing non-numeric suffix.
func extractSegments(v string) ParsedVersion {
	pv := ParsedVersion{}

	if strings.HasPrefix(v, "v") {
		pv.Prefix = "v"
		v = v[1:]
	}

	// Split off non-numeric suffix.
	numPart := v
	for i, c := range v {
		if c == '-' || c == '+' {
			numPart = v[:i]
			pv.PreRelease = v[i:]
			break
		}
		if c != '.' && (c < '0' || c > '9') {
			numPart = v[:i]
			pv.PreRelease = v[i:]
			break
		}
	}

	parts := strings.SplitN(numPart, ".", 3)
	if len(parts) == 0 {
		return pv
	}

	if major, err := strconv.Atoi(parts[0]); err == nil {
		pv.Major = major
		pv.Segments = 1
	}
	if len(parts) >= 2 {
		if minor, err := strconv.Atoi(parts[1]); err == nil {
			pv.Minor = minor
			pv.Segments = 2
		}
	}
	if len(parts) >= 3 {
		if patch, err := strconv.Atoi(parts[2]); err == nil {
			pv.Patch = patch
			pv.Segments = 3
		}
	}

	return pv
}

// Format reconstructs a version string from parsed components.
func (pv ParsedVersion) Format() string {
	switch pv.Segments {
	case 1:
		return fmt.Sprintf("%s%d%s", pv.Prefix, pv.Major, pv.PreRelease)
	case 2:
		return fmt.Sprintf("%s%d.%d%s", pv.Prefix, pv.Major, pv.Minor, pv.PreRelease)
	default:
		return fmt.Sprintf("%s%d.%d.%d%s", pv.Prefix, pv.Major, pv.Minor, pv.Patch, pv.PreRelease)
	}
}

// Compare compares two version strings using ecosystem-specific parsing.
//
//   - "npm" and "go" use hashicorp/go-version (semver).
//   - "pypi" uses aquasecurity/go-pep440-version.
//   - "maven" uses masahiro331/go-mvn-version.
//
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func Compare(a, b, ecosystem string) int {
	switch strings.ToLower(ecosystem) {
	case "pypi":
		return ComparePyPI(a, b)
	case "maven":
		return CompareMaven(a, b)
	default: // npm, go, and anything else
		return CompareSemver(a, b)
	}
}

// ComparerFor returns a version comparison function appropriate for the
// given constraint type and ecosystem. SEMVER constraints always use
// semver comparison. ECOSYSTEM constraints dispatch to the ecosystem-
// specific library (Maven, PyPI, or semver as fallback).
func ComparerFor(constraintType, ecosystem string) func(a, b string) int {
	if constraintType == "SEMVER" {
		return CompareSemver
	}
	switch ecosystem {
	case "Maven":
		return CompareMaven
	case "PyPI":
		return ComparePyPI
	default:
		return CompareSemver
	}
}

// CompareSemver compares versions using hashicorp/go-version (semver).
func CompareSemver(a, b string) int {
	va, errA := goversion.NewVersion(a)
	vb, errB := goversion.NewVersion(b)
	if errA != nil || errB != nil {
		return Fallback(a, b)
	}
	return va.Compare(vb)
}

// CompareMaven compares versions using masahiro331/go-mvn-version.
func CompareMaven(a, b string) int {
	va, errA := mvnversion.NewVersion(a)
	vb, errB := mvnversion.NewVersion(b)
	if errA != nil || errB != nil {
		return Fallback(a, b)
	}
	return va.Compare(vb)
}

// ComparePyPI compares versions using aquasecurity/go-pep440-version.
func ComparePyPI(a, b string) int {
	va, errA := pepversion.Parse(a)
	vb, errB := pepversion.Parse(b)
	if errA != nil || errB != nil {
		return Fallback(a, b)
	}
	return va.Compare(vb)
}

// Fallback is a simple lexicographic comparison used when the
// ecosystem-specific parser fails to parse a version string.
func Fallback(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
