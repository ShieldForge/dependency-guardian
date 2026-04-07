// Package vercmp provides ecosystem-aware version comparison functions.
// It supports semver (npm, Go), PEP 440 (PyPI), and Maven versioning
// using the same underlying libraries throughout the codebase.
package vercmp

import (
	"strings"

	pepversion "github.com/aquasecurity/go-pep440-version"
	goversion "github.com/hashicorp/go-version"
	mvnversion "github.com/masahiro331/go-mvn-version"
)

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
