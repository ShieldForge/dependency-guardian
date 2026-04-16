// Package rewrite provides version and name rewriting for dependency requests.
// It allows administrators to define rules that transparently redirect or
// replace dependency versions (and optionally names) based on configurable
// strategies such as pinning, snapping to the nearest minor/major release,
// or enforcing minimum/maximum version bounds.
package rewrite

import (
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"dependency-guardian/internal/config"
	"dependency-guardian/internal/vercmp"
)

// Engine applies rewrite rules to dependency requests.
type Engine struct {
	rules  []config.RewriteRule
	logger *slog.Logger
}

// Result holds the outcome of a rewrite operation.
type Result struct {
	// Matched is true if a rule matched the input.
	Matched bool
	// Name is the (possibly rewritten) package name.
	Name string
	// Version is the (possibly rewritten) version string.
	Version string
	// Mode indicates how the rewrite should be applied: "transparent" or "redirect".
	Mode string
}

// New creates a new rewrite engine from the given rules.
func New(rules []config.RewriteRule, logger *slog.Logger) *Engine {
	return &Engine{rules: rules, logger: logger}
}

// Apply checks the rewrite rules against the given ecosystem, package name,
// and version. The first matching rule wins. If no rule matches, the original
// name and version are returned with Matched=false.
func (e *Engine) Apply(ecosystem, name, version string) Result {
	result := Result{
		Name:    name,
		Version: version,
		Mode:    "transparent",
	}

	for _, rule := range e.rules {
		if !matchesRule(rule.Match, ecosystem, name, version) {
			continue
		}

		result.Matched = true

		if rule.Rewrite.Name != "" {
			result.Name = rule.Rewrite.Name
		}

		if rule.Rewrite.Version != nil {
			newVer := applyVersionStrategy(version, rule.Rewrite.Version, ecosystem)
			if newVer != version {
				e.logger.Debug("version rewritten",
					"ecosystem", ecosystem,
					"package", name,
					"from", version,
					"to", newVer,
					"strategy", rule.Rewrite.Version.Strategy,
				)
			}
			result.Version = newVer
		}

		if rule.Rewrite.Mode != "" {
			result.Mode = rule.Rewrite.Mode
		}

		break // first match wins
	}

	return result
}

// ApplyWithAvailable applies the rewrite rules and then verifies
// that the rewritten version exists in the list of available versions.
// If the exact rewritten version is not available, it finds the closest
// match using the same major.minor prefix (for nearest-minor) or
// major prefix (for nearest-major). If no suitable version is found,
// the original version is returned unchanged.
func (e *Engine) ApplyWithAvailable(ecosystem, name, version string, available []string) Result {
	result := e.Apply(ecosystem, name, version)
	if !result.Matched || result.Version == version {
		return result
	}

	// Check if the rewritten version exists in available versions.
	for _, av := range available {
		if av == result.Version {
			return result
		}
	}

	// Rewritten version not available; find the closest match.
	closest := findClosestVersion(result.Version, available, ecosystem)
	if closest != "" {
		e.logger.Debug("rewritten version not available, using closest",
			"target", result.Version,
			"closest", closest,
			"package", name,
		)
		result.Version = closest
	} else {
		// No suitable version found; revert to original.
		e.logger.Warn("rewritten version not available and no close match found",
			"target", result.Version,
			"package", name,
			"original", version,
		)
		result.Version = version
		result.Matched = false
	}

	return result
}

// matchesRule checks whether a rule's match criteria apply to the given
// ecosystem, package name, and version.
func matchesRule(match config.RewriteMatch, ecosystem, name, version string) bool {
	if match.Ecosystem != "" && !strings.EqualFold(match.Ecosystem, ecosystem) {
		return false
	}

	if match.Name != "" && match.Name != "*" {
		matched, _ := filepath.Match(match.Name, name)
		if !matched {
			return false
		}
	}

	if match.Version != "" && match.Version != "*" {
		matched, _ := filepath.Match(match.Version, version)
		if !matched {
			return false
		}
	}

	return true
}

// applyVersionStrategy transforms a version string according to the
// given rewrite strategy.
func applyVersionStrategy(version string, vr *config.VersionRewrite, ecosystem string) string {
	switch vr.Strategy {
	case "pin":
		return vr.Target
	case "nearest-minor":
		return snapToMinor(version, ecosystem)
	case "nearest-major":
		return snapToMajor(version, ecosystem)
	case "min":
		return applyMin(version, vr.Target, ecosystem)
	case "max":
		return applyMax(version, vr.Target, ecosystem)
	case "replace-major":
		return replaceMajor(version, vr.Target, ecosystem)
	case "replace-minor":
		return replaceMinor(version, vr.Target, ecosystem)
	case "replace-patch":
		return replacePatch(version, vr.Target, ecosystem)
	default:
		return version
	}
}

// snapToMinor zeroes out the patch component: "1.2.3" -> "1.2.0".
func snapToMinor(version, ecosystem string) string {
	pv, ok := vercmp.ParseVersion(version, ecosystem)
	if !ok {
		return version
	}
	pv.Patch = 0
	pv.PreRelease = ""
	if pv.Segments < 3 {
		pv.Segments = 3
	}
	return pv.Format()
}

// snapToMajor zeroes out the minor and patch components: "1.2.3" -> "1.0.0".
func snapToMajor(version, ecosystem string) string {
	pv, ok := vercmp.ParseVersion(version, ecosystem)
	if !ok {
		return version
	}
	pv.Minor = 0
	pv.Patch = 0
	pv.PreRelease = ""
	if pv.Segments < 3 {
		pv.Segments = 3
	}
	return pv.Format()
}

// applyMin returns the target version if the input is less than the target.
func applyMin(version, target, ecosystem string) string {
	if vercmp.Compare(version, target, ecosystem) < 0 {
		return target
	}
	return version
}

// applyMax returns the target version if the input is greater than the target.
func applyMax(version, target, ecosystem string) string {
	if vercmp.Compare(version, target, ecosystem) > 0 {
		return target
	}
	return version
}

// replaceMajor replaces the major version component.
// E.g., replaceMajor("1.2.3", "2") -> "2.2.3".
func replaceMajor(version, target, ecosystem string) string {
	pv, ok := vercmp.ParseVersion(version, ecosystem)
	if !ok {
		return version
	}
	major, err := strconv.Atoi(target)
	if err != nil {
		return version
	}
	pv.Major = major
	return pv.Format()
}

// replaceMinor replaces the minor version component.
// E.g., replaceMinor("1.2.3", "5") -> "1.5.3".
func replaceMinor(version, target, ecosystem string) string {
	pv, ok := vercmp.ParseVersion(version, ecosystem)
	if !ok {
		return version
	}
	minor, err := strconv.Atoi(target)
	if err != nil {
		return version
	}
	pv.Minor = minor
	if pv.Segments < 2 {
		pv.Segments = 2
	}
	return pv.Format()
}

// replacePatch replaces the patch version component.
// E.g., replacePatch("1.2.3", "0") -> "1.2.0".
func replacePatch(version, target, ecosystem string) string {
	pv, ok := vercmp.ParseVersion(version, ecosystem)
	if !ok {
		return version
	}
	patch, err := strconv.Atoi(target)
	if err != nil {
		return version
	}
	pv.Patch = patch
	if pv.Segments < 3 {
		pv.Segments = 3
	}
	return pv.Format()
}

// findClosestVersion finds the version from available that is closest
// to the target version, preferring the same major.minor prefix.
// It uses ecosystem-aware version comparison for distance calculation.
func findClosestVersion(target string, available []string, ecosystem string) string {
	pt, ok := vercmp.ParseVersion(target, ecosystem)
	if !ok {
		return ""
	}

	var bestSameMinor, bestSameMajor, bestAny string
	var bestSameMinorAbs, bestSameMajorAbs, bestAnyAbs int = -1, -1, -1

	for _, av := range available {
		pa, ok := vercmp.ParseVersion(av, ecosystem)
		if !ok {
			continue
		}

		// Use the ecosystem-aware comparison to determine ordering,
		// then use parsed numeric distance for closest matching.
		cmp := vercmp.Compare(av, target, ecosystem)
		// Distance: linear numeric distance for accurate proximity.
		avNum := pa.Major*1000000 + pa.Minor*1000 + pa.Patch
		targetNum := pt.Major*1000000 + pt.Minor*1000 + pt.Patch
		dist := abs(avNum - targetNum)
		// Bias: prefer versions above the target so we pick a higher
		// safe candidate rather than a lower one at equal distance.
		if cmp < 0 {
			dist++ // slight penalty for being below target
		}

		if pa.Major == pt.Major && pa.Minor == pt.Minor {
			if bestSameMinorAbs < 0 || dist < bestSameMinorAbs {
				bestSameMinor = av
				bestSameMinorAbs = dist
			}
		}

		if pa.Major == pt.Major {
			if bestSameMajorAbs < 0 || dist < bestSameMajorAbs {
				bestSameMajor = av
				bestSameMajorAbs = dist
			}
		}

		if bestAnyAbs < 0 || dist < bestAnyAbs {
			bestAny = av
			bestAnyAbs = dist
		}
	}

	// Prefer same minor > same major > any.
	if bestSameMinor != "" {
		return bestSameMinor
	}
	if bestSameMajor != "" {
		return bestSameMajor
	}
	return bestAny
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
