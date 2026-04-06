# Guardian Default Policy
#
# This policy is evaluated for every package version that flows through
# the proxy. It produces a set of denial reasons – if the set is empty
# the version is allowed; otherwise it is filtered out.
#
# Input schema:
#   input.package.name          string
#   input.package.version       string
#   input.package.ecosystem     "npm" | "pypi" | "go"
#   input.package.published_at  RFC 3339 timestamp
#   input.package.deprecated    bool
#   input.package.yanked        bool
#   input.vulnerabilities[_]    {id, severity, summary, fixed_in, is_malicious}

package guardian

import rego.v1

# ── Malicious packages ──────────────────────────────────────────────
# Deny any version flagged as malicious by the vulnerability database.
deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.is_malicious == true
	msg := sprintf("package %s@%s is flagged as malicious (advisory %s)", [
		input.package.name,
		input.package.version,
		vuln.id,
	])
}

# ── Critical / High severity vulnerabilities ────────────────────────
# Deny versions with critical or high severity vulnerabilities.
deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.severity == "critical"
	msg := sprintf("package %s@%s has critical vulnerability %s: %s", [
		input.package.name,
		input.package.version,
		vuln.id,
		vuln.summary,
	])
}

deny contains msg if {
	some vuln in input.vulnerabilities
	vuln.severity == "high"
	msg := sprintf("package %s@%s has high-severity vulnerability %s: %s", [
		input.package.name,
		input.package.version,
		vuln.id,
		vuln.summary,
	])
}

# ── Minimum age requirement ─────────────────────────────────────────
# Deny packages published less than 7 days ago.
# This gives the community time to discover issues.
deny contains msg if {
	input.package.published_at != "0001-01-01T00:00:00Z"
	published := time.parse_rfc3339_ns(input.package.published_at)
	now := time.now_ns()
	age_days := (now - published) / (24 * 60 * 60 * 1000000000)
	age_days < 7
	msg := sprintf("package %s@%s was published less than 7 days ago (minimum age policy)", [
		input.package.name,
		input.package.version,
	])
}

# ── Yanked / unpublished versions ────────────────────────────────────
deny contains msg if {
	input.package.yanked == true
	msg := sprintf("package %s@%s has been yanked/unpublished", [
		input.package.name,
		input.package.version,
	])
}
