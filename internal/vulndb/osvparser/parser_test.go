package osvparser

import (
	"encoding/json"
	"testing"
)

func TestParseJSON_MinimalRecord(t *testing.T) {
	raw := `{
		"id": "GHSA-test-0001",
		"modified": "2024-06-15T12:00:00Z",
		"summary": "Test vulnerability"
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if vuln.OsvID != "GHSA-test-0001" {
		t.Errorf("expected GHSA-test-0001, got %s", vuln.OsvID)
	}
	if vuln.Summary != "Test vulnerability" {
		t.Errorf("unexpected summary: %s", vuln.Summary)
	}
	if vuln.Modified.IsZero() {
		t.Error("modified should not be zero")
	}
}

func TestParseJSON_FullRecord(t *testing.T) {
	raw := `{
		"schema_version": "1.6.0",
		"id": "GHSA-full-0001",
		"modified": "2024-06-15T12:00:00Z",
		"published": "2024-01-01T00:00:00Z",
		"aliases": ["CVE-2024-0001", "CVE-2024-0002"],
		"related": ["GHSA-related-001"],
		"summary": "Full test vulnerability",
		"details": "Detailed description",
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
		],
		"affected": [
			{
				"package": {
					"ecosystem": "npm",
					"name": "lodash",
					"purl": "pkg:npm/lodash"
				},
				"severity": [
					{"type": "CVSS_V3", "score": "9.8"}
				],
				"ranges": [
					{
						"type": "SEMVER",
						"events": [
							{"introduced": "0"},
							{"fixed": "4.17.21"}
						]
					}
				],
				"versions": ["4.17.19", "4.17.20"],
				"ecosystem_specific": {"severity": "critical"},
				"database_specific": {"source": "test"}
			}
		],
		"references": [
			{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-full-0001"},
			{"type": "WEB", "url": "https://example.com"}
		],
		"credits": [
			{"name": "Alice", "contact": ["alice@example.com"], "type": "FINDER"}
		],
		"database_specific": {"cwe_ids": ["CWE-79"]}
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if vuln.SchemaVersion != "1.6.0" {
		t.Errorf("expected schema_version 1.6.0, got %s", vuln.SchemaVersion)
	}
	if vuln.OsvID != "GHSA-full-0001" {
		t.Errorf("expected GHSA-full-0001, got %s", vuln.OsvID)
	}
	if vuln.Published == nil {
		t.Error("published should not be nil")
	}

	// Aliases
	if len(vuln.Aliases) != 2 {
		t.Errorf("expected 2 aliases, got %d", len(vuln.Aliases))
	}

	// Related
	if len(vuln.Related) != 1 {
		t.Errorf("expected 1 related, got %d", len(vuln.Related))
	}

	// Severities
	if len(vuln.Severities) != 1 {
		t.Errorf("expected 1 severity, got %d", len(vuln.Severities))
	}
	if vuln.Severities[0].Type != "CVSS_V3" {
		t.Errorf("expected CVSS_V3, got %s", vuln.Severities[0].Type)
	}

	// Affected
	if len(vuln.Affected) != 1 {
		t.Fatalf("expected 1 affected, got %d", len(vuln.Affected))
	}
	aff := vuln.Affected[0]
	if aff.PackageEcosystem != "npm" {
		t.Errorf("expected npm, got %s", aff.PackageEcosystem)
	}
	if aff.PackageName != "lodash" {
		t.Errorf("expected lodash, got %s", aff.PackageName)
	}
	if aff.PackagePURL != "pkg:npm/lodash" {
		t.Errorf("expected purl, got %s", aff.PackagePURL)
	}
	if len(aff.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(aff.Versions))
	}
	if len(aff.Severities) != 1 {
		t.Errorf("expected 1 per-affected severity, got %d", len(aff.Severities))
	}

	// Ranges
	if len(aff.Ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(aff.Ranges))
	}
	r := aff.Ranges[0]
	if r.Type != "SEMVER" {
		t.Errorf("expected SEMVER, got %s", r.Type)
	}
	if len(r.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(r.Events))
	}
	if r.Events[0].Introduced != "0" {
		t.Errorf("expected introduced=0, got %s", r.Events[0].Introduced)
	}
	if r.Events[1].Fixed != "4.17.21" {
		t.Errorf("expected fixed=4.17.21, got %s", r.Events[1].Fixed)
	}

	// References
	if len(vuln.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(vuln.References))
	}

	// Credits
	if len(vuln.Credits) != 1 {
		t.Errorf("expected 1 credit, got %d", len(vuln.Credits))
	}
	if vuln.Credits[0].Name != "Alice" {
		t.Errorf("expected Alice, got %s", vuln.Credits[0].Name)
	}
	if len(vuln.Credits[0].Contact) != 1 {
		t.Errorf("expected 1 contact, got %d", len(vuln.Credits[0].Contact))
	}

	// Source ecosystem derived from first affected
	if vuln.SourceEcosystem != "npm" {
		t.Errorf("expected source ecosystem npm, got %s", vuln.SourceEcosystem)
	}

	// Database specific
	if vuln.DatabaseSpecific == nil {
		t.Error("expected database_specific to be set")
	}
}

func TestParseJSON_InvalidJSON(t *testing.T) {
	_, err := ParseJSON([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJSON_MissingModified(t *testing.T) {
	_, err := ParseJSON([]byte(`{"id": "TEST-001"}`))
	if err == nil {
		t.Error("expected error for missing modified timestamp")
	}
}

func TestParseJSON_WithdrawnRecord(t *testing.T) {
	raw := `{
		"id": "GHSA-withdrawn",
		"modified": "2024-06-15T12:00:00Z",
		"withdrawn": "2024-06-14T00:00:00Z"
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}
	if vuln.Withdrawn == nil {
		t.Error("withdrawn should not be nil")
	}
}

func TestParseJSON_NoAffected(t *testing.T) {
	raw := `{
		"id": "GHSA-no-affected",
		"modified": "2024-06-15T12:00:00Z"
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}
	if len(vuln.Affected) != 0 {
		t.Errorf("expected 0 affected, got %d", len(vuln.Affected))
	}
	if vuln.SourceEcosystem != "" {
		t.Errorf("expected empty source ecosystem, got %s", vuln.SourceEcosystem)
	}
}

func TestParseJSON_MultipleEcosystems(t *testing.T) {
	raw := `{
		"id": "GHSA-multi-eco",
		"modified": "2024-06-15T12:00:00Z",
		"affected": [
			{
				"package": {"ecosystem": "npm", "name": "pkg-npm"},
				"versions": ["1.0.0"]
			},
			{
				"package": {"ecosystem": "PyPI", "name": "pkg-pypi"},
				"versions": ["2.0.0"]
			}
		]
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}
	if len(vuln.Affected) != 2 {
		t.Errorf("expected 2 affected, got %d", len(vuln.Affected))
	}
	// Source ecosystem should be first affected's
	if vuln.SourceEcosystem != "npm" {
		t.Errorf("expected source npm, got %s", vuln.SourceEcosystem)
	}
}

func TestParseJSON_GitRangeType(t *testing.T) {
	raw := `{
		"id": "GHSA-git-range",
		"modified": "2024-06-15T12:00:00Z",
		"affected": [
			{
				"package": {"ecosystem": "Go", "name": "example.com/mod"},
				"ranges": [
					{
						"type": "GIT",
						"repo": "https://github.com/example/mod",
						"events": [
							{"introduced": "abc123"},
							{"fixed": "def456"}
						]
					}
				]
			}
		]
	}`

	vuln, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	r := vuln.Affected[0].Ranges[0]
	if r.Type != "GIT" {
		t.Errorf("expected GIT, got %s", r.Type)
	}
	if r.Repo != "https://github.com/example/mod" {
		t.Errorf("expected repo URL, got %s", r.Repo)
	}
}

func TestConvert_NilPackage(t *testing.T) {
	raw := &RawVulnerability{
		ID:       "TEST-nil-pkg",
		Modified: "2024-06-15T12:00:00Z",
		Affected: []RawAffected{
			{
				Package:  nil,
				Versions: []string{"1.0.0"},
			},
		},
	}

	vuln, err := Convert(raw)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}
	if len(vuln.Affected) != 1 {
		t.Errorf("expected 1 affected, got %d", len(vuln.Affected))
	}
	if vuln.Affected[0].PackageEcosystem != "" {
		t.Errorf("expected empty ecosystem for nil package, got %s", vuln.Affected[0].PackageEcosystem)
	}
}

func TestParseJSON_TimestampFormats(t *testing.T) {
	tests := []struct {
		name     string
		modified string
		wantErr  bool
	}{
		{"rfc3339_nano", "2024-06-15T12:00:00.123456789Z", false},
		{"rfc3339", "2024-06-15T12:00:00Z", false},
		{"iso_no_tz", "2024-06-15T12:00:00", false},
		{"invalid", "not-a-date", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{"id": "TEST-` + tt.name + `", "modified": "` + tt.modified + `"}`
			_, err := ParseJSON([]byte(raw))
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRawVulnerability_JSONRoundTrip(t *testing.T) {
	raw := RawVulnerability{
		ID:       "TEST-roundtrip",
		Modified: "2024-06-15T12:00:00Z",
		Aliases:  []string{"CVE-2024-001"},
	}

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	var parsed RawVulnerability
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.ID != raw.ID {
		t.Errorf("expected %s, got %s", raw.ID, parsed.ID)
	}
}
