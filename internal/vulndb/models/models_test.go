package models

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
)

func TestJSONMap_Value(t *testing.T) {
	t.Run("nil_map", func(t *testing.T) {
		var j JSONMap
		val, err := j.Value()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != nil {
			t.Errorf("expected nil, got %v", val)
		}
	})

	t.Run("non_nil_map", func(t *testing.T) {
		j := JSONMap{"key": "value", "num": float64(42)}
		val, err := j.Value()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		s, ok := val.(string)
		if !ok {
			t.Fatalf("expected string, got %T", val)
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(s), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed["key"] != "value" {
			t.Errorf("expected key=value, got %v", parsed["key"])
		}
	})
}

func TestJSONMap_Scan(t *testing.T) {
	t.Run("nil_src", func(t *testing.T) {
		var j JSONMap
		if err := j.Scan(nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if j != nil {
			t.Errorf("expected nil, got %v", j)
		}
	})

	t.Run("string_src", func(t *testing.T) {
		var j JSONMap
		if err := j.Scan(`{"key":"value"}`); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if j["key"] != "value" {
			t.Errorf("expected key=value, got %v", j["key"])
		}
	})

	t.Run("bytes_src", func(t *testing.T) {
		var j JSONMap
		if err := j.Scan([]byte(`{"num":42}`)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if j["num"] != float64(42) {
			t.Errorf("expected num=42, got %v", j["num"])
		}
	})

	t.Run("unsupported_type", func(t *testing.T) {
		var j JSONMap
		err := j.Scan(12345)
		if err == nil {
			t.Error("expected error for unsupported type")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		var j JSONMap
		err := j.Scan(`{invalid}`)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestStringSlice_Value(t *testing.T) {
	t.Run("nil_slice", func(t *testing.T) {
		var s StringSlice
		val, err := s.Value()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != nil {
			t.Errorf("expected nil, got %v", val)
		}
	})

	t.Run("non_empty_slice", func(t *testing.T) {
		s := StringSlice{"a", "b", "c"}
		val, err := s.Value()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		str, ok := val.(string)
		if !ok {
			t.Fatalf("expected string, got %T", val)
		}

		var parsed []string
		if err := json.Unmarshal([]byte(str), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(parsed) != 3 || parsed[0] != "a" {
			t.Errorf("unexpected result: %v", parsed)
		}
	})

	t.Run("empty_slice", func(t *testing.T) {
		s := StringSlice{}
		val, err := s.Value()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val.(string) != "[]" {
			t.Errorf("expected [], got %v", val)
		}
	})
}

func TestStringSlice_Scan(t *testing.T) {
	t.Run("nil_src", func(t *testing.T) {
		var s StringSlice
		if err := s.Scan(nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s != nil {
			t.Errorf("expected nil, got %v", s)
		}
	})

	t.Run("string_src", func(t *testing.T) {
		var s StringSlice
		if err := s.Scan(`["x","y"]`); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(s) != 2 || s[0] != "x" {
			t.Errorf("unexpected result: %v", s)
		}
	})

	t.Run("bytes_src", func(t *testing.T) {
		var s StringSlice
		if err := s.Scan([]byte(`["a","b"]`)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(s) != 2 {
			t.Errorf("expected 2 items, got %d", len(s))
		}
	})

	t.Run("unsupported_type", func(t *testing.T) {
		var s StringSlice
		err := s.Scan(42)
		if err == nil {
			t.Error("expected error for unsupported type")
		}
	})
}

func TestJSONMap_RoundTrip(t *testing.T) {
	original := JSONMap{
		"string": "hello",
		"number": float64(42),
		"nested": map[string]interface{}{"a": "b"},
	}

	val, err := original.Value()
	if err != nil {
		t.Fatal(err)
	}

	var restored JSONMap
	if err := restored.Scan(val); err != nil {
		t.Fatal(err)
	}

	if restored["string"] != "hello" {
		t.Errorf("string field mismatch: %v", restored["string"])
	}
	if restored["number"] != float64(42) {
		t.Errorf("number field mismatch: %v", restored["number"])
	}
}

func TestStringSlice_RoundTrip(t *testing.T) {
	original := StringSlice{"alpha", "beta", "gamma"}

	val, err := original.Value()
	if err != nil {
		t.Fatal(err)
	}

	var restored StringSlice
	if err := restored.Scan(val); err != nil {
		t.Fatal(err)
	}

	if len(restored) != 3 {
		t.Fatalf("expected 3 items, got %d", len(restored))
	}
	for i, expected := range []string{"alpha", "beta", "gamma"} {
		if restored[i] != expected {
			t.Errorf("item %d: got %q, want %q", i, restored[i], expected)
		}
	}
}

func TestAllModels(t *testing.T) {
	models := AllModels()
	if len(models) != 12 {
		t.Errorf("expected 12 models, got %d", len(models))
	}
}

// Verify JSONMap and StringSlice implement driver.Valuer
func TestImplementsDriverValuer(t *testing.T) {
	var _ driver.Valuer = JSONMap{}
	var _ driver.Valuer = StringSlice{}
}

func TestTableNames(t *testing.T) {
	tests := []struct {
		name  string
		table string
	}{
		{"Vulnerability", Vulnerability{}.TableName()},
		{"VulnerabilityAlias", VulnerabilityAlias{}.TableName()},
		{"VulnerabilityRelated", VulnerabilityRelated{}.TableName()},
		{"Severity", Severity{}.TableName()},
		{"Affected", Affected{}.TableName()},
		{"AffectedRange", AffectedRange{}.TableName()},
		{"RangeEvent", RangeEvent{}.TableName()},
		{"Reference", Reference{}.TableName()},
		{"Credit", Credit{}.TableName()},
		{"EcosystemSyncState", EcosystemSyncState{}.TableName()},
		{"SyncLog", SyncLog{}.TableName()},
		{"AffectedPackageIndex", AffectedPackageIndex{}.TableName()},
	}

	expectedTables := map[string]string{
		"Vulnerability":        "vulnerabilities",
		"VulnerabilityAlias":   "vulnerability_aliases",
		"VulnerabilityRelated": "vulnerability_related",
		"Severity":             "severities",
		"Affected":             "affected",
		"AffectedRange":        "affected_ranges",
		"RangeEvent":           "range_events",
		"Reference":            "references",
		"Credit":               "credits",
		"EcosystemSyncState":   "ecosystem_sync_states",
		"SyncLog":              "sync_logs",
		"AffectedPackageIndex": "affected_package_index",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := expectedTables[tt.name]
			if tt.table != expected {
				t.Errorf("expected %q, got %q", expected, tt.table)
			}
		})
	}
}
