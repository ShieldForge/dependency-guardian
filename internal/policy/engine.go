// Package policy provides an OPA/Rego policy evaluation engine that
// determines whether individual package versions are allowed.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	reg "dependency-guardian/internal/registry"
)

// Engine evaluates package versions against loaded Rego policies.
type Engine struct {
	mu       sync.RWMutex
	compiler *ast.Compiler
	store    storage.Store
	prepared rego.PreparedEvalQuery
}

// NewEngine creates a new policy engine and loads all .rego files from dir.
func NewEngine(dir string) (*Engine, error) {
	modules, err := loadRegoFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("loading rego files: %w", err)
	}

	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: true,
	})
	if err != nil {
		return nil, fmt.Errorf("compiling rego modules: %w", err)
	}

	store := inmem.New()

	prepared, err := rego.New(
		rego.Query("data.guardian.deny"),
		rego.Compiler(compiler),
		rego.Store(store),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("preparing rego query: %w", err)
	}

	return &Engine{
		compiler: compiler,
		store:    store,
		prepared: prepared,
	}, nil
}

// Evaluate runs the policy against a single package version and returns
// whether it is allowed along with any violation reasons.
func (e *Engine) Evaluate(ctx context.Context, input reg.PolicyInput) (reg.PolicyResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rs, err := e.prepared.Eval(ctx, rego.EvalInput(toMap(input)))
	if err != nil {
		return reg.PolicyResult{}, fmt.Errorf("evaluating policy: %w", err)
	}

	reasons := extractReasons(rs)

	return reg.PolicyResult{
		Allowed: len(reasons) == 0,
		Reasons: reasons,
	}, nil
}

// Reload re-reads all .rego files from the given directory and
// recompiles the policy modules. This allows live policy updates.
func (e *Engine) Reload(dir string) error {
	modules, err := loadRegoFiles(dir)
	if err != nil {
		return fmt.Errorf("loading rego files: %w", err)
	}

	compiler, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
		EnablePrintStatements: true,
	})
	if err != nil {
		return fmt.Errorf("compiling rego modules: %w", err)
	}

	prepared, err := rego.New(
		rego.Query("data.guardian.deny"),
		rego.Compiler(compiler),
		rego.Store(e.store),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("preparing rego query: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.compiler = compiler
	e.prepared = prepared
	return nil
}

// loadRegoFiles walks a directory and returns a map of filename -> rego source.
func loadRegoFiles(dir string) (map[string]string, error) {
	modules := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".rego") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		modules[path] = string(data)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("no .rego files found in %s", dir)
	}

	return modules, nil
}

// toMap converts a PolicyInput to map[string]interface{} for OPA input.
func toMap(input reg.PolicyInput) map[string]interface{} {
	vulns := make([]interface{}, len(input.Vulnerabilities))
	for i, v := range input.Vulnerabilities {
		vulns[i] = map[string]interface{}{
			"id":           v.ID,
			"severity":     v.Severity,
			"summary":      v.Summary,
			"fixed_in":     v.FixedIn,
			"is_malicious": v.IsMalicious,
		}
	}

	m := map[string]interface{}{
		"package": map[string]interface{}{
			"name":         input.Package.Name,
			"version":      input.Package.Version,
			"ecosystem":    string(input.Package.Ecosystem),
			"published_at": input.Package.PublishedAt.Format("2006-01-02T15:04:05Z"),
			"deprecated":   input.Package.Deprecated,
			"yanked":       input.Package.Yanked,
		},
		"vulnerabilities": vulns,
	}

	if input.Metadata != nil {
		m["metadata"] = input.Metadata
	}

	return m
}

// extractReasons pulls string reasons from the OPA result set.
// The policy is expected to produce a set of strings under data.guardian.deny.
func extractReasons(rs rego.ResultSet) []string {
	var reasons []string

	for _, result := range rs {
		for _, expr := range result.Expressions {
			switch v := expr.Value.(type) {
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						reasons = append(reasons, s)
					}
				}
			case map[string]interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						reasons = append(reasons, s)
					}
				}
			}
		}
	}

	return reasons
}
