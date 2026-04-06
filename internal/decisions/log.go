// Package decisions provides an in-memory decision log that records
// policy evaluation results for packages passing through the proxy.
// It is designed for the VS Code extension mode where developers need
// visibility into what is being allowed or blocked.
package decisions

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Entry represents a single policy decision made by the proxy.
type Entry struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Ecosystem       string    `json:"ecosystem"`
	Package         string    `json:"package"`
	Version         string    `json:"version"`
	Allowed         bool      `json:"allowed"`
	Reasons         []string  `json:"reasons,omitempty"`
	Vulnerabilities int       `json:"vulnerabilities"`
}

// Stats holds aggregate statistics about proxy decisions.
type Stats struct {
	TotalRequests     int64            `json:"total_requests"`
	TotalAllowed      int64            `json:"total_allowed"`
	TotalDenied       int64            `json:"total_denied"`
	ByEcosystem       map[string]int64 `json:"by_ecosystem"`
	DeniedByEcosystem map[string]int64 `json:"denied_by_ecosystem"`
	RecentDenied      []Entry          `json:"recent_denied"`
	Uptime            string           `json:"uptime"`
}

// Log is a thread-safe, bounded decision log.
type Log struct {
	mu        sync.RWMutex
	entries   []Entry
	maxSize   int
	nextID    int64
	startTime time.Time

	totalRequests int64
	totalAllowed  int64
	totalDenied   int64
	byEcosystem   map[string]int64
	deniedByEco   map[string]int64
}

// NewLog creates a new decision log with the given maximum size.
func NewLog(maxSize int) *Log {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Log{
		entries:     make([]Entry, 0, maxSize),
		maxSize:     maxSize,
		startTime:   time.Now(),
		byEcosystem: make(map[string]int64),
		deniedByEco: make(map[string]int64),
	}
}

// Record adds a decision entry to the log.
func (l *Log) Record(ecosystem, pkg, version string, allowed bool, reasons []string, vulnCount int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.nextID++
	entry := Entry{
		ID:              l.nextID,
		Timestamp:       time.Now(),
		Ecosystem:       ecosystem,
		Package:         pkg,
		Version:         version,
		Allowed:         allowed,
		Reasons:         reasons,
		Vulnerabilities: vulnCount,
	}

	l.totalRequests++
	l.byEcosystem[ecosystem]++
	if allowed {
		l.totalAllowed++
	} else {
		l.totalDenied++
		l.deniedByEco[ecosystem]++
	}

	if len(l.entries) >= l.maxSize {
		// Shift entries to make room (ring buffer behavior).
		copy(l.entries, l.entries[1:])
		l.entries[len(l.entries)-1] = entry
	} else {
		l.entries = append(l.entries, entry)
	}
}

// Recent returns the most recent n entries (newest first).
func (l *Log) Recent(n int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	total := len(l.entries)
	if n <= 0 || n > total {
		n = total
	}

	result := make([]Entry, n)
	for i := 0; i < n; i++ {
		result[i] = l.entries[total-1-i]
	}
	return result
}

// GetStats returns aggregate statistics.
func (l *Log) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	byEco := make(map[string]int64, len(l.byEcosystem))
	for k, v := range l.byEcosystem {
		byEco[k] = v
	}
	deniedByEco := make(map[string]int64, len(l.deniedByEco))
	for k, v := range l.deniedByEco {
		deniedByEco[k] = v
	}

	// Collect recent denied entries.
	var recentDenied []Entry
	for i := len(l.entries) - 1; i >= 0 && len(recentDenied) < 50; i-- {
		if !l.entries[i].Allowed {
			recentDenied = append(recentDenied, l.entries[i])
		}
	}

	return Stats{
		TotalRequests:     l.totalRequests,
		TotalAllowed:      l.totalAllowed,
		TotalDenied:       l.totalDenied,
		ByEcosystem:       byEco,
		DeniedByEcosystem: deniedByEco,
		RecentDenied:      recentDenied,
		Uptime:            time.Since(l.startTime).Truncate(time.Second).String(),
	}
}

// HandleDecisions is an HTTP handler that returns recent decisions as JSON.
func (l *Log) HandleDecisions(w http.ResponseWriter, r *http.Request) {
	n := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if parsed, err := strconv.Atoi(q); err == nil && parsed > 0 && parsed <= 1000 {
			n = parsed
		}
	}

	filter := r.URL.Query().Get("filter") // "allowed", "denied", or "" for all

	entries := l.Recent(n)

	if filter == "denied" {
		filtered := entries[:0]
		for _, e := range entries {
			if !e.Allowed {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	} else if filter == "allowed" {
		filtered := entries[:0]
		for _, e := range entries {
			if e.Allowed {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// HandleStats is an HTTP handler that returns aggregate stats as JSON.
func (l *Log) HandleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(l.GetStats())
}
