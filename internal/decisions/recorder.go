package decisions

// Recorder is the interface handlers use to record policy decisions.
// When nil (not in VS Code mode), no decisions are recorded.
type Recorder interface {
	Record(ecosystem, pkg, version string, allowed bool, reasons []string, vulnCount int)
}
