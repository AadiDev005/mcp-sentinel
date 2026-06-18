// Package scanner is the orchestrator: input → embed → judge → report.
//
// Status: stub. Interface shape only.
package scanner

// Tool is a parsed MCP tool definition. Only the metadata fields the
// scanner inspects are kept here. Fields are added as detectors need them.
type Tool struct {
	Name        string
	Description string
	Schema      string
}

// Finding is a single detection result.
type Finding struct {
	Tool       string
	Category   string // matches CORPUS.md taxonomy
	Severity   string // low | medium | high | critical
	Confidence float64
	Evidence   string // why we flagged this
	CorpusRef  string // ID into corpus, e.g. "TP-007"
}

// Scanner is the top-level interface every detection backend satisfies.
type Scanner interface {
	Scan(tools []Tool) ([]Finding, error)
}
