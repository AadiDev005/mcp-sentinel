// Package corpus loads the curated attack corpus that the embedding
// retrieval stage compares candidate tool descriptions against.
//
// Status: stub. Schema is defined in /CORPUS.md (Day 4 deliverable).
package corpus

// Entry is a single curated attack example.
type Entry struct {
	ID       string // e.g. "TP-007"
	Category string
	Severity string
	Payload  string // the malicious text we'll embed
	Source   string // paper citation / scanner repo URL
}

// Load reads corpus entries from disk. To be implemented Day 4.
func Load(path string) ([]Entry, error) {
	return nil, nil
}
