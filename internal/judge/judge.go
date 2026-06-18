// Package judge is the LLM-as-judge stage. Runs only on the top-k
// candidates surfaced by the embedding retrieval stage.
//
// Status: stub. The structural defenses (XML-bounded untrusted input,
// json_schema response, self-consistency, heuristic pre-filter) are
// documented in ARCHITECTURE.md.
package judge

// Verdict is what the judge returns for a single (tool, corpus-match) pair.
type Verdict struct {
	Malicious  bool
	Confidence float64
	Reasoning  string // never shown to downstream prompts; logged only
}

// Judge inspects a candidate match and decides if it's a true positive.
type Judge interface {
	Judge(toolDescription, matchedAttack string) (Verdict, error)
}
