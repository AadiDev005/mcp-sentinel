// Package scanner is the top-level orchestrator. It defines the core
// types every other package agrees on: Unit (what gets scanned), Finding
// (what gets reported), and Surface (where the suspicious text lives).
//
// Pipeline order: ingest -> prefilter -> embed -> judge -> report.
// See ARCHITECTURE.md for the full data flow.
package scanner

// Surface tells us where in the MCP tool definition the scannable text
// came from. We use this both for reporting ("the description matched")
// and as part of the embedder input — the same string in a description
// is more suspicious than in a schema example.
type Surface string

const (
	// SurfaceToolDescription is the top-level `description` of a tool.
	SurfaceToolDescription Surface = "tool_description"
	// SurfaceToolName is the tool's `name` field.
	SurfaceToolName Surface = "tool_name"
	// SurfaceSchemaProperty is a `description`, `title`, or `examples`
	// field nested inside the input schema's `properties`.
	SurfaceSchemaProperty Surface = "schema_property"
	// SurfaceParameterName is the literal key of a property in
	// `inputSchema.properties` — the parameter name itself.
	SurfaceParameterName Surface = "parameter_name"
)

// UnitContext is structural information we collect during ingest that
// the embedder + judge use in addition to Unit.Text. None of these are
// detection signals on their own — they're context the later stages
// reason about.
type UnitContext struct {
	// SuspiciousParameters are parameter names of THIS tool that appear
	// on the exfil-channel watchlist (see T5-006 corpus entry).
	SuspiciousParameters []string

	// ReferencedTools are tool names mentioned inside Unit.Text — useful
	// for shadowing detection (T2-002, T2-014).
	ReferencedTools []string

	// ReferencedServers are MCP server names mentioned inside Unit.Text.
	ReferencedServers []string

	// LongWhitespaceRuns is true if Unit.Text contains ≥40 consecutive
	// spaces — the "visual exfiltration" signature from T8-003.
	LongWhitespaceRuns bool
}

// Unit is the atomic thing the scanner reasons about. One Unit per
// scannable surface per tool. See ARCHITECTURE.md §2 for why
// per-surface, not per-tool.
type Unit struct {
	// ToolName is the name of the parent tool (for reporting).
	ToolName string

	// Surface tells which kind of field this Unit came from.
	Surface Surface

	// Path is a dotted JSONPath-style locator back to the original
	// document, e.g. "tools[3].inputSchema.properties.query.description".
	// Lets users open the source file at the exact line.
	Path string

	// Text is the actual string the scanner inspects.
	Text string

	// Context is structural data the embedder + judge use.
	Context UnitContext
}

// Finding is one detection result emitted by the scanner.
type Finding struct {
	ToolName      string
	Surface       Surface
	Path          string
	CorpusID      string  // e.g. "T1-001"
	Category      string  // e.g. "T1"
	Severity      string  // low | medium | high | critical
	Similarity    float32 // cosine similarity to the matched corpus entry
	Malicious     bool    // judge verdict
	Confidence    float64
	EvidenceQuote string // short snippet of the matched text
	SourceURL     string // upstream attack source from corpus YAML
}
