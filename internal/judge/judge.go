// Package judge is Stage 3 of the pipeline: a structurally-defended
// LLM-as-judge that resolves the borderline cases surfaced by Stage 2
// (embedding retrieval).
//
// The judge ingests adversary-controlled text — the Unit body could
// contain prompt-injection instructions aimed at the judge itself. The
// four documented defenses (THREAT_MODEL §7, ARCHITECTURE §7) live in
// this package:
//
//  1. XML-wrapped untrusted input (prompt convention)
//  2. JSON-schema-enforced response via Anthropic tool_use (structural)
//  3. Self-consistency paraphrase on borderline confidence (mitigation)
//  4. Heuristic prefilter on judge input (defense-in-depth)
//
// The Judge interface is the contract every backend satisfies; v0.1
// ships an Anthropic-Claude implementation. A future OpenAI backend
// would be a constructor swap.
package judge

import (
	"context"
	"errors"
)

// Verdict is what the judge returns for one (Unit, CorpusMatch) pair.
type Verdict struct {
	// Malicious is the final yes/no. This is the only field the
	// downstream report uses for severity rendering.
	Malicious bool

	// Confidence is the judge's self-reported certainty in [0, 1].
	// Used by self-consistency: borderline values trigger a re-judge.
	Confidence float64

	// Reasoning is logged only — never re-fed into another prompt.
	// Capped at 500 chars by the schema so a runaway model can't dump
	// arbitrary text.
	Reasoning string

	// Defense4Triggered is true when the heuristic prefilter rejected
	// the input outright (e.g. it contained a literal `</untrusted>`
	// tag). In that case the judge short-circuited with Malicious=true
	// without an API call. Recorded so reports can show it.
	Defense4Triggered bool

	// Inconsistent is true when self-consistency re-judge produced a
	// different answer than the first call. Verdict is the conservative
	// fallback (Malicious=false) but the report can flag it for human
	// review.
	Inconsistent bool

	// JudgeName is the underlying model identifier, e.g.
	// "anthropic:claude-3-5-haiku-latest". Copied into Finding.
	JudgeName string
}

// JudgeInput is the bundle the judge needs: the suspicious candidate
// text and one specific corpus entry to compare it against. Stage 2
// produces N matches per Unit; the orchestrator calls the judge once
// per (Unit, top-match) pair, not N times.
type JudgeInput struct {
	// CandidateText is the Unit.Text under investigation. Adversary-
	// controlled — sanitize before sending to the LLM.
	CandidateText string

	// CandidateSurface tells the judge where the text came from
	// (tool_description / schema_property / parameter_name). The
	// judge's prompt uses this hint.
	CandidateSurface string

	// KnownAttackID is the corpus entry ID (e.g. "T1-001"). Logged
	// into the response for traceability.
	KnownAttackID string

	// KnownAttackText is the verbatim corpus payload — the example we
	// ask "is the candidate the same attack as this?"
	KnownAttackText string

	// KnownAttackCategory is the T-ID category (e.g. "T1"). Used in
	// the prompt.
	KnownAttackCategory string

	// JudgeQuestion is the corpus entry's judge_hints.primary_question.
	// Steers the model toward the right evidence.
	JudgeQuestion string

	// ExpectedEvidence is the corpus entry's judge_hints.expected_evidence
	// list. Given to the model as the rubric.
	ExpectedEvidence []string
}

// Judge is the interface every backend satisfies.
type Judge interface {
	// Judge returns a Verdict for one (Unit, Match) pair. Implementations
	// MUST apply the four defenses internally — callers never see the
	// raw LLM output.
	Judge(ctx context.Context, in JudgeInput) (Verdict, error)

	// Name is the model identifier copied into Verdict.JudgeName, e.g.
	// "anthropic:claude-3-5-haiku-latest".
	Name() string
}

// Sentinel errors. Package-level vars so callers can errors.Is against
// them.
var (
	// ErrEmptyInput is returned for empty candidate or attack text —
	// nothing to judge.
	ErrEmptyInput = errors.New("judge: candidate or attack text is empty")

	// ErrSchemaViolation is returned when the LLM response cannot be
	// coerced into the expected schema even after the tool_use call.
	// Should be vanishingly rare; surfaced so the orchestrator can log
	// it instead of producing a Verdict from garbage.
	ErrSchemaViolation = errors.New("judge: LLM response violated response schema")
)

// BorderlineLow and BorderlineHigh define the confidence band that
// triggers self-consistency re-judging. Outside this band the verdict
// stands as-is.
const (
	BorderlineLow  = 0.3
	BorderlineHigh = 0.7
)

// MaxCandidateChars caps the candidate text we send to the LLM. Real
// MCP tool descriptions are well under this; the cap exists so an
// adversary cannot stuff 100 KB of confounding text into one prompt.
const MaxCandidateChars = 8000
