package judge

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// ansiEscapeRe matches ANSI escape sequences:
//   - CSI: ESC [ <params> <final>      (e.g. ESC[2J for clear screen)
//   - OSC: ESC ] ... BEL                (operating-system commands)
//   - Single-shifts: ESC <single char>  (covers a wider net)
//
// Source-of-truth ranges from VT100 / ECMA-48; the regex is intentionally
// conservative — it strips known-bad sequences rather than trying to
// preserve unknown-but-maybe-fine ones.
var ansiEscapeRe = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07]*\x07|.)`)

// wrapperEscapeTokens are literal substrings that have no legitimate
// reason to appear in a tool description and which, if present, suggest
// the attacker is trying to break out of the <untrusted> wrapper in
// the judge prompt or to forge a JSON response. Detecting any of these
// short-circuits the judge to Malicious=true without making an API call.
//
// Lowercased for case-insensitive match. We compare against the
// lowercased candidate.
var wrapperEscapeTokens = []string{
	"</untrusted>",
	"</known>",
	"</system>",
	"</instruction>",
	`{"malicious"`,
	`{ "malicious"`,
	`"malicious":`,
	`"malicious" :`,
	"ignore previous instructions",
	"ignore the previous instructions",
	"system prompt:",
}

// SanitizeResult is what Sanitize returns for one candidate text.
type SanitizeResult struct {
	// Cleaned is the post-sanitization text — what the judge prompt
	// should embed. Empty if Rejected is true.
	Cleaned string

	// Rejected is true when Defense 4 caught a wrapper-escape attempt
	// or a forged-JSON pattern. The orchestrator should short-circuit
	// to Malicious=true without calling the LLM.
	Rejected bool

	// RejectionReason is a short tag for the report. Examples:
	// "wrapper_escape:</untrusted>", "ansi_only", "empty_after_clean".
	RejectionReason string
}

// Sanitize implements Defense 4 (THREAT_MODEL §7). Order of operations:
//
//  1. Strip ANSI escape sequences.
//  2. Normalize Unicode (NFKC) — collapses fullwidth, combining marks,
//     and look-alike characters into canonical form.
//  3. Truncate to MaxCandidateChars.
//  4. Scan for wrapper-escape tokens. If any is found, REJECT.
//
// Sanitize NEVER returns Cleaned text that contains the original ANSI
// or wrapper-escape patterns. If you call Sanitize and proceed to the
// LLM, you can trust Cleaned.
func Sanitize(candidate string) SanitizeResult {
	if candidate == "" {
		return SanitizeResult{Rejected: true, RejectionReason: "empty_input"}
	}

	// 1. Strip ANSI escape sequences.
	cleaned := ansiEscapeRe.ReplaceAllString(candidate, "")

	// 2. Normalize Unicode (NFKC = compatibility composition).
	//    Collapses fullwidth Latin to ASCII, combining marks to
	//    pre-composed forms, etc.
	cleaned = norm.NFKC.String(cleaned)

	// 3. Truncate. We keep the leading window — attackers tend to
	//    front-load the directive, and humans reading the report
	//    see the beginning of the text.
	if len(cleaned) > MaxCandidateChars {
		cleaned = cleaned[:MaxCandidateChars]
	}

	// Trim whitespace AFTER normalization (NFKC may have introduced
	// regular spaces from exotic whitespace characters).
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return SanitizeResult{Rejected: true, RejectionReason: "empty_after_clean"}
	}

	// 4. Wrapper-escape / forged-JSON scan.
	lower := strings.ToLower(cleaned)
	for _, token := range wrapperEscapeTokens {
		if strings.Contains(lower, token) {
			return SanitizeResult{
				Rejected:        true,
				RejectionReason: "wrapper_escape:" + token,
			}
		}
	}

	return SanitizeResult{Cleaned: cleaned}
}
