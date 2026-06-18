package scanner

import (
	"strings"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
)

// PrefilterHit is one signal that fired for one Unit. A single Unit can
// produce multiple hits (e.g. it contains both "<IMPORTANT>" and
// "~/.ssh"). Stage 2 (embed) uses the presence/absence of any hit as
// the routing gate; the specific corpus_ids attached are advisory only.
type PrefilterHit struct {
	UnitIndex int      // index into the Units slice the caller passed in
	SignalKind string  // literal | pseudo_xml_tag | param_keyword | suspicious_param
	Match      string  // the matched substring or token
	CorpusIDs  []string // corpus entries whose signals include this match
}

// Prefilter compiles all signals from a corpus and exposes the cheap
// matching step. It is safe to call Match concurrently from many
// goroutines once built.
type Prefilter struct {
	// literalToCorpus maps each lowercase literal substring to the set
	// of corpus IDs that reference it. We do case-insensitive matching
	// since attackers vary capitalization (<IMPORTANT> vs <Important>).
	literalToCorpus map[string][]string

	// pseudoXMLTags is the set of pseudo-XML tag names (without angle
	// brackets) that flag a Unit. We check for "<NAME>" or "<NAME "
	// anywhere in the text.
	pseudoXMLTags map[string][]string

	// paramKeywords is the watchlist for SurfaceParameterName Units.
	// If a parameter name contains any of these as a substring, fire.
	paramKeywords map[string][]string
}

// NewPrefilter builds a Prefilter from the union of signals across all
// corpus entries. Called once at scanner startup; cheap to keep around.
func NewPrefilter(entries []corpus.Entry) *Prefilter {
	pf := &Prefilter{
		literalToCorpus: make(map[string][]string),
		pseudoXMLTags:   make(map[string][]string),
		paramKeywords:   make(map[string][]string),
	}

	for _, e := range entries {
		for _, s := range e.Signals.LiteralSubstrings {
			if s == "" {
				continue
			}
			key := strings.ToLower(s)
			pf.literalToCorpus[key] = appendUnique(pf.literalToCorpus[key], e.ID)
		}
		for _, s := range e.Signals.ConcealmentPhrases {
			if s == "" {
				continue
			}
			key := strings.ToLower(s)
			pf.literalToCorpus[key] = appendUnique(pf.literalToCorpus[key], e.ID)
		}
		for _, tag := range e.Signals.PseudoXMLTags {
			if tag == "" {
				continue
			}
			key := strings.ToLower(tag)
			pf.pseudoXMLTags[key] = appendUnique(pf.pseudoXMLTags[key], e.ID)
		}
		for _, kw := range e.Signals.ParamNameKeywords {
			if kw == "" {
				continue
			}
			key := strings.ToLower(kw)
			pf.paramKeywords[key] = appendUnique(pf.paramKeywords[key], e.ID)
		}
		// suspicious_param_names from T5-006 are already enforced at
		// ingest time via UnitContext.SuspiciousParameters, so we don't
		// duplicate them here. Same with attack_verbs — those drift in
		// surface form too much to be useful as exact substrings; we
		// leave verb matching to the embedder.
	}

	return pf
}

// appendUnique appends s to xs iff s is not already present. Keeps the
// per-key corpus-ID lists small and free of duplicates.
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// Match runs the prefilter against a Unit and returns every hit.
// Returns nil if no signal fires.
//
// Implementation note: this is a naive substring scan, not Aho-Corasick.
// At v0.1 we have ~80 unique literals across the corpus and Units are
// typically <2 KB of text, so the cost of a naive scan is well under a
// millisecond per Unit. If literal count grows past a few hundred, swap
// in an Aho-Corasick implementation (no API change required).
func (pf *Prefilter) Match(u Unit, unitIndex int) []PrefilterHit {
	var hits []PrefilterHit
	lowerText := strings.ToLower(u.Text)

	// 1. Literal substring scan. Hits include the corpus IDs whose
	//    signals.literal_substrings or concealment_phrases listed the
	//    matched string.
	for literal, ids := range pf.literalToCorpus {
		if strings.Contains(lowerText, literal) {
			hits = append(hits, PrefilterHit{
				UnitIndex:  unitIndex,
				SignalKind: "literal",
				Match:      literal,
				CorpusIDs:  ids,
			})
		}
	}

	// 2. Pseudo-XML tag scan. We look for "<tag>" or "<tag " (with a
	//    space, in case the attacker added attributes). Case-insensitive
	//    via lowerText.
	for tag, ids := range pf.pseudoXMLTags {
		open1 := "<" + tag + ">"
		open2 := "<" + tag + " "
		if strings.Contains(lowerText, open1) || strings.Contains(lowerText, open2) {
			hits = append(hits, PrefilterHit{
				UnitIndex:  unitIndex,
				SignalKind: "pseudo_xml_tag",
				Match:      tag,
				CorpusIDs:  ids,
			})
		}
	}

	// 3. Parameter-name keyword scan, only for SurfaceParameterName.
	//    The keyword needs only to appear as a substring — that's
	//    enough to catch obfuscated names like `f_IMPORTANT_dump`.
	if u.Surface == SurfaceParameterName {
		for kw, ids := range pf.paramKeywords {
			if strings.Contains(lowerText, kw) {
				hits = append(hits, PrefilterHit{
					UnitIndex:  unitIndex,
					SignalKind: "param_keyword",
					Match:      kw,
					CorpusIDs:  ids,
				})
			}
		}
	}

	// 4. Suspicious-parameter context. We surface this hit only on the
	//    tool description (the canonical "tool surface"), not on every
	//    Unit that shares context. Otherwise a tool with one suspicious
	//    param would generate N copies of the same hit — pure noise.
	//    Tagging with T5-006 (exfil-channel corpus entry).
	if u.Surface == SurfaceToolDescription && len(u.Context.SuspiciousParameters) > 0 {
		hits = append(hits, PrefilterHit{
			UnitIndex:  unitIndex,
			SignalKind: "suspicious_param",
			Match:      strings.Join(u.Context.SuspiciousParameters, ","),
			CorpusIDs:  []string{"T5-006"},
		})
	}

	return hits
}

// MatchAll runs the prefilter over a slice of Units and returns hits
// grouped by Unit index. Convenience wrapper for the scan orchestrator.
func (pf *Prefilter) MatchAll(units []Unit) map[int][]PrefilterHit {
	out := make(map[int][]PrefilterHit)
	for i, u := range units {
		if h := pf.Match(u, i); len(h) > 0 {
			out[i] = h
		}
	}
	return out
}
