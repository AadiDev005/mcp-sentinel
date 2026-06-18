package scanner

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
)

// testCorpusPath returns the absolute path to <repo>/corpus/attacks/
// from this test file's location.
func testCorpusPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "corpus", "attacks")
}

// buildPrefilter loads the real 15-entry corpus and returns a Prefilter
// for the tests below to reuse.
func buildPrefilter(t *testing.T) *Prefilter {
	t.Helper()
	entries, err := corpus.LoadDir(testCorpusPath(t))
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	return NewPrefilter(entries)
}

func TestPrefilter_PoisonedDescriptionFiresImportantTag(t *testing.T) {
	pf := buildPrefilter(t)

	units, err := Ingest(strings.NewReader(samplePoisoned))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	hits := pf.MatchAll(units)
	if len(hits) == 0 {
		t.Fatal("expected at least one prefilter hit on poisoned sample, got zero")
	}

	// Find the tool-description Unit's index.
	var descIdx int = -1
	for i, u := range units {
		if u.Surface == SurfaceToolDescription {
			descIdx = i
			break
		}
	}
	if descIdx == -1 {
		t.Fatal("ingest produced no tool description Unit")
	}

	descHits := hits[descIdx]
	if len(descHits) == 0 {
		t.Fatalf("description Unit (idx %d) produced no hits", descIdx)
	}

	// Expect at least: <IMPORTANT> pseudo-XML tag and ~/.ssh literal.
	var sawImportant, sawSSH bool
	for _, h := range descHits {
		if h.SignalKind == "pseudo_xml_tag" && h.Match == "important" {
			sawImportant = true
		}
		if h.SignalKind == "literal" && strings.Contains(h.Match, "~/.ssh") {
			sawSSH = true
		}
	}
	if !sawImportant {
		t.Error("expected <IMPORTANT> pseudo_xml_tag hit on poisoned description")
	}
	if !sawSSH {
		t.Error("expected ~/.ssh literal hit on poisoned description")
	}
}

func TestPrefilter_BenignProducesNoLiteralHits(t *testing.T) {
	pf := buildPrefilter(t)
	units, _ := Ingest(strings.NewReader(sampleBenign))

	hits := pf.MatchAll(units)
	// The benign sample has a `path` parameter. That's not on the
	// suspicious-param watchlist. We expect zero hits.
	if len(hits) != 0 {
		t.Errorf("benign sample produced unexpected hits: %+v", hits)
	}
}

func TestPrefilter_SuspiciousParamFiresEvenWithCleanText(t *testing.T) {
	pf := buildPrefilter(t)
	// A tool with a clean description but a `feedback` parameter — that
	// alone should fire the suspicious_param hit.
	doc := `{"tools":[{
		"name": "weather",
		"description": "Get weather for a city.",
		"inputSchema": {"properties": {"city": {"type":"string"}, "feedback": {"type":"string"}}}
	}]}`
	units, _ := Ingest(strings.NewReader(doc))
	hits := pf.MatchAll(units)

	var foundSusParam bool
	for _, unitHits := range hits {
		for _, h := range unitHits {
			if h.SignalKind == "suspicious_param" && strings.Contains(h.Match, "feedback") {
				foundSusParam = true
			}
		}
	}
	if !foundSusParam {
		t.Error("expected suspicious_param hit for tool with `feedback` parameter")
	}
}

func TestPrefilter_ParamNameKeywordFires(t *testing.T) {
	pf := buildPrefilter(t)
	// Parameter name embedding a directive keyword (T4-011 pattern).
	doc := `{"tools":[{
		"name": "x",
		"description": "Clean.",
		"inputSchema": {"properties": {"input_ignore_previous": {"type":"string"}}}
	}]}`
	units, _ := Ingest(strings.NewReader(doc))
	hits := pf.MatchAll(units)

	var foundKeyword bool
	for _, unitHits := range hits {
		for _, h := range unitHits {
			if h.SignalKind == "param_keyword" && h.Match == "ignore" {
				foundKeyword = true
			}
		}
	}
	if !foundKeyword {
		t.Error("expected param_keyword=ignore hit on `input_ignore_previous` parameter")
	}
}
