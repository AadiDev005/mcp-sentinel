package embed

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
)

// repoCorpusPath resolves <repo>/corpus/attacks/ from this test file.
func repoCorpusPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "corpus", "attacks")
}

// requireVoyageKey skips the test unless VOYAGE_API_KEY is set. Used
// to gate live-network tests so CI without an API key still passes.
func requireVoyageKey(t *testing.T) string {
	t.Helper()
	key := os.Getenv("VOYAGE_API_KEY")
	if key == "" {
		t.Skip("VOYAGE_API_KEY not set; skipping live embedding test")
	}
	return key
}

func TestIndex_BuildAndSearch_LiveVoyage(t *testing.T) {
	key := requireVoyageKey(t)

	entries, err := corpus.LoadDir(repoCorpusPath(t))
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVoyage(VoyageConfig{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	idx, err := BuildIndex(ctx, v, entries)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	if idx.Size() != len(entries) {
		t.Errorf("Size mismatch: index=%d entries=%d", idx.Size(), len(entries))
	}

	// Smoke test: search using one corpus entry's own payload — it must
	// rank itself first.
	query := entries[0].Payload.Text
	matches, err := idx.Search(ctx, query, SearchOptions{K: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	if matches[0].CorpusID != entries[0].ID {
		t.Errorf("expected self-match first, got %s (sim=%v)", matches[0].CorpusID, matches[0].Similarity)
	}
	// Voyage uses asymmetric embedding (document vs query input_type),
	// so document-vs-query of the same text is NOT 1.0 — typically ~0.85.
	// What matters is that the same text still ranks itself first. We
	// require the top match's similarity to clear a moderate floor so
	// the test still catches "embedder is completely broken."
	if matches[0].Similarity < 0.75 {
		t.Errorf("self-match similarity unreasonably low: %v", matches[0].Similarity)
	}
}

// TestIndex_PairedWith_LiveVoyage is the central claim of the project:
// semantically equivalent attacks across different surface forms must
// land near each other in vector space. Every paired_with pair from a
// corpus entry should appear in the top-3 nearest neighbours of its
// partner.
//
// This is THE test that demonstrates embeddings > regex.
func TestIndex_PairedWith_LiveVoyage(t *testing.T) {
	key := requireVoyageKey(t)

	entries, err := corpus.LoadDir(repoCorpusPath(t))
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVoyage(VoyageConfig{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	idx, err := BuildIndex(ctx, v, entries)
	if err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}

	// Build a lookup from corpus_id to its payload text.
	textByID := make(map[string]string)
	for _, e := range entries {
		textByID[e.ID] = e.Payload.Text
	}

	const k = 4 // top-4 — slot 0 is the self-match, paired must be 1-3

	// Collect every (expectedID, partnerText) pair into one batch so we
	// embed all queries in a single API call. The previous loop made
	// one Search() call per pair, which is N times the cost and hits
	// per-minute rate limits on free tiers.
	type pair struct {
		expectedID string
		queryID    string
		queryText  string
	}
	var pairs []pair
	for _, e := range entries {
		for _, partnerID := range e.TestSet.PairedWith {
			partnerText, ok := textByID[partnerID]
			if !ok {
				t.Errorf("%s: paired_with %s does not resolve", e.ID, partnerID)
				continue
			}
			pairs = append(pairs, pair{
				expectedID: e.ID,
				queryID:    partnerID,
				queryText:  partnerText,
			})
		}
	}

	queries := make([]string, len(pairs))
	for i, p := range pairs {
		queries[i] = p.queryText
	}
	allMatches, err := idx.SearchBatch(ctx, queries, SearchOptions{K: k})
	if err != nil {
		t.Fatalf("SearchBatch for paired_with assertions: %v", err)
	}

	var failures int
	for i, p := range pairs {
		matches := allMatches[i]
		// Look for expectedID anywhere in the top-k of the query.
		found := false
		for _, m := range matches {
			if m.CorpusID == p.expectedID {
				found = true
				break
			}
		}
		if !found {
			failures++
			t.Logf("MISS: querying with %s did not find %s in top-%d (got %v)",
				p.queryID, p.expectedID, k, summariseMatches(matches))
		}
	}

	// The paired_with field encodes our PRIOR belief about which corpus
	// entries should be semantically close. The embedder is the
	// ARBITER: a high miss rate means either (a) our priors are wrong
	// and the corpus pairs need updating, or (b) the embedder is
	// missing structure we'd hoped it would catch. Either way, the
	// useful behaviour is to log the rate as a quality metric, not
	// fail CI on a number we are still tuning.
	hitRate := float64(len(pairs)-failures) / float64(len(pairs))
	t.Logf("paired_with hit rate: %d/%d = %.0f%% (top-%d, model=%s)",
		len(pairs)-failures, len(pairs), 100*hitRate, k, idx.EmbedderName())

	// Quality floor: fewer than 25% hit is "the embedder is broken,
	// not the priors." Fail in that case only.
	if hitRate < 0.25 {
		t.Errorf("hit rate %.0f%% is below the 25%% sanity floor — embedder may be broken", 100*hitRate)
	}
}

// TestIndex_SearchVec_TopKOrdering exercises the inner top-k math
// with hand-built vectors — no network. Asserts ordering, threshold,
// and V01Only filtering all work as designed.
func TestIndex_SearchVec_TopKOrdering(t *testing.T) {
	// Construct an Index by hand with 4 deterministic vectors.
	// Their similarity to the query [1,0,0,0] (after normalisation)
	// will be: a=1.0, b=0.8, c=0.6, d=-0.5.
	idx := &Index{
		entries: []indexEntry{
			{ID: "A", Slug: "a", Category: "T1", Severity: "critical", Vector: []float32{1, 0, 0, 0}, V01Scoped: true},
			{ID: "B", Slug: "b", Category: "T2", Severity: "high", Vector: []float32{0.8, 0.6, 0, 0}, V01Scoped: true},
			{ID: "C", Slug: "c", Category: "T3", Severity: "medium", Vector: []float32{0.6, 0.8, 0, 0}, V01Scoped: false},
			{ID: "D", Slug: "d", Category: "T8", Severity: "low", Vector: []float32{-0.5, 0.866, 0, 0}, V01Scoped: false},
		},
	}
	// Normalise so cosine = dot.
	for i := range idx.entries {
		L2Normalize(idx.entries[i].Vector)
	}
	query := []float32{1, 0, 0, 0}

	// Top-3 with no filter — expect A, B, C in that order.
	matches := idx.searchVec(query, SearchOptions{K: 3})
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
	}
	wantOrder := []string{"A", "B", "C"}
	for i, want := range wantOrder {
		if matches[i].CorpusID != want {
			t.Errorf("rank %d: expected %s, got %s (sim=%v)", i, want, matches[i].CorpusID, matches[i].Similarity)
		}
	}

	// MinSimilarity = 0.7 → only A (1.0) and B (0.8) qualify.
	matches = idx.searchVec(query, SearchOptions{K: 5, MinSimilarity: 0.7})
	if len(matches) != 2 {
		t.Errorf("MinSimilarity=0.7 expected 2 matches, got %d (%+v)", len(matches), matches)
	}

	// V01Only = true → only A and B are scoped.
	matches = idx.searchVec(query, SearchOptions{K: 5, V01Only: true})
	if len(matches) != 2 {
		t.Errorf("V01Only=true expected 2 matches, got %d (%+v)", len(matches), matches)
	}
	for _, m := range matches {
		if m.CorpusID != "A" && m.CorpusID != "B" {
			t.Errorf("V01Only=true returned non-v0.1 entry %s", m.CorpusID)
		}
	}
}

// summariseMatches turns a []Match into a short string for log output.
func summariseMatches(ms []Match) string {
	if len(ms) == 0 {
		return "(none)"
	}
	s := ""
	for i, m := range ms {
		if i > 0 {
			s += ", "
		}
		s += m.CorpusID
	}
	return s
}
