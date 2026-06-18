package embed

import (
	"context"
	"fmt"
	"sort"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
)

// indexEntry is one corpus entry held in the Index, with its embedding
// computed at startup.
type indexEntry struct {
	ID        string
	Slug      string
	Category  string
	Severity  string
	Vector    []float32
	V01Scoped bool // pre-cached so Search can filter cheaply
}

// Index holds an L2-normalized vector per corpus entry and supports
// cheap top-k cosine search. At v0.1 corpus size (~15-50 entries) we
// do flat linear search — no HNSW, no Annoy. Sub-millisecond for any
// realistic corpus.
type Index struct {
	embedder Embedder
	entries  []indexEntry
}

// BuildIndex embeds the given corpus entries' payload texts and
// returns a ready-to-query Index. This is the only network call at
// startup (one batch of N entries).
//
// We embed entry.Payload.Text with EmbedDocuments-style semantics
// (input_type=document) so retrieval is asymmetric — Units later use
// input_type=query for the small recall boost.
func BuildIndex(ctx context.Context, e Embedder, entries []corpus.Entry) (*Index, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("embed: cannot build Index from empty entries")
	}

	texts := make([]string, len(entries))
	for i, en := range entries {
		texts[i] = en.Payload.Text
	}

	// Use document semantics when available (Voyage-specific extension).
	var vecs [][]float32
	var err error
	if v, ok := e.(*Voyage); ok {
		vecs, err = v.EmbedDocuments(ctx, texts)
	} else {
		vecs, err = e.Embed(ctx, texts)
	}
	if err != nil {
		return nil, fmt.Errorf("embed: build index: %w", err)
	}

	idx := &Index{embedder: e, entries: make([]indexEntry, len(entries))}
	for i, en := range entries {
		idx.entries[i] = indexEntry{
			ID:        en.ID,
			Slug:      en.Slug,
			Category:  en.PrimaryCategory,
			Severity:  en.Severity,
			Vector:    vecs[i],
			V01Scoped: en.InScopeForV01(),
		}
	}
	return idx, nil
}

// SearchOptions controls top-k search behaviour.
type SearchOptions struct {
	K             int     // top-K to return; default 3
	MinSimilarity float32 // floor; matches below this are dropped; default 0.0
	V01Only       bool    // restrict matches to v0.1-scoped corpus entries
}

// Search embeds the query text and returns the K nearest corpus entries
// (sorted by similarity desc). At v0.1 we use input_type=query when the
// embedder is Voyage.
func (idx *Index) Search(ctx context.Context, query string, opts SearchOptions) ([]Match, error) {
	if opts.K <= 0 {
		opts.K = 3
	}

	var qvec []float32
	if v, ok := idx.embedder.(*Voyage); ok {
		vecs, err := v.EmbedQueries(ctx, []string{query})
		if err != nil {
			return nil, err
		}
		qvec = vecs[0]
	} else {
		vecs, err := idx.embedder.Embed(ctx, []string{query})
		if err != nil {
			return nil, err
		}
		qvec = vecs[0]
	}

	return idx.searchVec(qvec, opts), nil
}

// SearchBatch is the same as Search but runs N queries in a single
// embedding batch — important when scanning many Units at once.
// Returns matches[i] for queries[i].
func (idx *Index) SearchBatch(ctx context.Context, queries []string, opts SearchOptions) ([][]Match, error) {
	if opts.K <= 0 {
		opts.K = 3
	}
	if len(queries) == 0 {
		return nil, ErrEmptyInput
	}

	var qvecs [][]float32
	var err error
	if v, ok := idx.embedder.(*Voyage); ok {
		qvecs, err = v.EmbedQueries(ctx, queries)
	} else {
		qvecs, err = idx.embedder.Embed(ctx, queries)
	}
	if err != nil {
		return nil, err
	}

	out := make([][]Match, len(qvecs))
	for i, q := range qvecs {
		out[i] = idx.searchVec(q, opts)
	}
	return out, nil
}

// searchVec is the inner loop: cosine similarity over the entry table,
// keep top-K above the floor. Pure math, no I/O.
func (idx *Index) searchVec(qvec []float32, opts SearchOptions) []Match {
	// One pass: collect every (entry, similarity) above the floor.
	type scored struct {
		i   int
		sim float32
	}
	scratch := make([]scored, 0, len(idx.entries))
	for i, e := range idx.entries {
		if opts.V01Only && !e.V01Scoped {
			continue
		}
		s := CosineSimilarity(qvec, e.Vector)
		if s >= opts.MinSimilarity {
			scratch = append(scratch, scored{i, s})
		}
	}
	// Sort by similarity desc; ties broken by stable corpus order.
	sort.SliceStable(scratch, func(a, b int) bool {
		return scratch[a].sim > scratch[b].sim
	})

	k := opts.K
	if k > len(scratch) {
		k = len(scratch)
	}
	out := make([]Match, k)
	for j := 0; j < k; j++ {
		e := idx.entries[scratch[j].i]
		out[j] = Match{
			CorpusID:   e.ID,
			Slug:       e.Slug,
			Category:   e.Category,
			Severity:   e.Severity,
			Similarity: scratch[j].sim,
		}
	}
	return out
}

// Size returns the number of corpus entries in the Index. Mostly for
// logging / telemetry.
func (idx *Index) Size() int { return len(idx.entries) }

// EmbedderName returns the underlying Embedder's identifier — copied
// into Finding records so reports record which model produced them.
func (idx *Index) EmbedderName() string { return idx.embedder.Name() }
