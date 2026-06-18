// Package embed is the embedding-similarity retrieval stage.
//
// Status: stub. Backend choice (local model vs API) is deferred to ARCHITECTURE.md.
package embed

// Embedder converts text into a vector for similarity search.
type Embedder interface {
	Embed(text string) ([]float32, error)
}

// Match is a corpus entry that scored above the similarity threshold
// for a given tool description.
type Match struct {
	CorpusID   string
	Similarity float32
}
