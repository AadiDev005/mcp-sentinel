// Package embed is the Stage 2 retrieval pipeline: convert text into
// fixed-length vectors and find the corpus entries closest to a query
// Unit by cosine similarity.
//
// Backend choice: v0.1 uses a remote embedding API (Voyage AI by
// default). A local ONNX backend is on the v0.2 roadmap — see
// ARCHITECTURE.md §4.2 for the trade-off. The Embedder interface is
// designed so swapping backends is one constructor change.
package embed

import (
	"context"
	"errors"
	"math"
)

// Embedder is the contract every backend satisfies. Given a batch of
// texts, return one vector per text. Vectors MUST be L2-normalized
// (length 1) so cosine similarity = dot product.
//
// Why batch? One API call for N texts is cheaper and faster than N
// calls. At scanner startup we embed every corpus entry — a 15-entry
// batch is one HTTP round-trip.
//
// Why context? Embeddings can hang on slow networks. context.Context
// lets the caller set a deadline or cancel mid-flight (e.g. on Ctrl-C).
type Embedder interface {
	// Embed returns one vector per input text, in the same order.
	// All vectors share the same Dimension().
	Embed(ctx context.Context, texts []string) ([][]float32, error)

	// Dimension is the length of every vector this Embedder produces.
	// Voyage voyage-3-lite: 512. voyage-3: 1024. OpenAI ada-002: 1536.
	// Local bge-small-en-v1.5: 384.
	Dimension() int

	// Name is a short identifier of the model + provider, e.g.
	// "voyage:voyage-3-lite". Logged into reports so a finding can be
	// reproduced by re-running with the same model.
	Name() string
}

// Match is one corpus entry surfaced by the retrieval stage as similar
// to a query Unit. Similarity is in [-1, 1] (cosine), but for L2-normed
// real-text embeddings it is almost always in [0, 1].
type Match struct {
	CorpusID   string  // e.g. "T1-001"
	Slug       string  // e.g. "direct-poisoning-ssh-key-exfil"
	Category   string  // e.g. "T1"
	Severity   string  // e.g. "critical"
	Similarity float32 // higher = more similar
}

// ErrEmptyInput is returned when a caller asks an Embedder to embed an
// empty slice or a slice containing only empty strings. Cheaper to
// catch here than to round-trip to the API.
var ErrEmptyInput = errors.New("embed: input texts must be non-empty")

// CosineSimilarity computes the cosine similarity between two equal-
// length vectors. For L2-normalized vectors (every Embedder MUST
// normalize), this is just the dot product — we keep the general form
// for safety, but the hot path is the dot product itself.
//
// Math:
//
//	cos(a, b) = (a · b) / (|a| · |b|)
//	          = a · b      if |a| = |b| = 1
//
// where a · b = sum over i of a[i] * b[i].
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		fa, fb := float64(a[i]), float64(b[i])
		dot += fa * fb
		na += fa * fa
		nb += fb * fb
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(na) * math.Sqrt(nb)))
}

// L2Normalize scales v in place so its Euclidean length equals 1.
// If v is the zero vector, leaves it unchanged.
func L2Normalize(v []float32) {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	if sum == 0 {
		return
	}
	inv := float32(1.0 / math.Sqrt(sum))
	for i := range v {
		v[i] *= inv
	}
}
