package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VoyageDefaultEndpoint is Voyage AI's production embeddings URL.
// Overrideable via VoyageConfig.Endpoint so tests can point at an
// httptest.Server.
const VoyageDefaultEndpoint = "https://api.voyageai.com/v1/embeddings"

// VoyageDefaultModel is the v0.1 default. Lite is cheaper and fast
// enough for the corpus size we work with. We can bump to voyage-3.5 or
// voyage-4 later via VoyageConfig.Model.
const VoyageDefaultModel = "voyage-3.5-lite"

// VoyageMaxBatchSize is the per-request input cap Voyage documents.
// We stay well under it in v0.1 (corpus is 15 entries).
const VoyageMaxBatchSize = 1000

// VoyageConfig is the constructor input for NewVoyage. Everything has
// a sensible default except APIKey, which the caller must supply.
type VoyageConfig struct {
	APIKey    string        // required; from env var VOYAGE_API_KEY at the call site
	Model     string        // default VoyageDefaultModel
	Endpoint  string        // default VoyageDefaultEndpoint
	Timeout   time.Duration // per-request timeout; default 30s
	HTTPClient *http.Client // optional injection point for tests
	// InputType is Voyage's contextual hint. We use "document" when
	// embedding corpus entries and "query" when embedding Units. The
	// type is set per-call, not per-config.
}

// Voyage is the Voyage AI implementation of Embedder.
type Voyage struct {
	cfg    VoyageConfig
	client *http.Client
}

// NewVoyage constructs a Voyage embedder. Returns an error if the
// config is missing required fields. Does NOT make a network call —
// safe to call at startup.
func NewVoyage(cfg VoyageConfig) (*Voyage, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("embed/voyage: APIKey is required (set VOYAGE_API_KEY)")
	}
	if cfg.Model == "" {
		cfg.Model = VoyageDefaultModel
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = VoyageDefaultEndpoint
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Voyage{cfg: cfg, client: client}, nil
}

// Name implements Embedder. Format: "provider:model".
func (v *Voyage) Name() string {
	return "voyage:" + v.cfg.Model
}

// Dimension implements Embedder. Hardcoded by model name.
// If we add more models, this table grows; for now voyage-3.5-lite =
// 1024 is the only entry we need.
func (v *Voyage) Dimension() int {
	switch v.cfg.Model {
	case "voyage-3.5-lite", "voyage-3.5",
		"voyage-3", "voyage-3-lite",
		"voyage-4", "voyage-4-lite", "voyage-4-large":
		return 1024
	default:
		// Unknown model: caller must verify against a real Embed() call.
		// Return -1 so misuse surfaces obviously.
		return -1
	}
}

// voyageReq mirrors the Voyage POST /v1/embeddings request body.
// Field tags map our Go names to Voyage's JSON names.
type voyageReq struct {
	Input     []string `json:"input"`
	Model     string   `json:"model"`
	InputType string   `json:"input_type,omitempty"` // "document" | "query"
}

// voyageResp mirrors the response shape. We only consume `data`; the
// rest is logged-then-discarded.
type voyageResp struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Model string `json:"model"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

// EmbedDocuments is for embedding the corpus at startup. Sets
// input_type=document, which Voyage uses to bias toward "this text is
// going to be indexed."
func (v *Voyage) EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error) {
	return v.embed(ctx, texts, "document")
}

// EmbedQueries is for embedding Units at scan time. Sets
// input_type=query — biased toward "this text will be matched against
// indexed documents." Asymmetric embedding is a small but real
// recall boost on retrieval workloads.
func (v *Voyage) EmbedQueries(ctx context.Context, texts []string) ([][]float32, error) {
	return v.embed(ctx, texts, "query")
}

// Embed implements the generic Embedder interface. Defaults to query
// semantics; callers wanting document semantics should call
// EmbedDocuments explicitly.
func (v *Voyage) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	return v.embed(ctx, texts, "query")
}

// embed is the shared implementation. Builds the request, sends it,
// parses the response, and L2-normalizes every vector defensively.
func (v *Voyage) embed(ctx context.Context, texts []string, inputType string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, ErrEmptyInput
	}
	// Voyage rejects empty strings inside the input array — replace
	// them with a single space to keep the index alignment but avoid
	// an API error.
	cleaned := make([]string, len(texts))
	allEmpty := true
	for i, t := range texts {
		if t == "" {
			cleaned[i] = " "
		} else {
			cleaned[i] = t
			allEmpty = false
		}
	}
	if allEmpty {
		return nil, ErrEmptyInput
	}
	if len(cleaned) > VoyageMaxBatchSize {
		return nil, fmt.Errorf("embed/voyage: batch size %d exceeds limit %d", len(cleaned), VoyageMaxBatchSize)
	}

	body, err := json.Marshal(voyageReq{
		Input:     cleaned,
		Model:     v.cfg.Model,
		InputType: inputType,
	})
	if err != nil {
		return nil, fmt.Errorf("embed/voyage: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embed/voyage: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+v.cfg.APIKey)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embed/voyage: HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read up to 8 KB of error body for the message; ignore further.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return nil, fmt.Errorf("embed/voyage: HTTP %d: %s", resp.StatusCode, string(errBody))
	}

	var parsed voyageResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("embed/voyage: decode response: %w", err)
	}

	if len(parsed.Data) != len(cleaned) {
		return nil, fmt.Errorf("embed/voyage: got %d vectors for %d inputs", len(parsed.Data), len(cleaned))
	}

	// The response can come back in any order; re-sort by index.
	vecs := make([][]float32, len(cleaned))
	for _, item := range parsed.Data {
		if item.Index < 0 || item.Index >= len(vecs) {
			return nil, fmt.Errorf("embed/voyage: response index %d out of range", item.Index)
		}
		L2Normalize(item.Embedding) // defensive — Voyage already normalizes
		vecs[item.Index] = item.Embedding
	}
	for i, v := range vecs {
		if v == nil {
			return nil, fmt.Errorf("embed/voyage: response missing vector at index %d", i)
		}
	}
	return vecs, nil
}
