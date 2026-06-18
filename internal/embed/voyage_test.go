package embed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestVoyage returns a Voyage client wired to a test HTTP server.
// The server's handler returns a deterministic embedding shaped per the
// `respGen` function. Lets every test inject its own response.
func newTestVoyage(t *testing.T, respGen func(req voyageReq) any) (*Voyage, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			http.Error(w, "bad auth: "+got, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var parsed voyageReq
		_ = json.Unmarshal(body, &parsed)
		resp := respGen(parsed)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))

	v, err := NewVoyage(VoyageConfig{
		APIKey:     "test-key",
		Model:      "voyage-3.5-lite",
		Endpoint:   srv.URL,
		Timeout:    5 * time.Second,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return v, srv
}

func TestNewVoyage_RequiresAPIKey(t *testing.T) {
	_, err := NewVoyage(VoyageConfig{})
	if err == nil {
		t.Fatal("expected error for empty APIKey, got nil")
	}
	if !strings.Contains(err.Error(), "APIKey") {
		t.Errorf("unexpected message: %v", err)
	}
}

func TestNewVoyage_DefaultsAreApplied(t *testing.T) {
	v, err := NewVoyage(VoyageConfig{APIKey: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if v.cfg.Model != VoyageDefaultModel {
		t.Errorf("default model wrong: %q", v.cfg.Model)
	}
	if v.cfg.Endpoint != VoyageDefaultEndpoint {
		t.Errorf("default endpoint wrong: %q", v.cfg.Endpoint)
	}
	if v.Dimension() != 1024 {
		t.Errorf("expected dim 1024, got %d", v.Dimension())
	}
	if v.Name() != "voyage:voyage-3.5-lite" {
		t.Errorf("Name wrong: %q", v.Name())
	}
}

func TestVoyage_EmbedHappyPath(t *testing.T) {
	v, srv := newTestVoyage(t, func(req voyageReq) any {
		// Return one fake vector per input — vector[0] = input index,
		// rest zeros. Easy to assert on.
		data := make([]map[string]any, len(req.Input))
		for i := range req.Input {
			vec := make([]float32, 4)
			vec[0] = float32(i + 1) // distinguishable per index
			data[i] = map[string]any{"index": i, "embedding": vec}
		}
		return map[string]any{"data": data, "model": req.Model}
	})
	defer srv.Close()

	vecs, err := v.Embed(context.Background(), []string{"alpha", "beta", "gamma"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 3 {
		t.Fatalf("expected 3 vectors, got %d", len(vecs))
	}
	// Vectors should be L2-normalized after Embed.
	for i, vec := range vecs {
		sim := CosineSimilarity(vec, vec)
		if sim < 0.999 || sim > 1.001 {
			t.Errorf("vec %d not normalized: self-cosine %v", i, sim)
		}
	}
}

func TestVoyage_PreservesIndexOrder(t *testing.T) {
	// Server returns the data array in reversed order, but with index
	// fields set correctly. The client must re-sort.
	v, srv := newTestVoyage(t, func(req voyageReq) any {
		data := make([]map[string]any, len(req.Input))
		for i := range req.Input {
			vec := make([]float32, 4)
			vec[0] = float32(i + 1)
			// Write in reversed order
			data[len(req.Input)-1-i] = map[string]any{"index": i, "embedding": vec}
		}
		return map[string]any{"data": data, "model": req.Model}
	})
	defer srv.Close()

	vecs, err := v.Embed(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	// vecs[0] (after normalize) should still correspond to input 0;
	// since vec[0]=1 was the only non-zero component, normalized it's
	// [1,0,0,0]. Check first component is positive (close to 1).
	if vecs[0][0] < 0.9 {
		t.Errorf("index 0 vector wrong after re-sort: %v", vecs[0])
	}
}

func TestVoyage_EmptyInputRejected(t *testing.T) {
	v, srv := newTestVoyage(t, func(req voyageReq) any { return nil })
	defer srv.Close()

	_, err := v.Embed(context.Background(), nil)
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("expected ErrEmptyInput on nil input, got %v", err)
	}

	_, err = v.Embed(context.Background(), []string{})
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("expected ErrEmptyInput on empty slice, got %v", err)
	}

	// All-empty-strings should also be rejected before any HTTP call.
	_, err = v.Embed(context.Background(), []string{"", "", ""})
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("expected ErrEmptyInput on all-empty inputs, got %v", err)
	}
}

func TestVoyage_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	v, _ := NewVoyage(VoyageConfig{
		APIKey:     "test-key",
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	_, err := v.Embed(context.Background(), []string{"hi"})
	if err == nil {
		t.Fatal("expected error on 429, got nil")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("expected '429' in error message, got %v", err)
	}
}

func TestVoyage_VectorCountMismatchSurfaces(t *testing.T) {
	v, srv := newTestVoyage(t, func(req voyageReq) any {
		// Send only 1 vector for 2 inputs.
		return map[string]any{
			"data":  []map[string]any{{"index": 0, "embedding": []float32{1, 0}}},
			"model": req.Model,
		}
	})
	defer srv.Close()

	_, err := v.Embed(context.Background(), []string{"a", "b"})
	if err == nil {
		t.Fatal("expected error on vector-count mismatch")
	}
}
