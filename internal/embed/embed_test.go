package embed

import (
	"math"
	"testing"
)

// Tolerance for float32 equality in similarity tests. Embedding math
// runs in float64 internally then casts; 1e-6 is plenty.
const epsilon = 1e-6

func TestCosineSimilarity_IdenticalVectorsReturnOne(t *testing.T) {
	a := []float32{1, 2, 3, 4}
	got := CosineSimilarity(a, a)
	if math.Abs(float64(got-1.0)) > epsilon {
		t.Errorf("expected 1.0 for identical vectors, got %v", got)
	}
}

func TestCosineSimilarity_OrthogonalVectorsReturnZero(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{0, 1, 0}
	got := CosineSimilarity(a, b)
	if math.Abs(float64(got)) > epsilon {
		t.Errorf("expected 0.0 for orthogonal vectors, got %v", got)
	}
}

func TestCosineSimilarity_OppositeVectorsReturnMinusOne(t *testing.T) {
	a := []float32{1, 2, 3}
	b := []float32{-1, -2, -3}
	got := CosineSimilarity(a, b)
	if math.Abs(float64(got+1.0)) > epsilon {
		t.Errorf("expected -1.0 for opposite vectors, got %v", got)
	}
}

func TestCosineSimilarity_MismatchedLengthsReturnZero(t *testing.T) {
	got := CosineSimilarity([]float32{1, 2}, []float32{1, 2, 3})
	if got != 0 {
		t.Errorf("expected 0 for mismatched lengths, got %v", got)
	}
}

func TestCosineSimilarity_ZeroVectorReturnsZero(t *testing.T) {
	got := CosineSimilarity([]float32{0, 0, 0}, []float32{1, 2, 3})
	if got != 0 {
		t.Errorf("expected 0 for zero vector, got %v", got)
	}
}

func TestL2Normalize_UnitVectorUnchanged(t *testing.T) {
	v := []float32{1, 0, 0}
	L2Normalize(v)
	if math.Abs(float64(v[0]-1)) > epsilon || v[1] != 0 || v[2] != 0 {
		t.Errorf("unit vector got modified: %v", v)
	}
}

func TestL2Normalize_ProducesUnitLength(t *testing.T) {
	v := []float32{3, 4, 0} // length 5
	L2Normalize(v)
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	length := math.Sqrt(sum)
	if math.Abs(length-1.0) > epsilon {
		t.Errorf("expected unit length after normalize, got %v (vec=%v)", length, v)
	}
	// Specifically: 3/5=0.6, 4/5=0.8
	if math.Abs(float64(v[0]-0.6)) > epsilon || math.Abs(float64(v[1]-0.8)) > epsilon {
		t.Errorf("normalization produced wrong direction: %v", v)
	}
}

func TestL2Normalize_ZeroVectorSurvives(t *testing.T) {
	v := []float32{0, 0, 0}
	L2Normalize(v) // must not crash
	for _, x := range v {
		if x != 0 {
			t.Errorf("zero vector should stay zero, got %v", v)
		}
	}
}
