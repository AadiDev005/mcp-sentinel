package corpus

import (
	"path/filepath"
	"runtime"
	"testing"
)

// repoCorpusPath returns the absolute path to <repo>/corpus/attacks/
// from this test file's location. Avoids hardcoding absolute paths.
func repoCorpusPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	// .../internal/corpus/corpus_test.go -> .../corpus/attacks
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "corpus", "attacks")
}

func TestLoadDir_AllFifteenEntriesParse(t *testing.T) {
	entries, err := LoadDir(repoCorpusPath(t))
	if err != nil {
		t.Fatalf("LoadDir error: %v", err)
	}
	if len(entries) != 15 {
		t.Fatalf("expected 15 entries, got %d", len(entries))
	}
}

func TestLoadDir_EveryEntryHasRequiredFields(t *testing.T) {
	entries, err := LoadDir(repoCorpusPath(t))
	if err != nil {
		t.Fatalf("LoadDir error: %v", err)
	}

	for _, e := range entries {
		if e.ID == "" {
			t.Errorf("entry has empty ID: %+v", e)
		}
		if e.PrimaryCategory == "" {
			t.Errorf("%s: empty primary_category", e.ID)
		}
		if e.Severity == "" {
			t.Errorf("%s: empty severity", e.ID)
		}
		if e.Payload.Text == "" {
			t.Errorf("%s: empty payload.text", e.ID)
		}
		if e.Source.URL == "" {
			t.Errorf("%s: empty source.url (provenance is non-negotiable)", e.ID)
		}
		if e.Source.License == "" {
			t.Errorf("%s: empty source.license", e.ID)
		}
		if e.JudgeHints.PrimaryQuestion == "" {
			t.Errorf("%s: empty judge_hints.primary_question", e.ID)
		}
	}
}

func TestLoadDir_V01ScopeContainsExpectedIDs(t *testing.T) {
	entries, _ := LoadDir(repoCorpusPath(t))

	wantInV01 := map[string]bool{
		"T1-001": false, "T1-004": false, "T1-007": false,
		"T2-002": false, "T2-005": false, "T2-008": false, "T2-014": false,
		"T3-009": false, "T4-011": false, "T5-006": false,
		"T6-012": false, "T7-015": false,
	}
	for _, e := range entries {
		if e.InScopeForV01() {
			if _, expected := wantInV01[e.ID]; expected {
				wantInV01[e.ID] = true
			}
		}
	}
	for id, seen := range wantInV01 {
		if !seen {
			t.Errorf("expected %s in v0.1 scope, not seen", id)
		}
	}
}
