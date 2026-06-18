// Package corpus loads the YAML attack corpus from disk and exposes it
// as typed Entries. At v0.1 the corpus lives at <repo>/corpus/attacks/
// and the scanner loads it from there at startup. Future versions may
// bake it into the binary via go:embed; we keep it on disk for now so
// users browsing GitHub can read the YAML files directly without
// digging into the Go package.
package corpus

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one parsed corpus YAML file.
// Field names map 1:1 to CORPUS.md §3 schema.
type Entry struct {
	ID                string   `yaml:"id"`
	Slug              string   `yaml:"slug"`
	Title             string   `yaml:"title"`
	Version           int      `yaml:"version"`
	Created           string   `yaml:"created"`
	Updated           string   `yaml:"updated"`
	PrimaryCategory   string   `yaml:"primary_category"`
	SecondaryCategory *string  `yaml:"secondary_category"`
	Severity          string   `yaml:"severity"`
	Confidence        float64  `yaml:"confidence"`
	Payload           Payload  `yaml:"payload"`
	Source            Source   `yaml:"source"`
	Signals           Signals  `yaml:"signals"`
	JudgeHints        Judge    `yaml:"judge_hints"`
	TestSet           TestSet  `yaml:"test_set"`
	InScopeFor        []string `yaml:"in_scope_for"`
	Notes             string   `yaml:"notes"`
}

// Payload is the malicious-text body of an entry.
type Payload struct {
	Surface string         `yaml:"surface"`
	Text    string         `yaml:"text"`
	Context PayloadContext `yaml:"context"`
}

type PayloadContext struct {
	SuspiciousParameters []string `yaml:"suspicious_parameters"`
	ReferencedTools      []string `yaml:"referenced_tools"`
	ReferencedServers    []string `yaml:"referenced_servers"`
	SchemaInjectionField string   `yaml:"schema_injection_field"`
}

// Source is provenance + license info — non-negotiable per CORPUS.md.
type Source struct {
	Type        string   `yaml:"type"`
	Repo        string   `yaml:"repo"`
	Path        string   `yaml:"path"`
	URL         string   `yaml:"url"`
	License     string   `yaml:"license"`
	Commit      *string  `yaml:"commit"`
	CitedWorks  []string `yaml:"cited_works"`
}

// Signals feed the Stage 1 prefilter.
type Signals struct {
	LiteralSubstrings           []string `yaml:"literal_substrings"`
	ConcealmentPhrases          []string `yaml:"concealment_phrases"`
	PseudoXMLTags               []string `yaml:"pseudo_xml_tags"`
	AttackVerbs                 []string `yaml:"attack_verbs"`
	SuspiciousParamNames        []string `yaml:"suspicious_param_names"`
	ParamNameKeywords           []string `yaml:"param_name_keywords"`
	UnpinnedVersionSpecifiers   []string `yaml:"unpinned_version_specifiers"`
}

// Judge feeds the Stage 3 LLM judge prompt.
type Judge struct {
	PrimaryQuestion  string   `yaml:"primary_question"`
	ExpectedEvidence []string `yaml:"expected_evidence"`
}

type TestSet struct {
	IsHoldout  bool     `yaml:"is_holdout"`
	PairedWith []string `yaml:"paired_with"`
}

// LoadDir reads every YAML file in `dir` (typically <repo>/corpus/attacks/)
// and returns a slice of Entry. Errors out on the first malformed file —
// at startup we want hard failure, not silent partial corpus.
func LoadDir(dir string) ([]Entry, error) {
	return loadFromFS(os.DirFS(dir), ".")
}

// loadFromFS is the testable inner function — reads YAML from any
// fs.FS, not just disk. Lets tests use an in-memory fs without touching
// real files.
func loadFromFS(fsys fs.FS, dir string) ([]Entry, error) {
	var entries []Entry

	walkErr := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var e Entry
		if err := yaml.Unmarshal(data, &e); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if e.ID == "" {
			// Skip non-entry YAML files (none today, but defensive).
			return nil
		}
		entries = append(entries, e)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return entries, nil
}

// InScopeForV01 returns true if the entry is scoped for the v0.1 scanner.
func (e Entry) InScopeForV01() bool {
	for _, s := range e.InScopeFor {
		if s == "v0.1" {
			return true
		}
	}
	return false
}

// Load is the public entry point with a default name kept for the older
// stub signature. Given a path, it forwards to LoadDir.
func Load(path string) ([]Entry, error) {
	return LoadDir(path)
}
