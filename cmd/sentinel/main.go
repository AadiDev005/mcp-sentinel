// Package main is the mcp-sentinel CLI entry point.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
	"github.com/AadiDev005/mcp-sentinel/internal/embed"
	"github.com/AadiDev005/mcp-sentinel/internal/scanner"
)

const version = "0.0.3-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("mcp-sentinel", version)
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mcp-sentinel — semantic scanner for MCP tool poisoning

Usage:
  mcp-sentinel <subcommand> [flags]

Subcommands:
  scan <file>   Scan an MCP tool-definitions JSON file
  version       Print version and exit
  help          Show this message

Run 'mcp-sentinel scan --help' for scan-specific flags.`)
}

// runScan implements the `scan` subcommand. Returns the process exit
// code: 0 = no findings, 1 = findings emitted, 2 = invocation error.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	corpusDir := fs.String("corpus", defaultCorpusDir(), "path to corpus/attacks/ directory")
	useEmbed := fs.Bool("embed", false, "enable Stage 2: embed prefilter-surviving Units and retrieve top-k corpus matches via Voyage AI (requires VOYAGE_API_KEY)")
	topK := fs.Int("top-k", 3, "number of nearest corpus entries to return per Unit (requires --embed)")
	minSim := fs.Float64("similarity", 0.55, "minimum cosine similarity to report a match (requires --embed)")
	v01Only := fs.Bool("v01-only", false, "restrict embed-stage matches to v0.1-scoped corpus entries")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: mcp-sentinel scan [flags] <input.json>

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "scan: missing input file")
		fs.Usage()
		return 2
	}
	inputPath := fs.Arg(0)

	// Stage 1 setup: load the corpus and build the prefilter.
	entries, err := corpus.LoadDir(*corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: load corpus from %s: %v\n", *corpusDir, err)
		return 2
	}
	pf := scanner.NewPrefilter(entries)

	// Stage 0: open and ingest the input.
	f, err := os.Open(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: open %s: %v\n", inputPath, err)
		return 2
	}
	defer f.Close()

	units, err := scanner.Ingest(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		return 2
	}

	hits := pf.MatchAll(units)
	if len(hits) == 0 {
		fmt.Printf("scan OK: %d units, 0 prefilter hits\n", len(units))
		return 0
	}

	// Stage 2 (optional): embed each hit Unit and run retrieval.
	var unitMatches map[int][]embed.Match
	if *useEmbed {
		var err error
		unitMatches, err = runEmbedStage(entries, units, hits, *topK, float32(*minSim), *v01Only)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: embed stage: %v\n", err)
			return 2
		}
	}

	// Report.
	fmt.Printf("scan: %d units, %d with prefilter hits", len(units), len(hits))
	if *useEmbed {
		fmt.Printf(", embed stage enabled (model=%s)", "voyage:voyage-3.5-lite")
	}
	fmt.Println()
	fmt.Println()
	for i, u := range units {
		unitHits, ok := hits[i]
		if !ok {
			continue
		}
		fmt.Printf("[HIT] tool=%s surface=%s path=%s\n", u.ToolName, u.Surface, u.Path)
		for _, h := range unitHits {
			fmt.Printf("      [prefilter] %-16s match=%q corpus=%v\n", h.SignalKind, h.Match, h.CorpusIDs)
		}
		if matches, ok := unitMatches[i]; ok && len(matches) > 0 {
			for _, m := range matches {
				fmt.Printf("      [embed]     %-16s sim=%.3f category=%s severity=%s\n",
					m.CorpusID, m.Similarity, m.Category, m.Severity)
			}
		}
		fmt.Println()
	}
	return 1
}

// runEmbedStage runs Stage 2 against the Units that survived Stage 1.
// Returns a map[unit_index][]Match — only Units with at least one match
// above the similarity threshold appear in the map.
func runEmbedStage(
	entries []corpus.Entry,
	units []scanner.Unit,
	hits map[int][]scanner.PrefilterHit,
	topK int,
	minSim float32,
	v01Only bool,
) (map[int][]embed.Match, error) {
	apiKey := os.Getenv("VOYAGE_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("VOYAGE_API_KEY not set (required when --embed is enabled)")
	}

	v, err := embed.NewVoyage(embed.VoyageConfig{APIKey: apiKey})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	idx, err := embed.BuildIndex(ctx, v, entries)
	if err != nil {
		return nil, fmt.Errorf("build index: %w", err)
	}

	// Collect texts to embed in batch. We embed in the same order as
	// the unit-index slice so we can map results back.
	var (
		indices []int
		queries []string
	)
	for i, u := range units {
		if _, ok := hits[i]; !ok {
			continue
		}
		indices = append(indices, i)
		queries = append(queries, embedInputFor(u))
	}
	if len(queries) == 0 {
		return map[int][]embed.Match{}, nil
	}

	all, err := idx.SearchBatch(ctx, queries, embed.SearchOptions{
		K:             topK,
		MinSimilarity: minSim,
		V01Only:       v01Only,
	})
	if err != nil {
		return nil, fmt.Errorf("search batch: %w", err)
	}

	out := make(map[int][]embed.Match)
	for batchIdx, unitIdx := range indices {
		if len(all[batchIdx]) > 0 {
			out[unitIdx] = all[batchIdx]
		}
	}
	return out, nil
}

// embedInputFor produces the canonical string we feed the embedder for
// a Unit. Surface tag is included so the embedder treats the same text
// differently based on where it appeared (ARCHITECTURE.md §4.1).
func embedInputFor(u scanner.Unit) string {
	prefix := fmt.Sprintf("[%s] ", u.Surface)
	tail := ""
	if len(u.Context.ReferencedTools) > 0 {
		tail += fmt.Sprintf("\nReferenced tools: %v", u.Context.ReferencedTools)
	}
	if len(u.Context.SuspiciousParameters) > 0 {
		tail += fmt.Sprintf("\nSuspicious params: %v", u.Context.SuspiciousParameters)
	}
	return prefix + u.Text + tail
}

// defaultCorpusDir locates the corpus directory relative to the binary's
// expected workspace. At v0.1 we assume the user runs the scanner from
// the repo root; the default points at ./corpus/attacks. Overrideable
// via --corpus.
func defaultCorpusDir() string {
	cwd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(cwd, "corpus", "attacks")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	return "./corpus/attacks"
}
