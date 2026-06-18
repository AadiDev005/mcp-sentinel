// Package main is the mcp-sentinel CLI entry point.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AadiDev005/mcp-sentinel/internal/corpus"
	"github.com/AadiDev005/mcp-sentinel/internal/scanner"
)

const version = "0.0.2-dev"

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

	// Load the corpus (Stage 1's signal table source).
	entries, err := corpus.LoadDir(*corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: load corpus from %s: %v\n", *corpusDir, err)
		return 2
	}
	pf := scanner.NewPrefilter(entries)

	// Open + ingest the input.
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
		fmt.Printf("scan OK: %d units, 0 prefilter hits (v0.1 stops here — Stage 2 not implemented yet)\n", len(units))
		return 0
	}

	fmt.Printf("scan: %d units, %d with prefilter hits\n\n", len(units), len(hits))
	for i, u := range units {
		unitHits, ok := hits[i]
		if !ok {
			continue
		}
		fmt.Printf("[HIT] tool=%s surface=%s path=%s\n", u.ToolName, u.Surface, u.Path)
		for _, h := range unitHits {
			fmt.Printf("      %s match=%q corpus=%v\n", h.SignalKind, h.Match, h.CorpusIDs)
		}
		fmt.Println()
	}
	return 1
}

// defaultCorpusDir locates the corpus directory relative to the binary's
// expected workspace. At v0.1 we assume the user runs the scanner from
// the repo root; the default points at ./corpus/attacks. Overrideable
// via --corpus.
func defaultCorpusDir() string {
	// Prefer cwd-relative if it exists. Fall back to ./corpus/attacks
	// even if missing so the error message is clear.
	cwd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(cwd, "corpus", "attacks")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
	}
	return "./corpus/attacks"
}
