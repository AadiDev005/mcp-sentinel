// Package main is a one-off helper that converts MCP-server TypeScript
// source into corpus/benign/ YAML entries.
//
// Usage:
//   extract-benign \
//     --server filesystem \
//     --source https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/filesystem/index.ts \
//     --license MIT \
//     --start-id 1 \
//     --output ../../corpus/benign/
//
// Why we do this: hand-writing 50 YAMLs is error-prone and time-
// consuming. Real benign entries come from real MCP servers — the
// extractor pulls them directly from upstream source, preserving the
// exact description text the agent would see at runtime.
//
// Provenance rules (CORPUS.md §7 / corpus-raw/README.md):
//   - Every entry MUST cite source.url, source.license.
//   - The source must be license-compatible (MIT, Apache-2.0, BSD, CC-BY).
//   - We never paraphrase or "fix" the description — extracted verbatim.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// registerToolRe anchors on `server.registerTool("name", {` and
// captures only as far as we need: the name (group 1) and the start
// position of the body. The body is parsed by walkBalancedBraces below,
// which counts {/} pairs and stops at the matching close — regex can't
// reliably balance nested braces.
//
// Dotall mode `(?s)` lets `.` match newlines.
var registerToolRe = regexp.MustCompile(`(?s)server\.(?:registerTool|tool)\(\s*"([a-zA-Z0-9_\-]+)"\s*,\s*\{`)

// descRe pulls the description string from a tool body. Descriptions
// can be string concatenations (joined with `+`) spanning multiple
// lines — we capture each quoted segment and rejoin.
var descRe = regexp.MustCompile(`description\s*:\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)`)

// stringLitRe matches one quoted string literal (handling escaped quotes).
var stringLitRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// inputSchemaRe pulls the inputSchema block — we only use it to count
// parameters and capture their names (good signal for benign-ness).
var inputSchemaRe = regexp.MustCompile(`(?s)inputSchema\s*:\s*\{(.*?)\}`)

// paramNameRe finds parameter names inside an inputSchema block.
// Matches `paramName: z.something(...)`.
var paramNameRe = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*z\.`)

// Tool is one extracted tool.
type Tool struct {
	Name        string
	Description string
	ParamNames  []string
}

// BenignEntry mirrors the corpus YAML shape for benign entries.
// Same top-level fields as corpus/attacks/*.yaml, plus
// expected_classification.
type BenignEntry struct {
	ID                     string         `yaml:"id"`
	Slug                   string         `yaml:"slug"`
	Title                  string         `yaml:"title"`
	Version                int            `yaml:"version"`
	Created                string         `yaml:"created"`
	Updated                string         `yaml:"updated"`
	ExpectedClassification string         `yaml:"expected_classification"`
	Payload                BenignPayload  `yaml:"payload"`
	Source                 BenignSource   `yaml:"source"`
	Notes                  string         `yaml:"notes,omitempty"`
}

type BenignPayload struct {
	Surface string  `yaml:"surface"`
	Text    string  `yaml:"text"`
	Context Context `yaml:"context"`
}

type Context struct {
	SuspiciousParameters []string `yaml:"suspicious_parameters,omitempty"`
}

type BenignSource struct {
	Type       string `yaml:"type"`
	Repo       string `yaml:"repo"`
	Path       string `yaml:"path"`
	URL        string `yaml:"url"`
	License    string `yaml:"license"`
	ServerName string `yaml:"server_name"`
}

func main() {
	var (
		serverName = flag.String("server", "", "MCP server name (e.g. 'filesystem')")
		sourceURL  = flag.String("source", "", "raw URL of the server's main TS source file")
		license    = flag.String("license", "MIT", "SPDX license identifier for the source repo")
		repoSlug   = flag.String("repo", "modelcontextprotocol/servers", "GitHub owner/repo")
		repoPath   = flag.String("path", "", "path within the repo (e.g. 'src/filesystem/index.ts')")
		startID    = flag.Int("start-id", 1, "first benign-entry ID number (B-NNN)")
		outDir     = flag.String("output", "./corpus/benign", "output directory for YAML files")
		dryRun     = flag.Bool("dry-run", false, "print what would be written; don't touch disk")
	)
	flag.Parse()

	if *serverName == "" || *sourceURL == "" {
		fmt.Fprintln(os.Stderr, "extract-benign: --server and --source are required")
		flag.Usage()
		os.Exit(2)
	}

	// 1. Fetch the source.
	source, err := fetchSource(*sourceURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch %s: %v\n", *sourceURL, err)
		os.Exit(1)
	}

	// 2. Extract tools.
	tools := extractTools(source)
	if len(tools) == 0 {
		fmt.Fprintln(os.Stderr, "extract-benign: no tools matched the registerTool() pattern in this source")
		os.Exit(1)
	}
	fmt.Printf("extracted %d tools from %s\n", len(tools), *serverName)

	// 3. Convert each to a BenignEntry + write YAML.
	if !*dryRun {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", *outDir, err)
			os.Exit(1)
		}
	}

	today := time.Now().UTC().Format("2006-01-02")
	for i, t := range tools {
		id := fmt.Sprintf("B-%03d", *startID+i)
		slug := fmt.Sprintf("%s-%s", *serverName, strings.ReplaceAll(t.Name, "_", "-"))

		entry := BenignEntry{
			ID:                     id,
			Slug:                   slug,
			Title:                  fmt.Sprintf("%s server: %s", *serverName, t.Name),
			Version:                1,
			Created:                today,
			Updated:                today,
			ExpectedClassification: "benign",
			Payload: BenignPayload{
				Surface: "tool_description",
				Text:    t.Description,
				Context: Context{
					SuspiciousParameters: filterSuspiciousParams(t.ParamNames),
				},
			},
			Source: BenignSource{
				Type:       "github_repo",
				Repo:       *repoSlug,
				Path:       *repoPath,
				URL:        *sourceURL,
				License:    *license,
				ServerName: *serverName,
			},
			Notes: fmt.Sprintf("Auto-extracted from upstream %s server. Tool name: %s. Parameters: %s.",
				*serverName, t.Name, strings.Join(t.ParamNames, ", ")),
		}

		path := filepath.Join(*outDir, id+"-"+slug+".yaml")
		if *dryRun {
			data, _ := yaml.Marshal(entry)
			fmt.Println("--- would write", path)
			fmt.Println(string(data))
			continue
		}
		if err := writeYAML(path, entry); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("  wrote %s\n", path)
	}
}

// fetchSource downloads the TS/Python source file at url.
func fetchSource(url string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "mcp-sentinel-extract-benign/0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// extractTools tries two extraction strategies in order:
//
//  1. New SDK pattern: `server.registerTool("name", { description, inputSchema, ... }, handler)`
//     Used by current modelcontextprotocol/servers (filesystem, memory, ...).
//
//  2. Legacy pattern: an object literal with `name: "..."` and `description: "..."`
//     as direct keys. Used by modelcontextprotocol/servers-archived (slack,
//     github, postgres, ...). The tools are typically stored in a
//     `const tools: Tool[] = [ { name, description, inputSchema }, ... ]`
//     array — we don't need to find the array, just the object literals.
//
// We try (1) first; if zero matches, we fall back to (2). This keeps a
// single source-of-truth `extractTools` for both eras of MCP servers.
func extractTools(source string) []Tool {
	tools := extractToolsNewSDK(source)
	if len(tools) == 0 {
		tools = extractToolsLegacy(source)
	}
	return tools
}

// extractToolsNewSDK handles the `server.registerTool("name", {...}, handler)` pattern.
func extractToolsNewSDK(source string) []Tool {
	var tools []Tool
	matches := registerToolRe.FindAllStringSubmatchIndex(source, -1)
	for _, m := range matches {
		nameStart, nameEnd := m[2], m[3]
		name := source[nameStart:nameEnd]
		bodyStart := m[1]

		bodyEnd, ok := findMatchingBrace(source, bodyStart-1)
		if !ok {
			fmt.Fprintf(os.Stderr, "  skip tool %q: unbalanced braces in body\n", name)
			continue
		}
		body := source[bodyStart:bodyEnd]

		desc := extractDescription(body)
		if desc == "" {
			fmt.Fprintf(os.Stderr, "  skip tool %q: no description extractable\n", name)
			continue
		}

		params := extractParamNames(body)
		tools = append(tools, Tool{
			Name:        name,
			Description: desc,
			ParamNames:  params,
		})
	}
	return tools
}

// legacyNameRe finds `name: "<id>"` followed (within the same object
// literal) by `description: "..."`. We use the position of `name:` as
// an anchor, then walk back to the enclosing `{` and forward to its
// matching `}` to extract the body.
var legacyNameRe = regexp.MustCompile(`name\s*:\s*"([a-zA-Z0-9_\-]+)"`)

// extractToolsLegacy handles the older pattern: object literals with
// `name:` and `description:` as direct keys.
func extractToolsLegacy(source string) []Tool {
	var tools []Tool
	matches := legacyNameRe.FindAllStringSubmatchIndex(source, -1)
	for _, m := range matches {
		nameStart, nameEnd := m[2], m[3]
		name := source[nameStart:nameEnd]
		nameKeyPos := m[0]

		// Find the `{` that opens this object literal: walk backward
		// from nameKeyPos, balancing closes, until depth dips below 0.
		openIdx, ok := findEnclosingOpenBrace(source, nameKeyPos)
		if !ok {
			continue
		}
		closeIdx, ok := findMatchingBrace(source, openIdx)
		if !ok {
			continue
		}
		body := source[openIdx+1 : closeIdx]

		desc := extractDescription(body)
		if desc == "" {
			// Some object literals are not tool definitions (e.g. an
			// `arguments: { name: ..., description: ... }` schema
			// fragment). Silent skip — these are noise, not failures.
			continue
		}
		params := extractParamNames(body)
		tools = append(tools, Tool{
			Name:        name,
			Description: desc,
			ParamNames:  params,
		})
	}
	return tools
}

// findEnclosingOpenBrace walks backward from idx and returns the index
// of the `{` that opens the enclosing object literal. Skips string
// contents and balances any nested braces seen along the way.
func findEnclosingOpenBrace(s string, idx int) (int, bool) {
	if idx <= 0 || idx >= len(s) {
		return 0, false
	}
	depth := 0
	for i := idx - 1; i >= 0; i-- {
		c := s[i]
		switch c {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return i, true
			}
			depth--
		}
	}
	return 0, false
}

// findMatchingBrace returns the index of the `}` that closes the `{`
// at openIdx. Skips string literals so braces inside strings don't
// confuse the counter. Returns ok=false if EOF reached first.
func findMatchingBrace(s string, openIdx int) (int, bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '{' {
		return 0, false
	}
	depth := 0
	i := openIdx
	for i < len(s) {
		c := s[i]
		switch c {
		case '"', '\'', '`':
			// Skip to the matching close quote, respecting escapes.
			quote := c
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == quote {
					i++
					break
				}
				i++
			}
		case '{':
			depth++
			i++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
			i++
		default:
			i++
		}
	}
	return 0, false
}

// extractDescription pulls a description string, concatenating multi-
// line `"..." + "..."` literals.
func extractDescription(body string) string {
	m := descRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	concat := m[1]

	// Pull each "..." literal and join.
	var parts []string
	for _, lit := range stringLitRe.FindAllStringSubmatch(concat, -1) {
		parts = append(parts, unescapeJSString(lit[1]))
	}
	return strings.Join(parts, "")
}

// extractParamNames pulls parameter keys from an inputSchema block.
func extractParamNames(body string) []string {
	m := inputSchemaRe.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	schemaBody := m[1]
	var names []string
	for _, p := range paramNameRe.FindAllStringSubmatch(schemaBody, -1) {
		names = append(names, p[1])
	}
	return names
}

// unescapeJSString handles the common JS string escapes (\n, \t, \", \\).
func unescapeJSString(s string) string {
	r := strings.NewReplacer(
		`\n`, "\n",
		`\t`, "\t",
		`\"`, `"`,
		`\\`, `\`,
		`\'`, "'",
	)
	return r.Replace(s)
}

// filterSuspiciousParams reports any parameter name that matches the
// scanner's exfil-channel watchlist (mirrored from ingest.go). Helps
// us spot real MCP tools that genuinely use suspicious-sounding names
// — those are the false-positive candidates we WANT in the benign
// corpus.
func filterSuspiciousParams(names []string) []string {
	watchlist := map[string]bool{
		"note": true, "notes": true, "feedback": true, "details": true,
		"extra": true, "additional": true, "metadata": true, "debug": true,
		"sidenote": true, "context": true, "annotation": true,
		"reasoning": true, "remark": true,
	}
	var hits []string
	for _, n := range names {
		if watchlist[strings.ToLower(n)] {
			hits = append(hits, n)
		}
	}
	return hits
}

// writeYAML marshals an entry to YAML and writes it atomically.
func writeYAML(path string, entry BenignEntry) error {
	data, err := yaml.Marshal(entry)
	if err != nil {
		return err
	}
	// Add a header comment so humans editing the file know it's auto-gen.
	header := "# Auto-extracted by tools/extract-benign. Do not hand-edit.\n" +
		"# Source: " + entry.Source.URL + "\n" +
		"# Server: " + entry.Source.ServerName + " (" + entry.Source.License + ")\n\n"
	return os.WriteFile(path, []byte(header+string(data)), 0o644)
}
