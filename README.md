# mcp-sentinel

**Status:** pre-release scaffold. Not usable yet. See [Roadmap](#roadmap).

A semantic scanner for **MCP tool poisoning**. Detects malicious instructions embedded in Model Context Protocol tool metadata (names, descriptions, schemas) before the agent ever calls them.

## Why this exists

The MCPTox benchmark (AAAI 2026, anonymous review) reports attack success rates up to **72.8% on frontier LLM agents**, with the most refusal-prone model (Claude-3.7-Sonnet) refusing fewer than 3% of tool-poisoning attacks. Existing safety alignment doesn't engage when the malicious instruction arrives via a tool description rather than a user prompt.

A handful of MCP scanners already exist (`mcp-scan` by Invariant Labs, `mcp-scanner` by Cisco AI Defense, `agent-scan` by Snyk, `MCP-Shield`, MEDUSA). All of them rely on **regex / YARA patterns**, an **LLM-as-judge**, or both layered on top of each other. None uses **embedding-based semantic similarity** against a curated corpus of known attacks.

That's the gap mcp-sentinel fills.

## How it works (planned)

Four-stage pipeline. See `ARCHITECTURE.md` for the full data flow.

1. **Ingest** — parse JSON, walk the tool/schema tree, emit one Unit per scannable surface (tool description, schema property, parameter name).
2. **Prefilter** — Aho-Corasick scan for known literal substrings, pseudo-XML wrapper tags, and suspicious parameter names. Cheap routing gate; drops ~95% of Units before the expensive stages.
3. **Embed + retrieve** — embed each surviving Unit and find the top-k nearest neighbours in a corpus of known-malicious tool metadata. Catches paraphrases of known attacks.
4. **Judge** — a structurally-defended LLM runs only on candidates above the similarity threshold. XML-bounded untrusted input, JSON-schema-enforced response, self-consistency on borderline confidence, and a heuristic prefilter against judge-prompt-injection patterns.

The corpus is the primary artifact — every finding links back to a cited entry in `corpus/attacks/`, not an opaque rule. See `CORPUS.md` for the schema and `ARCHITECTURE.md` for the pipeline.

## Roadmap

Design phase (done):

- [x] Prior-art survey of 5 public MCP scanners — `notes/prior-art.md`
- [x] MCPTox reading notes — `notes/mcptox.md`
- [x] Go module scaffold (builds green; scanner not implemented)
- [x] `THREAT_MODEL.md` — 10 attack classes, in/out of scope, trust assumptions
- [x] `CORPUS.md` — YAML schema, taxonomy, negative-corpus plan
- [x] `corpus/attacks/` — 15 seed entries, license-attributed
- [x] `ARCHITECTURE.md` — 4-stage pipeline, ONNX backend, judge defenses

Implementation phase (in progress):

- [x] First public push of the design docs
- [x] Stage 0 — JSON ingest into per-surface `Unit` records
- [x] Stage 1 — literal / pseudo-XML / parameter-name prefilter
- [x] Stage 2 — embedding retrieval via Voyage AI (`voyage-3.5-lite`)
- [x] Stage 3 — structurally-defended LLM judge (Anthropic Claude, `tool_use` schema firewall + self-consistency + Unicode-normalized input sanitizer)
- [ ] Stage 4 — text / json / sarif report renderers
- [ ] Negative corpus: 40+ benign entries from `modelcontextprotocol/servers`
- [ ] Threshold tuning on benign corpus once it exists
- [ ] Local ONNX embedding backend (v0.2 — see `ARCHITECTURE.md §4.2`)
- [ ] MCPTox eval-set integration when the dataset becomes public

## Non-goals

- Not a runtime guardrail. mcp-sentinel inspects tool metadata before invocation — runtime filtering is out of scope.
- Not a general-purpose secret/credential scanner. Use [trufflehog](https://github.com/trufflesecurity/trufflehog) for that.
- Not "the most comprehensive" scanner. We optimize for one thing (tool-metadata poisoning) and cite the gaps explicitly.

## License

Apache 2.0. See `LICENSE`.
