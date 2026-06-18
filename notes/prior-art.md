# Prior Art — MCP Security Scanners

**Date of survey:** 2026-06-17
**Goal:** Understand what already exists so mcp-sentinel can claim a defensible niche, not duplicate work.

---

## Scanners surveyed

| Tool | Org | Repo | Lang | License | Stars (rough) |
|---|---|---|---|---|---|
| **mcp-scan** | Invariant Labs | invariantlabs-ai/mcp-scan | Python | Apache-2.0 | de-facto standard |
| **mcp-scanner** | Cisco AI Defense | cisco-ai-defense/mcp-scanner | Python 3.11+ | Apache-2.0 | enterprise-backed |
| **agent-scan** | Snyk | snyk/agent-scan | Python 3.13+ | Apache-2.0 | enterprise-backed |
| **MCP-Shield** | riseandignite | riseandignite/mcp-shield | TypeScript | MIT | community |
| **MEDUSA** | Pantheon Security | Pantheon-Security/medusa | Python | AGPL-3.0 | broad scope (not MCP-only) |
| **MCP-Scanner** (academic) | Univ. group | (paper, no public code) | n/a | n/a | ACM/IEEE 2026 paper |

---

## Detection methodology — what each one does

| Tool | Regex / YARA | LLM-as-judge | Embeddings / semantic similarity | Signatures / hashes | External API dependency |
|---|---|---|---|---|---|
| mcp-scan (Invariant) | Yes (pattern rules) | Optional via Invariant Guardrails API | **No** | Hashes (for rug-pull detection) | Yes (Invariant Guardrails API for classification) |
| mcp-scanner (Cisco) | YARA rules | Yes (OpenAI / Bedrock Claude) | **No** | YARA signatures | Optional Cisco AI Defense API |
| agent-scan (Snyk) | Local checks (not specified) | Not specified | **No** | n/a | **Required** (Snyk SaaS API token) |
| MCP-Shield | Regex (default) | Optional Claude API | **No** | n/a | Optional (Claude API key) |
| MEDUSA | 40,000+ "detection patterns" (YAML-rule-style) | No | **No** | n/a | None — local CLI |
| MCP-Scanner (paper) | Unknown (paper-only) | Unknown | Unknown | Unknown | n/a |

**The headline finding:** Across every public MCP scanner I could find, **none uses embedding-based semantic similarity** as a detection primitive. Everyone is either regex / YARA / rule-matcher or LLM-judge or both, sometimes layered.

This is a real gap, not a manufactured one — and it matters because:
- Regex / YARA misses novel phrasings of known attacks.
- LLM-judge is expensive ($) and slow (latency), so running it on every tool description doesn't scale.
- A semantic-similarity prefilter against a known-malicious corpus is the standard retrieval pattern from RAG — cheap, fast, generalizable to paraphrases — but no one has applied it to tool metadata.

---

## Input / output / posture

| Tool | Input | Output | Posture |
|---|---|---|---|
| mcp-scan | Live MCP server config, installed servers | Reports (CLI text) | Pre-install / pre-use scanner |
| mcp-scanner | Live HTTP/SSE/stdio servers, JSON files, static dirs | 5 formats: summary, detailed, table, by_severity, raw JSON | CLI + REST API server |
| agent-scan | Auto-discovers Claude/Cursor/Windsurf/Gemini configs | Rich text or JSON, by component | Local scan + background MDM mode |
| MCP-Shield | `.mcp/*.json`, `claude_desktop_config.json` | CLI report | Local CLI |
| MEDUSA | Files / git repo (general code scanner) | CI/CD friendly | General-purpose scanner with MCP rules added on |

---

## Attack coverage matrix

| Category | mcp-scan | Cisco | Snyk | Shield | MEDUSA |
|---|---|---|---|---|---|
| Direct tool poisoning (description injection) | ✓ | ✓ (Prompt Defense Analyzer: instruction override) | ✓ | ✓ (hidden instructions) | ✓ |
| Tool shadowing (one tool overrides another) | ✓ (cross-origin escalation) | ✓ | ✓ | ✓ | ✓ |
| Rug-pull (tool changes after install) | ✓ (hash-based) | n/a | n/a | n/a | ✓ |
| Schema poisoning | n/a | ✓ | n/a | n/a | ✓ |
| ATPA (Advanced Tool Poisoning Attacks) | n/a | n/a | n/a | n/a | ✓ |
| Sampling injection | n/a | n/a | n/a | n/a | ✓ |
| Cross-server manipulation | ✓ | n/a | n/a | ✓ | ✓ |
| Data-exfil channels in params | n/a | ✓ (data leakage) | n/a | ✓ | ✓ |
| Indirect injection (via tool output) | n/a | ✓ | n/a | n/a | n/a |
| Unicode / homoglyph attack | n/a | ✓ | n/a | n/a | n/a |
| Behavioral mismatch (docstring vs impl) | n/a | ✓ (multi-lang) | n/a | n/a | n/a |

The Cisco scanner is the most rigorous taxonomy (12-vector Prompt Defense Analyzer). MEDUSA has the broadest MCP-attack-category coverage. mcp-scan is the most adopted.

---

## Where mcp-sentinel fits

### What we won't claim
- We won't say "first MCP security scanner" — that's mcp-scan / mcp-scanner.
- We won't say "most comprehensive" — that's MEDUSA.
- We won't say "enterprise-backed" — that's Cisco and Snyk.

### What we will claim
**"A semantic-similarity-first scanner for MCP tool poisoning. Built on the retrieval pattern (k-NN over embeddings of known-malicious tool metadata) plus a structurally-defended LLM judge for the borderline cases."**

Specifically:
1. **Two-stage detection** (cheap embedding retrieval → expensive LLM judge on top-k) — none of the prior art does this. They do regex-then-LLM (substring → semantics) or LLM-alone or rules-alone.
2. **A curated corpus is the primary artifact**, not a rule file. Every detection links back to a cited attack in `CORPUS.md`. The corpus is auditable; rules are not.
3. **Structural judge defenses** (XML-bounded untrusted input, json-schema response, self-consistency, heuristic prefilter) — addresses the "the scanner itself gets prompt-injected" problem nobody else documents publicly.
4. **Go binary, no Python runtime, no SaaS account required.** mcp-scan and mcp-scanner are Python; agent-scan needs a Snyk token. mcp-sentinel is `go install` and offline-capable (embeddings can be local).
5. **JSON-first input.** Optional HTTP. stdio behind `--allow-execute` flag. The default mode never runs untrusted MCP server binaries — most existing scanners do, to introspect them.

### Risks to our positioning

- **"Why not just contribute embeddings to mcp-scan?"** Honest answer: Invariant's stack is Python + their SaaS Guardrails API, which is a deliberate productization. Our value is a single-binary, Go-native, SaaS-free scanner. That's a different deployment target, not a competing rule set.
- **"Cisco's scanner already has LLM-as-judge."** Yes — but they don't have an embedding-retrieved candidate set in front of it. LLM-judging every tool every time is expensive and slow. We optimize that.
- **"MEDUSA already covers MCP."** MEDUSA is a 79-analyzer general scanner where MCP is one feature. mcp-sentinel is MCP-only and aims to be the best at exactly that.

---

## Decisions for INTERVIEW_DEFENSE.md (carry forward)

- **Decision: don't compete on attack-category count.** Match the top-5 categories (tool poisoning, shadowing, rug-pull, schema poisoning, data-exfil-in-params). Skip the long tail (sampling injection, Unicode homoglyphs, etc.) for v0. Cite the gap explicitly in the roadmap.
- **Decision: corpus-first, rules-last.** Rules can supplement the corpus for edge cases (e.g., known YARA patterns we re-export). The primary detection signal is similarity over the corpus.
- **Decision: Go.** Differentiator vs the Python-dominated landscape. Aligns with K8s contributor identity.
- **Decision: Apache-2.0.** Matches the rest of the ecosystem; AGPL (MEDUSA's path) would scare enterprise adopters who might otherwise cite us.

---

## Sources

- mcp-scan: https://github.com/invariantlabs-ai/mcp-scan
- mcp-scanner: https://github.com/cisco-ai-defense/mcp-scanner
- agent-scan: https://github.com/snyk/agent-scan
- MCP-Shield: https://github.com/riseandignite/mcp-shield
- MEDUSA: https://github.com/Pantheon-Security/medusa
- MCP-Scanner paper: https://dl.acm.org/doi/10.1145/3786160.3788471
- Cisco blog: https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner
- Invariant blog: https://invariantlabs.ai/blog/introducing-mcp-scan
- Snyk Labs: https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
