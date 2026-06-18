# Threat Model — mcp-sentinel

**Version:** v0.1 draft (2026-06-17)
**Scope:** what mcp-sentinel is built to detect, what it isn't, and the trust assumptions it makes about its environment.

This document is the source of truth for "is X in scope?" — every feature request and every CVE filing checks against it.

---

## 1. System under threat

An **MCP host** (Cursor, Claude Desktop, Windsurf, VS Code with an MCP extension, or any agent loop) loads one or more **MCP servers** at startup. Each server publishes a set of **tools** (callable functions with structured input/output), **prompts** (templated user-facing prompts), and **resources** (URI-addressed read-only data).

At runtime, when the agent decides to act, it:

1. Reads the union of all loaded tools' **metadata** (names, descriptions, input JSON schemas).
2. Decides which tool to invoke based on that metadata plus the user's request.
3. Constructs an arguments object matching the chosen tool's input schema.
4. Invokes the tool over the MCP transport (stdio, Streamable HTTP, deprecated HTTP+SSE).
5. Receives the tool's output and re-prompts itself with that output included in context.

**The attack surface mcp-sentinel addresses is step 1 — the tool metadata that the agent reads before invocation.**

---

## 2. Attacker capabilities (the threat actor model)

### Primary attacker: the malicious MCP server author

We assume the attacker controls:

- The **name** of any tool published by a server they own.
- The **description** string of any tool they publish.
- The **JSON schema** of any tool's input, including property names, property descriptions, examples, and default values.
- The **resource URIs** the server publishes.
- The **server name** itself and the **package** that ships it (npm, pip, go module).
- The **version** the user installs (initial install and any subsequent updates).

We assume the attacker **does not** control:

- The user's MCP client binary (Cursor, Claude Desktop, etc.) — that is trusted.
- The user's filesystem or network (no machine compromise required).
- Other MCP servers loaded into the same host — but they can *reference* them.
- The LLM weights — but they can exploit the LLM's instruction-following.

### Realistic distribution channels

- The attacker publishes their server to a public package registry (npm / PyPI / Go modules) under a legitimate-sounding name.
- The attacker contributes a malicious tool to an otherwise-legitimate community server (supply-chain compromise of a maintainer account).
- The attacker maintains a benign server for months, then ships a malicious update (rug pull).
- The attacker provides a paid or sponsored MCP server that users add by hand.

### Attacker goals (in priority order, based on the public attack literature)

1. **Data exfiltration** — read sensitive files (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, source code) and smuggle them out via tool arguments or unrelated parameters.
2. **Silent communication redirect** — BCC emails, redirect WhatsApp/Slack messages, intercept Git pushes.
3. **Privilege escalation across MCP servers** — hijack a victim tool from a trusted server via a malicious tool in an untrusted server.
4. **Tool selection bias** — make the agent prefer the attacker's tool over a legitimate competitor (ToolHijacker, ToolTweak — 96.7% and 81% reported ASR).
5. **Persistence** — survive a re-scan via rug pull (description changes after first load).

---

## 3. In-scope attacks (mcp-sentinel detects)

Each row maps to entries in `corpus/attacks/` (see `corpus/attacks/INDEX.md`) and a v0 detection plan.

| # | Attack class | Corpus entries | v0.1? | Detection approach |
|---|---|---|---|---|
| T1 | Direct prompt injection in `tool.description` | T1-001, T1-004, T1-007 | yes | Embedding similarity to corpus + LLM judge |
| T2 | Cross-tool / cross-server shadowing | T2-002, T2-005, T2-008, T2-014 | yes | Embedding + name-graph check |
| T3 | Schema poisoning in property descriptions / examples / titles | T3-009 | yes | Tree-walk + per-node embedding |
| T4 | Parameter-name as payload | T4-011 | yes | Lexical pre-filter (cheap) + embedding |
| T5 | Unrelated parameter as exfil channel | T5-006 | yes | Schema heuristic + LLM judge |
| T6 | Silent BCC / metadata-rename exfil | T6-012 (cross-refs T2-005) | yes | Embedding + literal pattern match |
| T7 | Selection-bias / preference manipulation | T7-015 | yes | Embedding (the main case for embeddings > rules) |
| T8 | Sleeper rug pull (description mutates after install) | T8-003, T2-008 (secondary) | **no, v0.2** | Hash + diff across successive scans |
| T9 | Supply-chain / unpinned-version risk | T9-013 | **no, v0.2** | Config-file scanner (separate finding type) |
| T10 | ATPA — directives in tool *output* | T10-010 | **no, v0.3 / out** | Runtime guardrail problem; see §4 O1 |

### What "v0.1" means concretely

- The scanner ingests a single tool definition (or a directory of them) and emits findings for T1–T7.
- The scanner emits a structured report (`text | json | sarif`) with one finding per detected attack class per tool.
- Every finding links to a `corpus_id` from `corpus/attacks/INDEX.md` so the user can audit *why* we flagged it.

---

## 4. Out-of-scope attacks (documented, deferred or rejected)

| # | Attack class | Why out of scope |
|---|---|---|
| O1 | **ATPA** — malicious instructions in **tool output** that influence the next agent step (corpus T10-010) | Runtime guardrail problem, not a pre-invocation metadata problem. Belongs in a different layer — output filters, runtime guardrails, agent middleware. Roadmapped as v0.3 if at all. |
| O2 | Vulnerabilities in the MCP server's own executable code (RCE in the server binary, CVE-class issues like CVE-2025-6514, CVE-2025-26319 Flowise RCE) | Belongs to a code SAST scanner (MEDUSA, Semgrep). mcp-sentinel does not parse Python / JS / Go source. |
| O3 | LLM jailbreaks in the user's prompt | Different attack surface entirely (user → agent vs server → agent). PromptFortress-class problem, not MCP. |
| O4 | Sandboxing / process isolation of MCP servers | An operating-systems / container concern. mcp-sentinel does not run the servers. |
| O5 | Authentication / OAuth flaws in the MCP transport | Protocol-level concern. mcp-sentinel inspects metadata; auth is configured at the host. |
| O6 | Side-channel timing attacks against the LLM | Research-grade, not field-realistic. |
| O7 | Multi-turn social-engineering of the user via the host UI | Out of band — UI / UX concern. |

---

## 5. Trust assumptions (what mcp-sentinel believes is true)

1. **The MCP client (Cursor, Claude Desktop, etc.) is not compromised.** We trust it to load the metadata we are about to scan without itself modifying it adversarially.
2. **The user trusts the mcp-sentinel binary they ran.** No reproducible-build guarantees in v0.1; trust is `go install`-level.
3. **The user supplies a benign LLM API key for the judge stage** (or runs with `--no-judge` and accepts the embedding-only false-positive rate).
4. **The corpus is honestly curated.** A corpus contributor with commit access could insert false positives (poisoning the scanner). v0.1 mitigates this only by `CODEOWNERS` review and signed commits — not by cryptographic corpus signing.
5. **The embedding model is not adversarially manipulated.** A malicious local embedding model could deliberately lower similarity scores on real attacks. v0.1 expects users to download a vetted model.
6. **JSON parsing is safe.** The scanner takes potentially-untrusted JSON as input. We rely on Go's `encoding/json` and never `eval()` or shell out on parsed content.

---

## 6. Non-goals (explicit)

mcp-sentinel is **not**:

- A runtime guardrail. We scan; we don't intercept.
- A general-purpose code SAST tool. We don't read Python / JS / Go to find RCEs.
- An LLM safety classifier for *user* prompts. We scan *tool* metadata.
- A secret scanner. Use [trufflehog](https://github.com/trufflesecurity/trufflehog).
- A network IDS for MCP traffic. Out of band.
- A replacement for `mcp-scan`, `mcp-scanner`, or MEDUSA — it sits alongside them with a different detection primitive (embedding similarity vs regex / YARA / per-tool LLM judge).

---

## 7. The "scanner-itself-gets-attacked" surface

mcp-sentinel ingests adversary-controlled text (the tool metadata is the adversary's payload) and routes some of that text through an LLM (the judge stage). The judge is itself a potential injection target — the attacker's tool description could include instructions aimed at the *judge*.

Documented in detail in `ARCHITECTURE.md` ("Judge defenses"). Summary of the four primary defenses:

1. **Structural untrusted-input boundary.** The judge prompt wraps the tool description in `<untrusted>...</untrusted>` XML and the system prompt explicitly tells the judge to never follow instructions inside that wrapper.
2. **JSON-schema-enforced response.** The judge returns a typed `{ malicious: bool, confidence: float, reasoning: string }` — even a successful injection cannot exfiltrate text outside the schema.
3. **Self-consistency on near-threshold cases.** When the judge's confidence is in `[0.3, 0.7]`, we re-judge with a paraphrased prompt and take the majority.
4. **Heuristic pre-filter.** Before sending to the judge, strip ANSI escapes, normalize Unicode, and reject inputs containing literal `</untrusted>` (since that's a wrapper-escape attempt).

These defenses are **necessary, not sufficient.** A motivated attacker with corpus access could still craft inputs that fool the judge. We document the residual risk; we do not claim immunity.

---

## 8. Versioning of this document

When the threat model changes (new attack class, scope decision reversed, etc.):

1. Bump the version at the top of this file.
2. Add an entry to `INTERVIEW_DEFENSE.md` explaining the change and why.
3. Add or move the relevant row in §3 / §4.

The threat model is not aspirational. If we cannot detect something today, it goes in §4 with a "v0.X" tag, not in §3.
