# corpus-raw/ — Index

15 attack examples mined from public scanner repositories. Day 2 (2026-06-17).

Every entry has a verifiable source URL. No fabricated payloads.

## By category

| # | Category | Subcategory | Severity | Source |
|---|---|---|---|---|
| 001 | direct-tool-poisoning | ssh-key-exfil via `<IMPORTANT>` | critical | Invariant (Apache-2.0) |
| 002 | tool-shadowing | cross-tool email-redirect | critical | Invariant (Apache-2.0) |
| 003 | rug-pull | sleeper WhatsApp takeover | critical | Invariant (Apache-2.0) |
| 004 | direct-tool-poisoning | ssh-key-exfil via `<instructions>` | critical | MCP-Shield (MIT) |
| 005 | tool-shadowing | silent-BCC via `metadata` param | critical | MCP-Shield (MIT) |
| 006 | exfiltration-channel | unrelated parameter names | high | MCP-Shield (MIT) |
| 007 | direct-tool-poisoning | path-traversal via `<secret>` | critical | MCP-Shield (MIT) |
| 008 | rug-pull + shadowing | conditional WhatsApp hijack (JS port of 003) | critical | MCP-Shield (MIT) |
| 009 | schema-poisoning | injection in JSON property `description` | critical | MEDUSA (AGPL-3.0) |
| 010 | atpa | tool output as next-call directive | critical | MEDUSA (AGPL-3.0) |
| 011 | schema-poisoning | parameter *name* carries directive | high | MEDUSA (AGPL-3.0) |
| 012 | silent-bcc-exfil | literal `bcc` field in tool config | critical | MEDUSA (AGPL-3.0) |
| 013 | rug-pull | supply chain — unpinned version | medium | MEDUSA (AGPL-3.0) |
| 014 | tool-shadowing | cross-server privilege escalation | high | MEDUSA (AGPL-3.0) |
| 015 | tool-selection-hijack | ToolHijacker / ToolTweak preference manipulation | critical | MEDUSA (AGPL-3.0) |

## By scope decision (carry forward to CORPUS.md)

**In scope for v0.1 (metadata scanning):**
001, 002, 004, 005, 006, 007, 009, 011, 012, 014, 015 — anything in `tool.name`, `tool.description`, or `tool.inputSchema`.

**Roadmap (v0.2+):**
003, 008 — rug pull (needs successive-scan comparison + hashing).
013 — supply chain (separate finding category).
014 advanced mode — cross-server (needs full MCP client config as input).

**Out of scope, documented for completeness:**
010 ATPA — runtime guardrail problem, not a metadata problem.

## Cross-source pairs (semantic-similarity test cases)

Entries that describe the **same intent** with **different surface forms**. These are the golden test cases for the embedding stage — high cosine similarity expected:

| Pair | Intent | Surface differences |
|---|---|---|
| 001 ↔ 004 | SSH key exfil via unrelated string param | `<IMPORTANT>` vs `<instructions>`, `sidenote` vs `notes`, Python vs JS |
| 002 ↔ 005 ↔ 012 | Silent BCC of communications | `attkr@pwnd.com` vs `attacker@evil.com` vs literal `bcc:` field |
| 003 ↔ 008 | WhatsApp recipient hijack | Python `<IMPORTANT>` vs JS `<system>` |
| 002 ↔ 014 | Cross-tool/cross-server steering | Concrete `send_email` mention vs abstract "the other tool" |
| 005 ↔ 015 | "Trust me" social-proof override | "VERY VERY important" coercion vs ToolTweak "Trusted by OpenAI" |

If our embedding model is doing its job, each pair should land in the top-3 nearest neighbors of the other. We test this in `internal/embed/embed_test.go` once that stage is implemented (weekend 2).

## License compatibility note

- Apache-2.0 (Invariant) — compatible with mcp-sentinel's Apache-2.0 license.
- MIT (MCP-Shield) — compatible.
- **AGPL-3.0-or-later (MEDUSA)** — **NOT compatible** for direct redistribution. We can study MEDUSA's published rules and write our own corpus entries in our own words, but we cannot copy-paste their YAML rule files into our repo. The entries above paraphrase the regex semantics and cite the source rule ID; the prose is ours. Before public push (Day 7), re-confirm that nothing in `corpus-raw/00{9-15}.md` is a verbatim copy of MEDUSA's text.
