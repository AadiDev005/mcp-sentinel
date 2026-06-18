# corpus-raw/ — Seed attack examples

15 attack examples mined from public MCP-scanner repositories on 2026-06-17.

On Day 4 we convert these unstructured entries to a YAML schema (see `../CORPUS.md` once written) and build the negative corpus alongside.

See [INDEX.md](INDEX.md) for the full table.

## Provenance rules (non-negotiable)

1. Every file MUST cite its source (paper section, blog URL, repo path + commit).
2. NO fabricated attacks. Verbatim payloads are quoted exactly; pattern-class examples are clearly labeled "illustrative" and trace back to a rule definition.
3. NO content derived from any contributor's day-job employer or proprietary systems — public sources only.
4. Each attack is one file: `NNN-short-name.md` (3-digit zero-padded).
5. License-compatible attribution: Apache-2.0 / MIT sources can be quoted; AGPL-3.0 (MEDUSA) is paraphrased with rule-ID citation only.

## Sources

| Source | Type | License | Used in |
|---|---|---|---|
| Invariant Labs `mcp-injection-experiments` | OSS scanner / demo | Apache-2.0 | 001, 002, 003 |
| MCP-Shield (`riseandignite/mcp-shield`) | OSS scanner | MIT | 004, 005, 006, 007, 008 |
| MEDUSA (`Pantheon-Security/medusa`) | OSS scanner | AGPL-3.0 (paraphrased only) | 009, 010, 011, 012, 013, 014, 015 |

## Day 2 status

✅ Done — 15 entries with verifiable sources, license-safe.
Next: Day 4 — structured `CORPUS.md` schema + negative-corpus plan.
