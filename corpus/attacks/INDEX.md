# corpus/attacks/ — Index

15 attack entries, organized by taxonomy from `THREAT_MODEL.md §3`.
Schema defined in `../../CORPUS.md §3`.

## By taxonomy

### T1 — direct-poisoning (3 entries, v0.1)
- [T1-001 — Direct Poisoning: SSH Key Exfiltration via `<IMPORTANT>`](T1-001-direct-poisoning-ssh-key-exfil.yaml) — critical · Invariant (Apache-2.0)
- [T1-004 — Calculator Tool with `<instructions>` SSH Leak](T1-004-shield-calculator-ssh-leak.yaml) — critical · MCP-Shield (MIT)
- [T1-007 — `<secret>` Tag Encouraging Path Traversal](T1-007-shield-secret-tag-pathtraversal.yaml) — critical · MCP-Shield (MIT)

### T2 — tool-shadowing (4 entries, v0.1)
- [T2-002 — Email Redirect via Cross-Tool Instruction](T2-002-tool-shadowing-email-redirect.yaml) — critical · Invariant (Apache-2.0)
- [T2-005 — Email Tool with BCC-Style Metadata Exfil](T2-005-shield-email-bcc-exfil.yaml) — critical · MCP-Shield (MIT)
- [T2-008 — Conditional Shadowing of WhatsApp send_message](T2-008-shield-whatsapp-shadowing.yaml) — critical · MCP-Shield (MIT)
- [T2-014 — Cross-Server Tool Invocation Instructions](T2-014-medusa-cross-server-manipulation.yaml) — high · MEDUSA (AGPL, paraphrased)

### T3 — schema-poisoning (1 entry, v0.1)
- [T3-009 — Injection in JSON Schema Property](T3-009-medusa-full-schema-poisoning.yaml) — critical · MEDUSA (AGPL, paraphrased)

### T4 — parameter-name-injection (1 entry, v0.1)
- [T4-011 — Parameter Name Itself Contains Injection](T4-011-medusa-parameter-name-injection.yaml) — high · MEDUSA (AGPL, paraphrased)

### T5 — exfil-channel (1 entry, v0.1)
- [T5-006 — Suspicious Parameter Names as Exfiltration Channels](T5-006-shield-weather-exfil-params.yaml) — high · MCP-Shield (MIT)

### T6 — silent-bcc (1 entry, v0.1)
- [T6-012 — Literal BCC Field in Email Tool Configuration](T6-012-medusa-bcc-email-literal.yaml) — critical · MEDUSA (AGPL, paraphrased)

### T7 — selection-hijack (1 entry, v0.1)
- [T7-015 — ToolHijacker / ToolTweak Preference Manipulation](T7-015-medusa-toolhijacker-preference.yaml) — critical · MEDUSA (AGPL, paraphrased)

### T8 — rug-pull (1 entry, v0.2)
- [T8-003 — Sleeper Rug Pull: WhatsApp Hijack After Second Load](T8-003-rug-pull-whatsapp-takeover.yaml) — critical · Invariant (Apache-2.0)

### T9 — supply-chain (1 entry, v0.2)
- [T9-013 — Rug Pull Vector: Unpinned Server Version](T9-013-medusa-rug-pull-unpinned-version.yaml) — medium · MEDUSA (AGPL, paraphrased)

### T10 — atpa (1 entry, v0.3 / out of scope)
- [T10-010 — ATPA: Tool Output Contains Hidden Instructions](T10-010-medusa-atpa-output-poisoning.yaml) — critical · MEDUSA (AGPL, paraphrased)

## By v0.1 scope (the 11 entries the v0.1 scanner detects)

T1-001, T1-004, T1-007, T2-002, T2-005, T2-008, T2-014, T3-009, T4-011, T5-006, T6-012, T7-015.

## By v0.2 / v0.3 / out (4 entries, documented but not detected in v0.1)

T8-003 (rug-pull, needs successive scans), T9-013 (supply chain, separate finding type),
T2-008 secondary T8 (deferred to v0.2), T10-010 (ATPA, out of scope).

## Paired-with map (embedding sanity-check pairs)

| Anchor | Should land near | Why |
|---|---|---|
| T1-001 | T1-004, T1-007 | SSH-exfil via unrelated param, different pseudo-XML tag |
| T2-002 | T2-005, T6-012, T2-014 | Silent comms redirect, different surface |
| T2-005 | T2-002, T6-012, T7-015 | BCC pattern (literal vs metadata-field vs social-proof override) |
| T2-008 | T8-003, T2-002 | WhatsApp hijack (JS port of Python original) |
| T3-009 | T4-011 | Schema-tree injection (property vs name) |
| T6-012 | T2-005, T2-002 | BCC family |
| T7-015 | T2-005 | Coercion via "VERY important" vs "Trusted by OpenAI" |

## License attribution summary

- 5 entries from Invariant Labs (Apache-2.0) — verbatim payloads quoted.
- 5 entries from MCP-Shield (MIT) — verbatim payloads quoted.
- 7 entries from MEDUSA (AGPL-3.0) — payloads written from scratch matching
  the regex semantics; prose is ours; rule IDs cited.
  Validation rule §6.10 in CORPUS.md enforces no verbatim AGPL strings.

## What's next

- Day 5: Write `ARCHITECTURE.md`.
- Day 6 review: re-run license recheck pass.
- Pre-v0.1: grow corpus to ~50 entries (5/category target).
- Pre-v0.1: write 40+ `corpus/benign/*.yaml` entries from `modelcontextprotocol/servers`.
