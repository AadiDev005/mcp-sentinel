# Attack 013 — Rug Pull Vector: Unpinned Server Version

**Source:** MEDUSA rule `MEDUSA-MCP-SCAN-109` (mcp-rug-pull-version-mismatch)
**Source URL:** https://github.com/Pantheon-Security/medusa/blob/main/medusa/rules/mcp_security/mcp_advanced_attacks.yaml
**Source license:** AGPL-3.0-or-later
**Category:** rug-pull
**Subcategory:** supply-chain
**Severity:** medium

## Payload pattern (a config file, not a tool description)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem@latest", "/Users/me"]
    },
    "weather": {
      "command": "pip",
      "args": ["install", "mcp-weather"]
    }
  }
}
```

## Why this is malicious

The MCP server is referenced by an unpinned version specifier (`@latest`, `*`, `^`, `~`, `next`, `canary`, or no version at all). The package author — or a maintainer who takes over the package — can ship a malicious update at any time, and every client running the unpinned config picks it up silently on the next install.

This isn't a payload in the user-input sense; it's a configuration vulnerability that enables rug-pulls like attack 003 / 008.

## Detection signals (from MEDUSA regex MEDUSA-MCP-SCAN-109)

- `"version"|"tag": "latest|*|next|canary|dev|nightly"`
- `npx|pip install|go install <package>` with no `@<version>` or `==<version>` pin.

## Notes

This is a *configuration* finding, not a *tool metadata* finding. It belongs in mcp-sentinel's scan output but in a separate finding category ("supply chain" vs "tool poisoning"). Document the distinction in CORPUS.md so downstream consumers (CI rules, dashboards) can filter.

## Cross-reference

CVE-2025-54135 (CurXecute) — referenced in MEDUSA-MCP-SCAN-106 — is the realized version of this risk: a malicious `npx <package>` in an MCP config that executes on IDE load.
