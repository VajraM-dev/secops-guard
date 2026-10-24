---
name: plugin-audit
description: >
  Use when the user asks to audit their Claude Code plugins, asks "are my claude plugins safe",
  wants hooks or MCP servers checked, wants an MCP server audit, or when a secops-guard SessionStart
  message reports added/changed plugins or auto-updating marketplaces.
---

# Plugin and MCP audit

Plugins, hooks, and MCP servers run code on this machine with the user's privileges. Hooks can fire on
every tool call. This skill inventories that code, flags red flags, and gives a verdict per plugin.
**Read-only.** Run every step without asking. This skill reports risk and nothing else. Never disable,
quarantine, delete, or edit a plugin, hook, MCP config, or settings file, even if the user asks within
this skill. Print the recommended commands for the user to run personally.

## 1. Inventory and static scan

```bash
node "${CLAUDE_PLUGIN_ROOT}/skills/plugin-audit/scripts/audit-plugins.js" --cwd "<current project dir>"
```

Add `--json` for the full findings list. The script covers:
- Every installed plugin: its hook commands (event, matcher, command), MCP servers, and scripts, with a risk of HIGH, MED, LOW, or NONE.
- User config: hooks in `~/.claude/settings.json` and `settings.local.json`, files in `~/.claude/hooks/`,
  `mcpServers` in `~/.claude.json` (global and the current project), and `<cwd>/.mcp.json`.
- Marketplaces: `autoUpdate` and unpinned sources.

The script redacts env values, headers, URL queries, and token-shaped strings. Keep it that way:
never print the values from `env` or `headers`, even if you read the raw file.

## 2. Review HIGH and MED by reading the code

For each HIGH or MED plugin, and for user-level findings, Read the cited `file:line` and enough context
to answer these questions. Use `references/red-flags.md` to tell malicious patterns from benign ones.

1. **What does it send, and where?** Is the network destination hardcoded? Is it the plugin's own documented
   service? Is the payload user data, env, or files?
2. **What does it read?** Credential paths and env dumps next to network calls are the exfiltration pattern.
3. **What does it execute?** Fixed commands (`git status`) are fine. Strings built from downloads, decoded
   blobs, or tool input are not.
4. **Does it modify Claude's config or other plugins?** Writes to `~/.claude/settings*.json`, `~/.claude.json`,
   `~/.claude/plugins/**`, or other hooks are persistence or tampering, unless that is the plugin's documented
   purpose and it asks the user first.
5. **Is the code readable?** Minified or obfuscated code in a hook is HIGH until you have reviewed a
   deobfuscated version.

More than ~5 HIGH/MED plugins: dispatch one Explore subagent per plugin in parallel. Give each agent the plugin
root, the cited lines, and the five questions. Each agent returns a verdict and evidence.

**Known false positives: the scanner flags security tools and comments.** The scanner matches text, not behaviour.
- Security plugins contain credential paths, `curl | sh` and `eval` **as detection strings** in their regexes and deny
  lists. This includes **secops-guard itself** (`hooks/guard.js`) and its own `hooks/block-dangerous.js`. They will
  always show HIGH.
- Comments and docstrings also match. Examples are one-line install instructions in an installer header, and a comment that
  explains why a symlink to `~/.ssh/id_rsa` is refused.

For each hit, confirm whether the match is executed code, or a pattern, comment, or string that is never run.
If it is never run, mark it BENIGN and cite the line.

## 3. Verdict and recommendations

```markdown
# Plugin audit (<date>)
| Plugin | Static risk | Verdict | Evidence | Recommendation |
|---|---|---|---|---|
| market/plugin | HIGH | MALICIOUS / SUSPICIOUS / BENIGN | file:line: what it does | remove / pin / keep |

## User hooks and MCP servers
## Marketplaces
## Actions (need user OK)
```

Recommendations, from mildest to strongest:
- **Pin**: in `~/.claude/settings.json` `extraKnownMarketplaces.<name>.source`, set `"ref"` or `"sha"` to the
  reviewed commit (the installed commit is `gitCommitSha` in `~/.claude/plugins/installed_plugins.json`).
- **Disable auto-update**: set `"autoUpdate": false` on the marketplace, so updates arrive only after a review.
- **Pin MCP packages**: `npx -y pkg@X.Y.Z` and `uvx --from pkg==X.Y.Z`. Prefer servers that read secrets
  from env over secrets inlined in `args` or the URL.
- **Disable**: `/plugin disable <plugin>@<marketplace>`, or set `enabledPlugins` to false.
- **Remove**: `/plugin uninstall <plugin>@<marketplace>`. If you find MALICIOUS code: tell the user to rotate
  every credential the hook could read (cloud keys, GitHub/npm tokens, SSH keys), and to check
  `~/.claude/settings.json` and shell profiles for persistence.

Every action above is for the **user** to run. Do not run `/plugin` commands, and do not edit settings or
`~/.claude.json` yourself. The secops-guard guard hook blocks Claude from writing these files anyway.

## Common mistakes

- You trust the risk column without reading the code. The scanner is pattern-based.
  A NONE plugin can still have a malicious MCP binary. A HIGH plugin can be a security tool.
- You print MCP `env` values or tokens from `~/.claude.json` while you investigate.
- You recommend removing a plugin without naming the specific line that justifies it.
