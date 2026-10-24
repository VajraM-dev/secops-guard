# Releasing secops-guard

## 1. Validate

```bash
claude plugin validate ./plugins/secops-guard
node --test plugins/secops-guard/hooks/test/
node setup/verify.js
```

`verify.js` must end with 0 failures. SKIPs are fine - they are the support matrix for
whatever machine you are on.

## 2. Test locally from a path

```bash
claude plugin marketplace add "$PWD"            # absolute path to this repo root
claude plugin install secops-guard@secops-guard
# restart Claude Code, then:
claude plugin list
```

The repo root carries `.claude-plugin/marketplace.json`, whose single entry points at
`./plugins/secops-guard`, so the repo is both the marketplace and the plugin source.

To iterate: edit files in place, restart Claude Code. To start clean:

```bash
claude plugin uninstall secops-guard@secops-guard
claude plugin marketplace remove secops-guard
```

Check the hooks actually fire before you ship. In a scratch directory:

```bash
# should be rewritten to a pinned, cooldown-passing version, not denied
claude -p "install the npm package left-pad"
```

## 3. Publish to GitHub

```bash
git init                       # if this is not already a repo
git add -A
git commit -m "secops-guard 0.1.0"
git remote add origin git@github.com:VajraM-dev/secops-guard.git
git push -u origin main
git tag v0.1.0 && git push --tags
```

Then anyone installs it with:

```bash
claude plugin marketplace add VajraM-dev/secops-guard
claude plugin install secops-guard@secops-guard
```

Do **not** enable `autoUpdate` on the marketplace entry for a security plugin. An
auto-updating marketplace is a remote-code-execution channel into every session -
`plugin-integrity.js` flags exactly that pattern in other people's plugins, so do not
be that pattern. Update deliberately with `claude plugin update`.

## 4. Enterprise rollout (optional)

Permission rules and hooks in `~/.claude/settings.json` can be removed by the user.
`managed-settings.json` cannot - it is root/Administrator-owned and overrides user
settings.

| Platform | Path |
|---|---|
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux | `/etc/claude-code/managed-settings.json` |

```json
{
  "extraKnownMarketplaces": {
    "secops-guard": {
      "source": { "source": "github", "repo": "VajraM-dev/secops-guard" }
    }
  },
  "enabledPlugins": {
    "secops-guard@secops-guard": true
  },
  "allowManagedHooksOnly": true,
  "permissions": {
    "deny": [ "...copy the array from setup/settings.snippet.json..." ]
  }
}
```

`allowManagedHooksOnly: true` means **only** hooks defined in managed settings run -
user and project hooks are ignored entirely. That is the point (a user cannot strip the
guard) and also the catch: it disables every other hook those users rely on, unless you
list those in managed settings too. Roll it out to a pilot group first.

The installer never writes any of this. Deploy it with your existing MDM / Intune /
Jamf / Ansible flow.

## 5. Version bump checklist

1. `plugins/secops-guard/.claude-plugin/plugin.json` - bump `version` (semver).
2. Update the dates and any changed version requirements in `README.md`'s
   "What needs which version" table and in `setup/configs/*` headers - the research
   behind those numbers goes stale faster than the code does. Each release, re-check:
   npm `min-release-age` (11.10.0), pnpm `minimumReleaseAge` (10.16.0), uv
   `exclude-newer` relative durations (0.9.17), pip `--uploaded-prior-to` (26.1),
   cargo `global-min-publish-age` (Rust 1.100, due 2026-11-12), yarn
   `npmMinimalAgeGate` (4.10.0, **unit still unverified**), bun (1.3).
3. Re-check `setup/tools.md`: the Trivy malware advisory, the gitleaks maintenance note,
   and the two unverified winget IDs (`Gitleaks.Gitleaks`, `AquaSecurity.Trivy`).
4. `node --test plugins/secops-guard/hooks/test/` and `claude plugin validate`.
5. Dry-run both installers on a clean profile and read the diff:
   `pwsh -File setup\install.ps1` and `bash setup/install.sh`.
6. `node setup/verify.js` - 0 failures.
7. Commit, tag `vX.Y.Z`, push tags.
