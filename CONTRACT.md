# secops-guard — build contract

Shared contract for every agent working in this repo. Read this first. Do not change it without the orchestrator.

## Goal

A Claude Code plugin for a user who ALWAYS runs in bypass-permissions mode. It must never prompt the user.
It silently lets normal work through, rewrites where it can, and hard-denies only clear risk.

1. Supply-chain gate: no vulnerable, malicious, or too-new (< 7 days) dependency gets installed by Claude.
2. Guard: blocks secret theft, exfiltration, obfuscated execution, persistence, security-tool tampering, and attempts to disable this plugin. Destructive commands (rm -rf, git reset --hard, DROP TABLE …) are handled by `hooks/block-dangerous.js` (ported in), so do NOT duplicate them in `guard.js`.
3. Post-install and session checks that report to Claude.
4. Security-scan skills inspired by usestrix/strix.
5. Machine-level setup (package-manager cooldown configs) plus an installer, so the folder can be copied to another laptop.

## Conventions

- Node.js >= 18, CommonJS, `'use strict';`, **stdlib only** (no npm deps, no package.json deps). Use global `fetch`.
- Every hook file exports its pure functions and only runs `main()` when `require.main === module`.
- Hook IO: read the JSON payload from stdin, write the JSON decision to stdout, and always `exit 0`.
- Regex: no ReDoS. No `.*` chains or adjacent unbounded quantifiers. Use `SEG = [^;|&\n]*` for "rest of segment". Patterns must be non-global.
- Tests: `node:test` + `node:assert` in `plugins/secops-guard/hooks/test/*.test.js`. Network is mocked in unit tests through an injectable `fetchImpl`. Live network tests go in `test/live.test.js` and are skipped unless `SECOPS_LIVE=1`.
- Comments: sparse, explain *why* only.
- Windows + POSIX paths must both work (`os.homedir()`, normalise `\` to `/` before matching).

## Layout

```
secops-guard/                         <- repo root (copy this folder to another laptop)
  .claude-plugin/marketplace.json     <- standalone marketplace: plugins[0].source = "./plugins/secops-guard"
  README.md  RELEASE.md  CONTRACT.md
  plugins/secops-guard/
    .claude-plugin/plugin.json        {name:"secops-guard", version:"0.1.2", description, author:{name:"Prathamesh Kulkarni"}}
    hooks/hooks.json
    hooks/lib/config.js               config + allowlist loading
    hooks/lib/io.js                   readStdin(), emit helpers
    hooks/lib/parse-command.js        shell command -> install intents
    hooks/lib/registries.js           npm / PyPI / crates.io / Docker Hub metadata + version resolution
    hooks/lib/osv.js                  OSV.dev queries + severity normalisation
    hooks/lib/lockfiles.js            lockfile/manifest -> [{ecosystem,name,version}]
    hooks/lib/versions.js             semver + PEP 440 compare + simple range satisfy
    hooks/lib/cache.js                file cache in STATE_DIR (sha256 key, TTL)
    hooks/lib/docker.js               image scanner discovery (grype > trivy > docker scout) + report parsing
    hooks/lib/scan.js                 Side B scanning: trivy fs/image, secret parsing + redaction, dir fingerprint
    hooks/dep-gate.js                 PreToolUse  Bash|PowerShell
    hooks/manifest-gate.js            PreToolUse  Edit|Write|MultiEdit
    hooks/post-install-scan.js        PostToolUse Bash|PowerShell
    hooks/build-gate.js               PreToolUse  Bash|PowerShell  AND  PostToolUse Bash|PowerShell
    hooks/guard.js                    PreToolUse  Bash|PowerShell|Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit
    hooks/block-dangerous.js          PreToolUse  Bash|PowerShell (destructive commands)
    hooks/plugin-integrity.js         SessionStart
    hooks/test/...
    skills/dep-audit/SKILL.md   (+ scripts/audit.js, reuses ../../hooks/lib)
    skills/sast-scan/SKILL.md
    skills/appsec-review/SKILL.md (+ references/*.md - the 15 vuln-class files sast-scan loads)
    skills/plugin-audit/SKILL.md (+ scripts/audit-plugins.js, reuses hooks/plugin-integrity.js)
  setup/
    install.ps1  install.sh           apply machine-level configs (idempotent, backs up, --dry-run default)
    configs/                          npmrc snippet, pnpm, uv.toml, bunfig, yarnrc snippets
    settings.snippet.json             optional permission deny rules for ~/.claude/settings.json
    tools.md                          scanner install commands per OS
```

## State and config

- `STATE_DIR = process.env.SECOPS_STATE_DIR || <home>/.claude/secops-guard` (created lazily).
- `<STATE_DIR>/config.json` (optional, user-edited only. `guard.js` forbids Claude from writing anything under STATE_DIR):
  ```json
  {
    "cooldownDays": 7,
    "packageSeverityBlock": "ANY",
    "lockfileSeverityBlock": "HIGH",
    "imageSeverityBlock": "HIGH",
    "failOpen": false,
    "allow": ["npm:some-pkg", "pypi:some-pkg@1.2.3", "image:nginx:1.27"],
    "allowRegistries": ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "download.pytorch.org", "crates.io", "index.crates.io"]
  }
  ```
  Env overrides: `SECOPS_COOLDOWN_DAYS`, `SECOPS_FAIL_OPEN=1`, `SECOPS_DISABLE=1` (all hooks no-op; user sets this in their own shell only), `SECOPS_INTEGRITY_BUDGET_MS` (default 10000, plugin-integrity only), `SECOPS_GATE_BUDGET_MS` (default 120000, dep-gate only; must stay under the hook timeout in hooks.json), `SECOPS_BUILD_BUDGET_MS` (default 90000, build-gate only; same constraint).
  State dir also holds: `plugin-snapshot.json`, `plugin-integrity-state.json`, `cache/` (registry 1h, OSV 6h, lockfile verdict 24h, image scan 6h) and `cache.key` (0600, HMAC secret authenticating cache entries).
- Severity scale: `LOW < MODERATE < HIGH < CRITICAL`. `MAL-*` OSV ids = `MALICIOUS` (always block). Unknown severity counts as `HIGH`.
- `"ANY"` means any known vuln blocks.
- Cache: `<STATE_DIR>/cache/`. Registry metadata 1h, OSV results 6h, lockfile-scan verdict by lockfile sha256 for 24h.

## Policy (user-approved)

**Explicit package installs** (`npm i foo`, `pip install foo`, `cargo add foo`, `npx foo`, `uvx foo`, …):
1. Resolve the version. If unspecified, a dist-tag, or a range, pick the **newest non-prerelease, non-yanked version published >= cooldownDays ago** that satisfies the range.
   If the user pinned an exact version younger than the cooldown, deny and name the newest old-enough version.
2. OSV-check that exact version. Any MAL means deny. Any vuln at or above `packageSeverityBlock` (default ANY) means deny. The reason lists the ids and the first fixed version, if any.
3. If the package does not exist in the registry, deny ("possibly hallucinated / slopsquat").
4. Otherwise **rewrite the command** so each package is pinned to the checked version (`foo@1.2.3`, `foo==1.2.3`, `foo@=1.2.3` for cargo add, `foo@1.2.3` for npx/uvx `--from foo==1.2.3`), and allow it with `updatedInput`. Pinning avoids a check/install race.
5. Allowlisted entries skip steps 1–3 (they are still pinned if resolvable).

**Lockfile / bare installs** (`npm install`, `npm ci`, `pnpm install`, `pip install -r req.txt`, `uv sync`, `poetry install`, `cargo build|fetch|run|test|install`):
- Parse the relevant lockfiles in the command's cwd. OSV querybatch, then fetch details for hits.
- MAL means deny. Any vuln at or above `lockfileSeverityBlock` (default HIGH) means deny, with a list. Lower severities are allowed, with a summary in `additionalContext`.
- Verdict is cached by lockfile hash, so repeated builds cost nothing.
- No lockfile means allow + additionalContext ("no lockfile — transitive deps unchecked until post-install scan").

**Docker** (`docker pull X`, `docker run X`, `docker create X`, `docker compose up|pull`):
- If `grype`, `trivy`, or `docker scout` is on PATH, scan the image (timeout 90s). CRITICAL/HIGH (`imageSeverityBlock`) means deny.
- No scanner means allow + additionalContext telling Claude to recommend installing grype.
- Floating `:latest` / no tag means additionalContext suggesting a pinned tag or digest (not a deny).

**Builds and publishes — Side B** (`build-gate.js`): PostToolUse after a build (`npm run build`, `vite build`, `poetry build`, `pip wheel`, `python -m build`, `setup.py bdist/sdist`, `cargo build --release`, `cargo publish --dry-run`, `docker build`), PreToolUse before a publish (`docker|podman push`, `npm|pnpm|yarn|bun publish`, `twine upload`, `poetry|hatch|uv publish`, `cargo publish`, `gh release upload`). Scans the artifact with trivy (`fs` for bundles/wheels/`target/release`, `image` for a tag).
- **CVE findings: report only, never block** — on build and on publish alike. `imageSeverityBlock` is the floor for which ids get named, not a gate.
- **Secrets: deny.** PreToolUse `deny` on a publish, PostToolUse `block` on a build. Secret values are NEVER emitted: report `RuleID`, severity, target and `StartLine` only, each passed through `redact()`. Never read `Secrets[].Match` or `Code.Lines` — trivy's own masking is partial and rule-dependent (measured on 0.76.1: a GitHub PAT fully masked, a Slack token masked only in its first segment), so neither field is safe to print.
- No scanner, a scan error, or the budget expiring is **context only, never a deny**.
- An `image:<tag>` allowlist entry skips the scan. Scan results cached 10 min by image tag or by directory fingerprint.

**Network failure** while checking an install means deny with "could not verify; retry", unless `failOpen`.

**Not gated:** commands that only *run* already-installed tools (`npm run`, `npm test`, `pytest`, `cargo check`?). `cargo check|build` reads Cargo.lock, which is a lockfile install, so it is gated with the cache.

## Shared module APIs (implement exactly these names)

```js
// lib/config.js
loadConfig() -> {cooldownDays, packageSeverityBlock, lockfileSeverityBlock, imageSeverityBlock, failOpen, allow:Set<string>, allowRegistries:string[], stateDir}
isAllowed(cfg, ecosystem, name, version?) -> boolean   // matches "eco:name" or "eco:name@version"

// lib/io.js
readStdin() -> Promise<object|null>
preDeny(reason) / preAllowWithInput(updatedInput, context?) / preContext(context) / postBlock(reason) / postContext(context) / sessionMessage(userMsg, claudeContext?)  // each writes JSON to stdout

// lib/parse-command.js
splitSegments(cmd) -> string[]                         // split on ; && || | newline, respect quotes
tokenize(segment) -> string[]                          // shell-ish, quotes, PowerShell-tolerant
parseInstallIntents(cmd) -> Intent[]
// Intent = { kind:'explicit', ecosystem:'npm'|'pypi'|'crates', manager:string, packages:[{name, spec, raw}], segmentIndex, tokenIndexes }
//        | { kind:'lockfile', ecosystem, manager, files?:string[] }     // e.g. pip -r file
//        | { kind:'image', image:string }
rewriteCommand(cmd, pins: Map<raw, pinnedRaw>) -> string  // replaces only the package tokens

// lib/versions.js
compareSemver(a,b), comparePep440(a,b), isPrerelease(eco, v), satisfies(eco, version, spec) -> boolean|null  // null = unsupported spec

// lib/registries.js  (all accept opts {fetchImpl, now})
getPackageVersions(ecosystem, name, opts) -> Promise<null | [{version, publishedAt:Date, yanked:boolean}]>   // null = not found
resolveVersion(ecosystem, name, spec, cooldownDays, opts) -> Promise<{version, publishedAt} | {error:'not_found'|'too_new'|'no_match', detail}>

// lib/osv.js
queryPackages([{ecosystem,name,version}], opts) -> Promise<Map<key, Vuln[]>>   // key = `${eco}:${name}@${version}`
// Vuln = {id, aliases, summary, severity:'LOW'|'MODERATE'|'HIGH'|'CRITICAL'|'MALICIOUS', fixed:string|null}
atLeast(severity, threshold) -> boolean   // threshold 'ANY' -> always true

// lib/lockfiles.js
findLockfiles(cwd, ecosystem?) -> string[]
parseLockfile(path) -> [{ecosystem,name,version}]   // package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lock (json-ish text), requirements*.txt (pinned == lines), uv.lock, poetry.lock, Pipfile.lock, Cargo.lock

// lib/cache.js
cached(key, ttlMs, fn) -> Promise<value>

// lib/scan.js  (re-exports everything from lib/docker.js)
findTrivy(opts?) -> {name:'trivy', bin} | null        // PATH, then winget Packages/AquaSecurity.Trivy*, then brew/usr paths
findScanner(opts?) -> findTrivy() || docker.findScanner()
scanFs(target, {scanners, skipDirs, timeoutMs}) -> {scanner,vulns,secrets} | null   // null = scanner is not trivy
scanImage(image, {timeoutMs}) -> {scanner,vulns,secrets} | null                     // secrets:[] for grype/docker-scout
parseSecrets(trivyJson) -> [{rule, severity, title, target, line}]                  // never Match / Code.Lines
redact(s) -> string        // any run of 16+ [A-Za-z0-9_\-+/=] -> '***', capped at 120 chars
fingerprintDir(target, skipDirs?, limit=5000) -> string   // "<abs>|<newest mtime>|<file count>"
```

OSV ecosystems: `npm`, `PyPI`, `crates.io`. Internal ecosystem ids: `npm`, `pypi`, `crates`.

## plugin-integrity.js exports (used by the plugin-audit skill)

```js
snapshotPlugins(claudeHome = <home>/.claude) -> {takenAt, plugins: {[pluginKey]: {root, files: {[relPath]: sha256}, hooks: object|null, mcp: object|null}}}
// pluginKey = "<marketplace>/<plugin>". Hash: hooks/**, .mcp.json, scripts/**, bin/**, *.js|*.py|*.sh|*.ps1|*.cmd, plugin.json, settings.json. Skip node_modules, .git, files > 2 MB.
diffSnapshots(prev, next) -> {added:[pluginKey], removed:[pluginKey], changed:[{plugin, files:[relPath]}]}
riskyMarketplaces(settings) -> [{name, repo, autoUpdate:true}]   // reads extraKnownMarketplaces
// main(): snapshot -> diff against <STATE_DIR>/plugin-snapshot.json -> save -> if changes or risky: sessionMessage(user summary, Claude context suggesting /secops-guard:plugin-audit)
```

## Verified Claude Code hook semantics (v2.1.310, docs 2026-10)

- Hook `deny` blocks even in bypassPermissions. `settings.json` deny rules are enforced in bypass too. `ask` behavior in bypass is unverified, so **never use ask**.
- `updatedInput` REPLACES the whole tool_input. Always send the full object (`{...tool_input, command: newCmd}`), paired with `permissionDecision: "allow"`. Only `dep-gate.js` may return `updatedInput` for Bash/PowerShell.
- Parallel hooks: deny > ask > allow.
- Hook crash or timeout means fail-open, except `dep-gate.js`, which is configured `onFailure: "block"`. So dep-gate must catch ALL its own errors and return allow quickly for non-install commands (target < 50 ms, no network).
- PostToolUse cannot undo. Use `{"decision":"block","reason":…}` to push feedback to Claude, plus `hookSpecificOutput.additionalContext`.
- SessionStart: top-level `systemMessage` is shown to the user. `hookSpecificOutput.additionalContext` goes to Claude.
- Hook env: `CLAUDE_PLUGIN_ROOT`, `CLAUDE_PLUGIN_DATA`, `CLAUDE_PROJECT_DIR`. Payload has `cwd`, `tool_name`, `tool_input`, `tool_response` (Post).
- In SKILL.md bodies `${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_SKILL_DIR}` are substituted as text. They are NOT env vars inside Bash.
- Plugins cannot ship permission rules. `setup/settings.snippet.json` is merged by the installer. `Write(path)` deny rules never match, so use `Edit(...)`/`Read(...)` rules + guard.js.
- `hooks/hooks.json` is already written by the orchestrator. Do not edit it.

## Hooks output rules

- PreToolUse deny: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"secops-guard: …"}}`
- Every reason starts with `secops-guard:` and tells Claude what to do instead (pin X, choose Y, ask the user to add an allowlist entry in `~/.claude/secops-guard/config.json`).
- Never print anything else to stdout. Debug output goes to stderr only.
