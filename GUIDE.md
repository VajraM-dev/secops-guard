# secops-guard — portable setup guide

This guide assumes you have this folder and nothing else. It covers what the folder is,
what is in it, how to install it on a new machine, how to configure it, and what it does
not protect you from.

## 1. What this is

secops-guard is a set of Claude Code hooks and skills for people who run Claude Code
with permissions bypassed. In that mode an agent installs packages and reads files as
you, at machine speed, from registries anyone can publish to. A `postinstall` script runs
with your privileges and can read your SSH keys, `~/.aws/credentials`, your npm token and
your GitHub CLI token. secops-guard sits between an install intent and that outcome: it
resolves each requested package to a version that is old enough and clean in OSV, rewrites
the command to pin that version, and hard-denies clear risk. It raises the cost of an
accident and of a commodity supply-chain attack.

**It is a guardrail, not a sandbox.** Everything here is heuristics over text. Anything
running as you can turn it off, because you can turn it off. A determined attacker with
code execution works around it. Read section 9 before you trust it with anything.

Hooks work in bypass mode. Bypassing permissions bypasses the prompts, not the hooks. A
PreToolUse hook that returns `permissionDecision: "deny"` blocks the call outright, and
`permissions.deny` rules in `settings.json` are enforced in bypass too.

## 2. What is in the folder

| Path | Holds | Needed? |
|---|---|---|
| `plugins/secops-guard/hooks/` | The seven hook scripts, `hooks.json`, and `lib/` (shared registry, OSV, lockfile, scan, parsing code). | **Required.** This is the product. |
| `plugins/secops-guard/skills/` | The four skills: `dep-audit`, `sast-scan`, `appsec-review`, `plugin-audit`. | **Required.** This is the product. |
| `plugins/secops-guard/hooks/test/` | 727-test Node suite plus lockfile fixtures. | Only for development. |
| `setup/` | `install.ps1`, `install.sh`, `merge-settings.js`, `verify.js`, `settings.snippet.json`, `configs/`, `tools.md`. | Only for the installer route and for `verify.js`. |
| `.claude-plugin/` | `marketplace.json` — a standalone marketplace manifest. | Only for publishing as a plugin. |
| `README.md`, `RELEASE.md`, `CONTRACT.md` | Threat-model background, release notes, internal build contract. | Reference only. |
| `package.json` | Test runner entry point (`npm test`). | Only for development. |

The hooks have no npm dependencies. They run on Node with the standard library only.

## 3. The eight hooks

Eight scripts, nine wired entries: `build-gate.js` binds to both `PreToolUse` and
`PostToolUse`. Matchers and timeouts below are read from
`plugins/secops-guard/hooks/hooks.json`.

| File | Event / matcher | Timeout | What it does |
|---|---|---|---|
| `guard.js` | PreToolUse — `Bash\|PowerShell\|Read\|Grep\|Glob\|Edit\|Write\|MultiEdit\|NotebookEdit` | 10s | Denies reads of credential stores (everything under `~/.ssh` except `*.pub`, `known_hosts`, `config`, `authorized_keys`; `~/.aws/credentials`, gcloud, `~/.npmrc`, `~/.pypirc`, netrc, `~/.git-credentials`, GitHub CLI token, crates.io token, browser login stores), uploads to paste/callback hosts, obfuscated execution (`curl \| sh`, base64-decoded eval), persistence (cron, autorun, shell profiles), writes to package-manager configs, and any edit to secops-guard's own installed files or state directory. |
| `dep-gate.js` | PreToolUse — `Bash\|PowerShell` | 150s, `onFailure: "block"` | Parses install intents out of the command, resolves each package to the newest non-prerelease version published at least `cooldownDays` ago, OSV-checks that exact version, and **rewrites the command** with the version pinned (plus `--save-exact` / `--exact` for npm, pnpm, yarn and bun, so the manifest records the exact version and not a `^` range). Denies on malware, on a vulnerability at or above the threshold, on a package that does not exist in the registry, and on a user-pinned version that is too new. For a bare `npm install` / `uv sync` / `cargo build` it scans the lockfile instead, caching the verdict by lockfile hash. |
| `manifest-gate.js` | PreToolUse — `Edit\|Write\|MultiEdit` | 60s | The same checks when a dependency is added by editing `package.json`, `pyproject.toml` or `Cargo.toml` directly rather than by running a command. |
| `block-dangerous.js` | PreToolUse — `Bash\|PowerShell` | 10s | Denies destructive commands: `rm -rf`, `git reset --hard`, force-pushes to protected branches, `DROP TABLE`, `mkfs`, `dd` and similar. |
| `redact-env.js` | PreToolUse — `Read\|Grep\|Bash\|PowerShell` | 10s | Blocks shell access to `.env` files. A Read of one is denied but returns the keys with values replaced by `<REDACTED>`, so Claude still sees variable names. |
| `post-install-scan.js` | PostToolUse — `Bash\|PowerShell` | 120s | After an install has run, scans the resulting lockfiles and any built Docker image, and reports findings to Claude. Feedback, not a gate. |
| `build-gate.js` | PreToolUse — `Bash\|PowerShell`, **and** PostToolUse — `Bash\|PowerShell` | 120s each | Side B. After a build, and before a publish, scans the artifact for CVEs and for baked-in secrets. Reports CVEs; denies on a secret. See below. |
| `plugin-integrity.js` | SessionStart | 60s | Hashes every installed plugin's hooks, scripts and MCP config, diffs against the last snapshot, and reports added, removed or changed plugins plus any marketplace with `autoUpdate: true`. |

`dep-gate.js` is the only hook configured `onFailure: "block"`. Every other hook fails
open: if it crashes or times out, the tool call proceeds. `dep-gate.js` is the layer that
decides whether a package is safe to install, so a crashed or timed-out run must not be
read as approval. The cost is that a dep-gate failure blocks the install until it is
fixed or until `SECOPS_DISABLE=1` is set.

### Side B — `build-gate.js`

The dependency hooks gate what gets **installed**. Side B gates what gets **built and
shipped**: Docker images, React/Vite/Next bundles in `dist/`, Python wheels and sdists,
Rust release binaries.

It exists because Side A cannot see what ends up in the artifact. Transitive
dependencies pulled in at build time, OS packages inherited from a base image, drift
between install day and build day — none of those passed through `dep-gate.js`. And the
main point: **secrets baked in at build time.** Three concrete mechanisms:

- `REACT_APP_*`, `VITE_*` and `NEXT_PUBLIC_*` environment variables are inlined into the
  JS bundle at build time **by design**. There is no bug to fix; the bundler is doing its
  job. Whatever is in them ships to every browser that loads the page.
- No `.dockerignore` means `docker build` copies `.env` and `.git` into the build
  context, and usually straight into an image layer.
- A secret passed as a build arg stays in `docker history` for the life of the image.

**The policy is deliberately asymmetric.**

| Finding | On build (PostToolUse) | On publish (PreToolUse) |
|---|---|---|
| CVE | Report only | Report only |
| Secret | Block, with a "do not publish this" reason | **Deny** |

A CVE in a base image is common, often unfixable that minute, and blocking on it would
make the tool unusable — so it is reported and never blocks. A secret in a shipped
artifact cannot be taken back: a pushed layer or a published package is public from that
moment. It is cheap to fix before it ships and impossible to fix after.

Builds that are detected: an `npm`/`pnpm`/`yarn`/`bun` script named `build` or
`build:*`, a bare `vite|next|astro|nuxt|remix|rollup|webpack|esbuild|parcel|tsup|ng
build`, `poetry|hatch|uv build`, `pip wheel`, `python -m build`, `setup.py bdist/sdist`,
`cargo build --release`, `cargo publish --dry-run`, and `docker build`. Publishes:
`docker|podman push`, `npm|pnpm|yarn|bun publish`, `twine upload`, `poetry|hatch|uv
publish`, `cargo publish`, `gh release upload`.

**Nothing produces a deny except a secret.** No scanner installed, a scanner that errors,
or the scan budget expiring (`SECOPS_BUILD_BUDGET_MS`, default 90000 ms) all produce
context for Claude and let the call through. A finding you never got is not a finding,
and a slow scan must not block a publish that a CVE would not have blocked either.

**Secret values are never printed.** The report carries rule id, severity, file and line,
and nothing else. A deny reason goes into Claude's context and into the transcript, so
echoing the secret would copy it into one more place — exactly the leak the hook exists to
prevent. Everything that does get printed is run through a redactor that replaces any run
of 16+ token characters with `***`.

> A measured finding behind that rule: **trivy's own masking of a matched secret is
> partial, and how partial depends on the rule.** Observed with trivy 0.76.1 on this
> machine: a GitHub PAT came back fully masked, but a Slack token came back as
> `slack = *****************-1234567890123-abcdefghijklmnopqrstuvwx` — only the first
> segment masked, most of the token in clear. So `Secrets[].Match` and `Code.Lines`
> cannot be treated as safe to print. `lib/scan.js` never reads either; it takes only
> `RuleID`, `Severity`, `Title`, `StartLine` and the target path. Reproduce it with
> `trivy fs --scanners secret --format json` over a file holding a test token.

### Scanners

All optional. Side B does nothing without trivy, and says so rather than staying quiet.

| Tool | Version here | For | Install |
|---|---|---|---|
| **trivy** | v0.76.1 | The Side B engine: image CVEs, filesystem CVEs, secrets, IaC misconfig. The only one of the three image scanners that reports secrets, and the only one that can scan a filesystem at all. | `winget install AquaSecurity.Trivy` / `brew install trivy` / https://trivy.dev/latest/getting-started/installation/ |
| **semgrep** | v1.182.1 | Backs the `sast-scan` skill. Runs natively on Windows since the Fall 2025 release. Without it, `sast-scan` falls back to grep. | `uv tool install semgrep` (all three platforms) |

Neither lands on the `PATH` a fresh shell or a hook process inherits. winget puts trivy
in `%LOCALAPPDATA%\Microsoft\WinGet\Packages\AquaSecurity.Trivy_*\`, and `uv tool
install` puts semgrep in `~/.local/bin`. `lib/scan.js` and `setup/verify.js` both look in
those places before calling a tool absent, so you do not have to fix your `PATH`.

Deliberately not installed, and not needed:

| Tool | Why not |
|---|---|
| `grype`, `gitleaks` | trivy covers both jobs — image CVEs and secrets. |
| `osv-scanner` | `dep-gate.js` queries the OSV API directly. |
| `syft` | Only if you need an SBOM. |
| `guarddog` | Docker-only on Windows, and marginal once `dep-gate.js` blocks everything OSV knows about. |

**Trivy version safety.** v0.69.4, v0.69.5 and v0.69.6 were malicious releases
(CVE-2026-33634, March 2026 — the binaries were replaced and the mutable tags on
`aquasecurity/trivy-action` were force-pushed). v0.76.1 is well past that window and is
itself a security release. Do **not** pin to an old version to avoid the bad ones: an
outdated trivy may fail to pull a current vulnerability database and will then silently
find nothing, which is worse than not scanning. In CI, keep pinning
`aquasecurity/trivy-action` **by commit SHA**, never by tag — that advice is unchanged.

## 4. The four skills

Invocation depends on the install route. As a plugin: `/secops-guard:<name>`. As plain
skills copied into `~/.claude/skills/`: `/<name>`. Claude also invokes them on its own
when a request matches the trigger phrases below.

| Skill | What it does | Trigger phrases |
|---|---|---|
| `dep-audit` | Audits a repo's dependencies: lockfile CVEs, SBOM, Dockerfile base images, GitHub Actions pinning. Covers npm, pnpm, yarn, bun, pip/uv/poetry/pipenv and Cargo. | "audit dependencies", "check for vulnerable packages", "CVE scan", "SCA", "supply chain check", "SBOM review", "is this package safe", "are my deps OK". |
| `sast-scan` | SAST and secret scanning over a repo, directory or the current diff, with per-finding triage. Uses semgrep / bandit / checkov / gitleaks when present. | "security scan", "SAST", "scan code for vulnerabilities", "find secrets", "hardcoded keys/tokens/passwords", "IaC scan" (Terraform, Kubernetes, Dockerfile, CloudFormation), "security review of a repo / diff / PR". |
| `appsec-review` | Secure code review of your own codebase, with `file:line` evidence and a minimal fix diff. Triages a scanner finding into TRUE / FALSE / NEEDS-CONTEXT. | "security review", "review this code for vulnerabilities", "is this endpoint safe", "secure code review", "threat model", "check authz", "harden this", "did I introduce a vuln", "review my PR for security". |
| `plugin-audit` | Inventories installed Claude Code plugins, their hooks and their MCP servers, flags red flags, and gives a verdict per plugin. | "audit my Claude Code plugins", "are my claude plugins safe", "check my hooks", "MCP server audit". Also prompted by a `plugin-integrity.js` SessionStart message. |

## 5. Install on a new machine

Both routes end in the same place: hook entries and deny rules in **`~/.claude/settings.json`**.

> A project-level `.claude/settings.json` install is **silently ignored**. An unapproved
> project hook never executes and nothing tells you. Dropping this repo into a project
> folder gives you a security tool that does not run. `claude -p --settings <file>` does
> not load hooks either. User scope or plugin scope only.

> Pick **one** route. With both the plain hooks and the plugin installed, every hook runs
> twice: two copies of each deny, two pin messages, and twice the registry lookups. Moving
> to the plugin? Remove the `~/.claude/hooks/secops-guard/` entries from
> `~/.claude/settings.json` and delete that folder, outside Claude Code (guard.js denies it
> from inside).

### Route A — plain hooks (what is running on the original machine)

Copy the hooks and skills into your Claude home, then wire them up by hand.

```bash
mkdir -p ~/.claude/hooks/secops-guard
cp -r ~/secops-guard/plugins/secops-guard/hooks/* ~/.claude/hooks/secops-guard/
cp -r ~/secops-guard/plugins/secops-guard/skills/* ~/.claude/skills/
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\hooks\secops-guard"
Copy-Item -Recurse -Force "$env:USERPROFILE\secops-guard\plugins\secops-guard\hooks\*" "$env:USERPROFILE\.claude\hooks\secops-guard\"
Copy-Item -Recurse -Force "$env:USERPROFILE\secops-guard\plugins\secops-guard\skills\*" "$env:USERPROFILE\.claude\skills\"
```

Then add eight hook entries to `~/.claude/settings.json` — seven scripts, with
`build-gate.js` wired twice, once under `PreToolUse` and once under `PostToolUse`. Use
the events, matchers,
timeouts and `onFailure` from `plugins/secops-guard/hooks/hooks.json` (section 3 above),
but replace `${CLAUDE_PLUGIN_ROOT}` with an **absolute path**.

**A literal `$HOME` or `~` in a hook `args` entry does not work.** Claude Code does not
expand it, Node is handed the literal string, the hook fails to start, and `dep-gate.js`
with `onFailure: "block"` then blocks every Bash call. Write the full path out.

One entry, as it looks on a Windows machine:

```json
{
  "matcher": "Bash|PowerShell",
  "hooks": [
    {
      "type": "command",
      "command": "node",
      "args": ["C:/Users/YOURNAME/.claude/hooks/secops-guard/dep-gate.js"],
      "timeout": 150,
      "onFailure": "block"
    }
  ]
}
```

Finally merge the 33 deny rules from `setup/settings.snippet.json` into
`permissions.deny` in the same file. They are the backstop for when hooks are disabled,
crash or time out. Skipping them leaves the hooks as the only layer.

### Route B — the installer

Dry run is the **default**: it prints a per-file diff and writes nothing.

```powershell
pwsh -File setup\install.ps1            # dry run
pwsh -File setup\install.ps1 -Apply     # write
```

```bash
bash setup/install.sh                   # dry run
bash setup/install.sh --apply           # write
```

| Flag (PowerShell / bash) | Effect |
|---|---|
| *(none)* | Dry run. Prints every change and exits. |
| `-Apply` / `--apply` | Write the changes. |
| `-CooldownDays <n>` / `--cooldown-days <n>` | Default 7. Recomputed per manager: days for npm, minutes for pnpm and yarn, seconds for bun. |
| `-SkipIgnoreScripts` / `--skip-ignore-scripts` | Do not set `ignore-scripts=true` in `.npmrc`. |
| `-NoPluginInstall` / `--no-plugin-install` | Print the `claude plugin` commands instead of running them. |
| `-NoDenyRules` / `--no-deny-rules` | Skip the 33 permission deny rules. Everything else still installs. The rules are on by default; this is the supported way to decline them. |
| `-Uninstall` / `--uninstall` | Remove only the keys the installer added, leaving the rest of each file untouched. Prints the restore command for each backup. |
| `-RestoreBackups` / `--restore-backups` | Use with `-Uninstall`: replace each file with its **oldest** backup instead. A full rollback, but it also discards every edit you made to those files since. |
| `-Quiet` / `--quiet` | Summary only. |

The installer never needs admin, never touches `managed-settings.json`, backs up every
file it writes to `<file>.secops-bak-<timestamp>`, and is idempotent.

It also writes the package-manager cooldown configs in `setup/configs/` — `.npmrc`,
pnpm's `config.yaml`, `uv.toml`, `pip.ini`, Cargo's `config.toml`. That layer applies to
every install on the machine, including ones you type yourself with no agent involved.
Keys your tool version is too old to accept are skipped, not written (see section 10).

### Verify, either route

1. **Restart Claude Code.** Hooks and permission rules load at startup.
2. Run the self-check:

```bash
node setup/verify.js
```

Every row should be `PASS` or `SKIP`, and the last line must read `ENFORCEMENT: ACTIVE`.
`INACTIVE` means nothing is being blocked. On the original machine this prints
`33 passed, 11 skipped, 0 failed` — the skips are optional scanners and the
package-manager cooldown keys the installed tool versions are too old to accept.

`verify.js` recognises both install shapes — a plugin, or plain hooks wired into
`settings.json` — reports how many hook entries it found and which, checks that the
installed copy still matches this repo, and finds trivy at the winget path and semgrep
in `~/.local/bin` rather than calling them absent.

## 6. Configuration

`~/.claude/secops-guard/config.json`. Optional — the defaults apply without it. Defaults
below are from `plugins/secops-guard/hooks/lib/config.js`.

```json
{
  "cooldownDays": 7,
  "packageSeverityBlock": "ANY",
  "lockfileSeverityBlock": "HIGH",
  "imageSeverityBlock": "HIGH",
  "failOpen": false,
  "allow": [],
  "allowRegistries": ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "download.pytorch.org", "crates.io", "index.crates.io"]
}
```

| Key | Default | Effect |
|---|---|---|
| `cooldownDays` | `7` | A package version younger than this is not installed. An explicit install resolves down to the newest version that is old enough; an exact pin that is too new is denied, naming the version to use instead. |
| `packageSeverityBlock` | `"ANY"` | Severity threshold for an explicitly named package. `"ANY"` means any known vulnerability blocks. Scale: `LOW < MODERATE < HIGH < CRITICAL`. |
| `lockfileSeverityBlock` | `"HIGH"` | Threshold for a bare `npm install` / `uv sync` / `cargo build`, where the lockfile is scanned. Below the threshold is allowed with a summary passed to Claude. |
| `imageSeverityBlock` | `"HIGH"` | Threshold for a Docker image, scanned with grype / trivy / docker scout if one is on PATH. No scanner means allowed with a note. Side B reuses it as the floor for which CVEs it names in its report, but never blocks on them. |
| `failOpen` | `false` | What to do when OSV or a registry is unreachable. `false` denies with "could not verify; retry". Set `true` only if you work offline and accept the gap. |
| `allow` | `[]` | The allowlist escape hatch. See below. |
| `allowRegistries` | the six hosts above | Registry hosts considered normal. A fetch from anywhere else is denied as unverifiable. |

A malformed `config.json` is ignored with a warning on stderr; the hooks keep running on
the defaults. An `MAL-*` OSV id is always `MALICIOUS` and always blocks, whatever the
thresholds say. Unknown severity counts as `HIGH`.

Per-shell environment overrides: `SECOPS_COOLDOWN_DAYS`, `SECOPS_FAIL_OPEN=1`,
`SECOPS_DISABLE=1`, `SECOPS_STATE_DIR`, `SECOPS_BUILD_BUDGET_MS` (Side B scan budget,
default 90000; keep it under `build-gate.js`'s 120s hook timeout).

An `image:<tag>` allowlist entry also skips the Side B scan of that image.

### The `allow` allowlist

When a block is wrong — an internal package, a CVE that does not apply, a version you
need today — add an entry. The format is `<ecosystem>:<name>` for any version, or
`<ecosystem>:<name>@<version>` for one exact version. Ecosystems: `npm`, `pypi`,
`crates`, `image`.

```json
{
  "allow": [
    "npm:@acme/internal-ui",
    "pypi:torch@2.9.0",
    "crates:my-fork",
    "image:nginx:1.27"
  ]
}
```

An allowlisted package skips the cooldown, the OSV check and the registry-existence
check. It is still pinned to a resolvable version.

**Claude cannot create or edit this file.** `guard.js` denies any write under
`~/.claude/secops-guard/`, and the deny rule `Edit(~/.claude/secops-guard/**)` backs that
up. Create and edit it yourself, in your own editor, outside Claude Code. This is
deliberate: an agent that can add an entry to its own allowlist does not have an
allowlist. If you ask Claude to add one, it will be denied, and the deny message tells
you to do it yourself.

## 7. Day to day

Most of the time you see nothing. Three things do surface.

**A deny.** The tool call does not run and Claude is handed a reason with a suggested
fix. A real one, from asking Claude to read `~/.npmrc`:

```
PreToolUse:Bash hook error: secops-guard: reads the npm auth token file (~/.npmrc).
Credential stores are off-limits to the agent. Ask the user for the value, or read the
file yourself outside Claude Code.
```

A cooldown deny reads:

```
secops-guard: left-pad@1.4.0 was published less than 7 days ago (supply-chain cooldown).
Use left-pad@1.3.0 instead (newest version old enough). If the user needs this exact
version, ask them to add "npm:left-pad@1.4.0" to "allow" in
~/.claude/secops-guard/config.json.
```

**A silent pin.** The common case is not a deny. `dep-gate.js` rewrites the command with
a checked version pinned and lets it through via `updatedInput`, adding one line of
context for Claude: `secops-guard: pinned express -> express@4.21.2 (versions checked
against cooldown and OSV).` Nothing interrupts you.

**A SessionStart message.** When `plugin-integrity.js` sees a plugin's hooks, scripts or
MCP config change since the last session, or a marketplace with `autoUpdate: true`, it
reports what changed and recommends the `plugin-audit` skill. On a first run it records a
baseline and says so.

## 8. Turning it off

In **your own shell**, before launching Claude Code:

```powershell
$env:SECOPS_DISABLE = "1"; claude
```

```bash
SECOPS_DISABLE=1 claude
```

Every hook becomes a no-op for that session. Do not put this in the `env` block of
`settings.json` — that disables it permanently and silently, which is the failure mode
the tool exists to prevent.

To remove it, edit `~/.claude/settings.json` yourself outside Claude Code, or run the
installer with `-Uninstall -Apply` / `--uninstall --apply`.

`guard.js` refuses to let Claude turn the guard off or edit its own installed files: it
denies `SECOPS_DISABLE=` in a command, `claude plugin disable/uninstall secops-guard`,
`disableAllHooks`, and writes to `~/.claude/hooks/secops-guard/**`, the plugin install
paths, and the state directory. A consequence worth knowing: **after you edit a hook in
this repo, Claude cannot copy it into place for you.** Run the copy command from section
5 yourself, outside Claude Code, then re-run `node setup/verify.js`.

## 9. Known limits

Read these before trusting it.

- **A guardrail, not a sandbox.** Heuristics over text. It raises the cost of an accident
  and of a commodity attack; it does not contain a targeted one.
- **You can turn it off, so anything running as you can too.** In bypass mode the agent
  could in principle edit `settings.json` and remove the hooks. `plugin-integrity.js`
  reports that at the next session start, which is detection, not prevention. For real
  enforcement use `managed-settings.json` with `allowManagedHooksOnly` — see `RELEASE.md`.
- **Exfiltration of ordinary project files to an arbitrary host is not caught.** This is
  a deliberate gap. Posting a build artifact or a JSON body to an API is ordinary
  development; denying it on shape alone costs more than it saves. Only two cases are
  denied: the file being sent is a credential store, or the destination is a throwaway
  paste/callback service, a Discord webhook, the Telegram bot API, or a raw `/dev/tcp`
  socket.
- **PostToolUse cannot undo anything.** By the time `post-install-scan.js` runs, the
  `postinstall` script has already run as you. It reports; it does not roll back.
- **No transitive protection before the fact.** Without a lockfile, `dep-gate.js` sees
  only the package you named; its dependencies are checked after installation. With a
  lockfile, the whole tree is checked first.
- **A bare `pip install x` gets no transitive post-scan either.** `post-install-scan.js`
  scans lockfiles it can find in the install directory. A Python project with no
  `uv.lock`, `poetry.lock` or `Pipfile.lock` leaves nothing for it to read, so the
  dependencies that install pulls in are never checked. `requirements.txt` is read only
  for exact `name==version` lines, and `-r` includes are not followed.
- **Side B does nothing without trivy.** grype and docker-scout cannot scan a filesystem,
  so on a machine with only those installed every bundle, wheel and release-binary scan
  returns nothing and the artifact is accepted unchecked. Image CVE scanning still works
  through them; secret detection does not, in any form. `build-gate.js` says so in
  context rather than failing quietly, but it says it once per call, not loudly.
- **The `.dockerignore` check looks at the wrong directory for an out-of-tree build
  context.** It reads `payload.cwd`, not the build-context argument, so
  `docker build -t app ./sub` checks the `.dockerignore` of the current directory and
  not of `./sub`. It under-warns; it does not over-warn.
- **`gh release upload dist/*` with an unexpanded glob scans nothing.** Side B resolves
  the literal asset paths off the command line and skips the ones that do not exist on
  disk. A glob the shell did not expand is one of those, so the upload goes through
  unscanned. Pass real filenames if you want the check. At most 5 assets are scanned per
  release, because each one is a separate scanner process.
- **`cargo build` without `--release` is not treated as a build.** Only
  `cargo build --release` and `cargo publish --dry-run` are. A debug binary is not
  scanned.
- **CVEs in a shipped artifact are reported, never blocked** — on build and on publish
  alike. That is the chosen policy, not an oversight, but it means Side B will hand you a
  list of criticals in your base image and still let the push run.
- **Heredoc bodies are not inspected.** A heredoc body is data the shell never executes,
  so it is stripped before matching — except when it is fed to an interpreter, which is
  inspected.
- **`echo '...' | tee <settings file>` is allowed where the `>` form is denied.** The
  `tee` case is covered only for shell startup files piped from a fetch or decode command.
- **Destructive commands are `block-dangerous.js`'s job, not `guard.js`'s.** It catches
  `rm -rf /`, `git reset --hard`, `DROP TABLE`, `mkfs`, `dd` and force-pushes to protected
  branches. Like the other hooks it is pattern matching over the command text, so a
  sufficiently indirect command gets past it.
- **Cooldowns do not catch slow burns.** The malicious `faster_log` crate sat on crates.io
  for four months. A cooldown catches the hours-to-days attacks, which is nearly all of
  them; OSV catches the rest, later.
- **Network checks need the network.** With `failOpen: false` (the default) an install is
  denied when OSV is unreachable. That is the safe choice and it will annoy you on a plane.
- **`ignore-scripts=true` breaks native addons.** esbuild, sharp and friends need
  `npm rebuild <pkg> --foreground-scripts` afterwards. Opt out with `-SkipIgnoreScripts`.
- **Hooks fail open** on crash or timeout, except `dep-gate.js`, which blocks.
- **Uninstall deletes the keys it added rather than restoring your previous values.** If
  you had `ignore-scripts=false` before, uninstall leaves the key absent, not `false`. The
  backup holds your original file; add `-RestoreBackups` for a full rollback.
- **A private key with a non-standard filename is covered by the hook, not by the
  permission rules.** A permission glob cannot express "everything in `~/.ssh` except
  `*.pub`", so the deny rules name only `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`,
  `*.pem` and `*.key`. `guard.js` closes the gap by inverting the match: everything
  directly under `~/.ssh` is secret material except `*.pub`, `known_hosts`, `config` and
  `authorized_keys`. So `~/.ssh/work_github` is allowed by the deny rules and denied by
  the hook — the exposure returns only if the hook is disabled.
- **A project-level install does nothing, silently.** See section 5. This is the failure
  mode most likely to bite you, which is why `verify.js` ends with `ENFORCEMENT: ACTIVE`
  or `INACTIVE`.
- **Six of the eight package-manager cooldown settings are inert on older tooling.** See
  section 10. When they are skipped, the 7-day cooldown is carried almost entirely by
  `dep-gate.js` — which only sees installs that go through Claude Code. An `npm install`
  you type yourself, a VS Code task, a `make` target, a CI step, a Dependabot bump: none
  of those pass through a hook.
- **Not written on purpose:** yarn's `npmMinimalAgeGate` — the unit is disputed between
  sources and a wrong value makes `yarn install` fail, which is worse than no cooldown.
  The installer prints the line as a suggestion. The winget package ID for gitleaks in
  `setup/tools.md` is likewise unverified and marked there. (`AquaSecurity.Trivy` is now
  verified — it is what installed the trivy on this machine.)

## 10. Version requirements for the cooldown settings

Checked at install time. If your version predates support, the installer skips the key —
it never writes something your tooling will reject — and prints the upgrade command.
Re-run the installer after upgrading.

| Setting | Tool | Needs | Unit | Upgrade |
|---|---|---|---|---|
| `min-release-age` | npm | >= 11.10.0 | days | `npm i -g npm@latest` |
| `min-release-age-exclude` | npm | >= 11.17.0 | globs | `npm i -g npm@latest` |
| `ignore-scripts` | npm | any | — | — |
| `minimumReleaseAge` | pnpm | >= 10.16.0 | minutes | `npm i -g pnpm@latest` |
| `minimumReleaseAgeExclude` | pnpm | >= 10.17.0 | globs | `npm i -g pnpm@latest` |
| `exclude-newer = "7 days"` | uv | >= 0.9.17 for a relative duration | days | `uv self update` |
| `uploaded-prior-to = P7D` | pip | >= 26.1 (26.0 is absolute dates only) | ISO-8601 duration | `python -m pip install --upgrade pip` |
| `global-min-publish-age` | cargo | Rust >= 1.100 (due 2026-11-12) | duration string | `rustup update` |
| `npmMinimalAgeGate` | yarn berry | >= 4.10.0 — never written, see section 9 | disputed | — |
| `minimumReleaseAge` | bun | >= 1.3 | seconds | `bun upgrade` |

Until Rust 1.100 lands, `cargo install cargo-cooldown` gives you `cargo cooldown <cmd>`
as a manual stand-in.

## 11. Maintenance

Run the test suite from the repo root:

```bash
npm test
```

It runs 727 tests with the Node test runner and no dependencies. As of 2026-10-24:
720 pass, 0 fail, 7 skipped.

After editing a hook in this repo, the installed copy does not change. Re-copy it
yourself — Claude cannot, by design — and re-verify:

```bash
cp -r ~/secops-guard/plugins/secops-guard/hooks/* ~/.claude/hooks/secops-guard/
node ~/secops-guard/setup/verify.js
```

```powershell
Copy-Item -Recurse -Force "$env:USERPROFILE\secops-guard\plugins\secops-guard\hooks\*" "$env:USERPROFILE\.claude\hooks\secops-guard\"
node "$env:USERPROFILE\secops-guard\setup\verify.js"
```

Restart Claude Code after any change to `settings.json`. Changes to hook *scripts* take
effect on the next tool call, since each hook is a fresh Node process.
