# secops-guard

A Claude Code plugin for people who run in **bypass-permissions mode** and want the
supply chain checked anyway. It never prompts. It lets normal work through silently,
rewrites install commands to pin a version it has actually checked, and hard-denies
only clear risk.

```
pwsh -File setup\install.ps1          # dry run: shows every change, writes nothing
pwsh -File setup\install.ps1 -Apply   # do it
node setup\verify.js                  # PASS/FAIL self-check
```

## Install

As a Claude Code plugin, straight from GitHub:

```
claude plugin marketplace add VajraM-dev/secops-guard
claude plugin install secops-guard@secops-guard
```

Restart Claude Code afterwards. The installer above additionally writes the
package-manager cooldown configs and the permission deny rules.

---

## The threat model

You run Claude Code with permissions bypassed. That is a reasonable trade for speed,
and it means an agent installs packages on your behalf, at machine speed, from a
registry anyone can publish to, with a lifecycle script that runs as you.

The agent is not the attacker. The agent is the **delivery mechanism**. It reads a
README that says `npm i some-helper`, and it does. If `some-helper` was compromised
forty minutes ago, or was never real and the model hallucinated the name and someone
registered it (slopsquatting), nothing between the suggestion and your credentials
notices. Your SSH keys, `~/.aws/credentials`, npm token and GitHub token are all
readable by any `postinstall` script.

secops-guard puts four cheap layers between an install intent and your secrets.

**This works in bypass mode.** A PreToolUse hook that returns `permissionDecision:
"deny"` blocks the tool call outright, bypass or not - verified on Claude Code 2.1.310
by tripping a hook with `cat <file>.env` under bypass: the hook denied and the shell
never ran the command. Permission `deny` rules in `settings.json` are enforced in
bypass too. Bypassing permissions bypasses the *prompts*, not the hooks.

## Why: a short history of why 7 days matters

Nearly every one of these was found and pulled within **hours to days** of publishing.
A cooldown costs you a week of newness and removes almost the entire window.

| Date | Incident | One line |
|---|---|---|
| 2025-03-14 | **tj-actions/changed-files** (CVE-2025-30066) | Action tags repointed to malicious code; runners leaked secrets. Workflows pinned by commit SHA were unaffected. |
| 2025-09-08 | **chalk / debug + 16 npm packages** | Maintainer phished; malicious versions live about 2.5 hours - long enough to reach thousands of CI runs. |
| 2025-09-15 | **Shai-Hulud worm** | Self-replicating npm worm: 180 packages, then 500+. Stole tokens from `postinstall` and republished itself. |
| 2025-11-24 | **Shai-Hulud 2.0** | 796 packages. Credential harvesting in `preinstall` this time, so even `--ignore-scripts`-less installs paid before anyone looked. |
| 2025-05-25 → 2025-09-24 | **crates.io `faster_log`, `async_println`** | Malicious crates sat undetected for four months. Cooldowns do not catch slow burns - OSV does, later. |
| 2025-10-17 | **GlassWorm** (Open VSX / VS Code) | Invisible-Unicode payloads in extensions; waves continued into 2026. Editor plugins are supply chain too. |
| 2026-03 | **Trivy 0.69.4 - 0.69.6** (CVE-2026-33634) | The *security scanner* shipped malicious binaries and images; mutable `trivy-action` tags force-pushed. Fixed long ago - install a current trivy (v0.76.1 here), do **not** pin to an old one, and pin `trivy-action` by commit SHA in CI. |
| 2026-08 | **crates.io `arrayref`, `internment`, `append-only-vec`** | Exposure windows of 86 to 107 minutes. Caught fast; a cooldown catches it anyway. |

## The layered design

Each layer is cheaper and dumber than the one below it, and catches a different thing.

1. **Package-manager config** (`setup/configs/**`) - a 7-day cooldown written into
   `.npmrc`, pnpm's `config.yaml`, `uv.toml`, `pip.ini`, Cargo's `config.toml`. Applies
   to *everything*, including installs you run yourself with no agent involved. No
   network, no latency, no bypass. This is the strongest layer and the least clever.
2. **PreToolUse hooks** - run before the command does.
   - `dep-gate.js` resolves each requested package to a version that is old enough and
     clean in OSV, then **rewrites the command** to pin that exact version. A deny is
     the exception, not the mechanism.
   - `manifest-gate.js` does the same for a dependency added by editing
     `package.json` / `pyproject.toml` / `Cargo.toml` directly.
   - `guard.js` blocks secret exfiltration, obfuscated execution (`curl | sh`,
     base64-decoded eval), persistence, and tampering with security tooling or with
     this plugin.
   - `build-gate.js` denies a publish that would ship a secret baked into the artifact.
3. **PostToolUse hooks** - `post-install-scan.js` scans what actually landed and
   reports back to Claude. `build-gate.js` scans what the build just wrote. Neither can
   undo anything; they tell the agent what to do next.
4. **On-demand scans** - the four skills below, plus whatever scanners you chose to
   install from `setup/tools.md`.

### Side A and Side B

Layers 1 to 3 above gate **inputs**: what gets installed. `build-gate.js` is the other
side - it gates **outputs**: the Docker image, the `dist/` bundle, the wheel, the release
binary. Side A cannot see transitive dependencies that only appear in the artifact, OS
packages inherited from a base image, drift since install day, or a secret inlined at
build time - `VITE_*` and `NEXT_PUBLIC_*` go into the JS bundle by design, a missing
`.dockerignore` copies `.env` into a layer, a build arg lives in `docker history`
forever.

The policy is asymmetric on purpose: **CVEs are reported and never block; a secret
denies the publish.** A CVE in a base image is common and often unfixable that minute, so
blocking on it would make the tool unusable. A secret in a pushed layer or a published
package cannot be taken back, and costs nothing to fix before it ships. Details in
`GUIDE.md` section 3.

Destructive commands (`rm -rf`, `git reset --hard`, force-pushes to protected branches,
`DROP TABLE`, `mkfs`, `dd`) are blocked by secops-guard's own `block-dangerous.js`.

## What ships

**Hooks**

| Hook | Event | What it does |
|---|---|---|
| `dep-gate.js` | PreToolUse (Bash, PowerShell) | Parses install intents out of the command. Resolves each package to the newest non-prerelease version published at least `cooldownDays` ago, OSV-checks that exact version, then rewrites the command with the version pinned (plus `--save-exact` / `--exact` for npm, pnpm, yarn and bun, so the manifest records the exact version and not a `^` range). Denies on malware, on a vuln at or above the threshold, on a package that does not exist in the registry (hallucinated / slopsquatted), and on a user-pinned version that is too new. For bare `npm install` / `uv sync` / `cargo build` it scans the lockfile instead and caches the verdict by lockfile hash. Configured `onFailure: block`. |
| `manifest-gate.js` | PreToolUse (Edit, Write, MultiEdit) | The same checks when a dependency is added by editing a manifest rather than by running a command. |
| `guard.js` | PreToolUse (all file and shell tools) | Blocks reading or shipping out credentials, obfuscated execution, persistence (cron, autorun, shell profiles), disabling other security hooks, and any write under the plugin's own state directory. |
| `block-dangerous.js` | PreToolUse (Bash, PowerShell) | Denies destructive commands: `rm -rf`, `git reset --hard`, force-pushes to protected branches, `DROP TABLE`, `mkfs`, `dd` and similar. |
| `redact-env.js` | PreToolUse (Read, Grep, Bash, PowerShell) | Blocks shell access to `.env` files. A Read of one is denied but returns the keys with values replaced by `<REDACTED>`, so Claude still sees variable names. |
| `post-install-scan.js` | PostToolUse (Bash, PowerShell) | After an install actually ran, scans the resulting tree and reports findings to Claude. Cannot undo - it is feedback, not a gate. |
| `build-gate.js` | PreToolUse **and** PostToolUse (Bash, PowerShell) | Side B. Scans the artifact a build just wrote, and the artifact a publish is about to ship, for CVEs and for secrets baked in at build time. CVEs are reported; a secret denies the publish. Needs trivy; without it the hook says so and allows. Secret values are never printed - rule id, severity, file and line only. |
| `plugin-integrity.js` | SessionStart | Hashes every installed plugin's hooks, scripts and MCP config, diffs against the last snapshot, and reports added, removed or changed plugins plus any marketplace with `autoUpdate: true`. |

**Skills** (invoke with `/secops-guard:<name>`)

| Skill | For |
|---|---|
| `dep-audit` | Audit the dependencies of a repo: lockfile CVEs, SBOM, Dockerfile base images, GitHub Actions pinning. |
| `sast-scan` | SAST and secret scanning over a repo, directory or the current diff. Uses semgrep / bandit / checkov / gitleaks when present. |
| `appsec-review` | Secure code review of your own code, with `file:line` evidence and a minimal fix diff. |
| `plugin-audit` | Audit your installed Claude Code plugins, their hooks and their MCP servers. |

## Install on a fresh laptop

1. Copy or clone this whole folder, e.g. to `~/secops-guard`.
2. Dry run, read what it intends to do:
   - Windows: `pwsh -File setup\install.ps1`
   - macOS / Linux / WSL: `bash setup/install.sh`
3. Apply: add `-Apply` (or `--apply`).
4. **Restart Claude Code.** Hooks and permission rules load at startup.
5. `node setup/verify.js` - everything should be PASS or SKIP, and the last line must
   read `ENFORCEMENT: ACTIVE`. If it says `INACTIVE`, nothing is being blocked.

### Install it as a plugin, or in user settings. Nothing else works.

Verified on Claude Code 2.1.310:

- **A plugin** (what the installer does) or **`~/.claude/settings.json`** - hooks run.
- **A project-level `.claude/settings.json`** - hooks are **silently ignored**. An
  unapproved project hook never executes, and nothing tells you. Dropping this repo
  into a project folder gives you a security plugin that does not run. `verify.js`
  fails loudly if it finds secops-guard configured that way.
- **`claude -p --settings <file>`** - hooks do **not** load at all. The hook process
  never starts. Do not use it to install or to test.

The installer never needs admin, never touches `managed-settings.json`, and backs up
every file it writes to `<file>.secops-bak-<timestamp>`, printing the restore command.
Re-running it changes nothing.

### Installer flags

| Flag (PowerShell / bash) | Effect |
|---|---|
| *(none)* | Dry run. Prints a per-file diff and exits. **This is the default.** |
| `-Apply` / `--apply` | Actually write. |
| `-CooldownDays <n>` / `--cooldown-days <n>` | Default 7. Recomputed per manager: days for npm, minutes for pnpm and yarn, seconds for bun. |
| `-SkipIgnoreScripts` / `--skip-ignore-scripts` | Do not set `ignore-scripts=true` in `.npmrc`. |
| `-NoPluginInstall` / `--no-plugin-install` | Print the `claude plugin` commands instead of running them. |
| `-NoDenyRules` / `--no-deny-rules` | Skip the permission deny rules below. Everything else still installs. The rules are **on by default** - this is the supported way to decline them. |
| `-Uninstall` / `--uninstall` | Remove only the keys the installer added, leaving everything else in each file untouched. Prints the restore command for each backup. |
| `-RestoreBackups` / `--restore-backups` | With `-Uninstall`: replace each file with the **oldest** backup instead. A true rollback, but it also discards any edit you made to those files since. Use the surgical default unless you want that. |
| `-Quiet` / `--quiet` | Summary only. |

### What needs which version

Checked at install time. If your version predates support, the installer **skips the
key** (it never writes something your tooling will reject) and tells you the upgrade
command. Re-run the installer after upgrading.

| Setting | Tool | Needs | Unit |
|---|---|---|---|
| `min-release-age` | npm | **>= 11.10.0** | days |
| `min-release-age-exclude` | npm | >= 11.17.0 | globs |
| `ignore-scripts` | npm | any | - |
| `minimumReleaseAge` | pnpm | **>= 10.16.0** | minutes |
| `minimumReleaseAgeExclude` | pnpm | >= 10.17.0 | globs |
| `exclude-newer = "7 days"` | uv | **>= 0.9.17** for a relative duration | days |
| `uploaded-prior-to = P7D` | pip | **>= 26.1** (26.0 is absolute dates only) | ISO-8601 duration |
| `global-min-publish-age` | cargo | **Rust >= 1.100** (due 2026-11-12) | duration string |
| `npmMinimalAgeGate` | yarn berry | >= 4.10.0 - **never written**, see below | disputed |
| `minimumReleaseAge` | bun | >= 1.3 | seconds |

### On this machine (2026-10-24): layer 1 is mostly inert

**Six of the eight cooldown settings are skipped.** npm 10.9.8, uv 0.7.12, pip 25.1.1
and cargo 1.92.0 all predate cooldown support; yarn and bun are not installed. Only
**pnpm `minimumReleaseAge`** and **npm `ignore-scripts`** are actually written.

That means the 7-day cooldown is being carried almost entirely by one layer:
`dep-gate.js`, a PreToolUse hook. It enforces the same policy regardless of what your
package manager supports, so you are not unprotected - but it only sees installs that
**go through Claude Code**. An `npm install` you type in your own terminal, a VS Code
task, a `make` target, a CI step, a Dependabot bump, a postinstall script invoking its
own installer: none of those pass through a hook. Nothing checks them today.

Upgrading is what buys you defense in depth - the layer that keeps working when Claude
Code is not the thing running the install:

```powershell
npm  i -g npm@latest                      # unlocks min-release-age   (needs >= 11.10.0)
uv   self update                          # unlocks exclude-newer     (needs >= 0.9.17)
python -m pip install --upgrade pip       # unlocks uploaded-prior-to (needs >= 26.1)
rustup update                             # unlocks global-min-publish-age (Rust >= 1.100, due 2026-11-12)
```

Then re-run the installer - it is idempotent and will write only the keys the new
versions accept:

```powershell
pwsh -File setup\install.ps1          # check the diff first
pwsh -File setup\install.ps1 -Apply
node setup\verify.js                  # the skipped rows should turn into PASS
```

npm and uv are the two worth doing today. pip's support is not released yet in a form
this installer will write, and cargo's lands with Rust 1.100 on 2026-11-12; until then
`cargo install cargo-cooldown` gives you `cargo cooldown <cmd>` as a manual stand-in.

**Unverified, so not written:** yarn's `npmMinimalAgeGate` unit is disputed - the docs
show `"1w"`, other sources say a plain minute count, and a reported bug ignores day
suffixes. A wrong value could make `yarn install` fail, which is worse than no
cooldown, so the installer **prints the line as a suggestion and never writes it**.
The winget package ID for gitleaks is likewise unverified and marked where it appears in
`setup/tools.md`. `AquaSecurity.Trivy` is verified - it is what installed trivy v0.76.1
on this machine.

### Scanners on this machine

`trivy` v0.76.1 (winget) and `semgrep` v1.182.1 (`uv tool install semgrep`). trivy is the
Side B engine - image CVEs, filesystem CVEs, secrets, IaC misconfig - and semgrep backs
the `sast-scan` skill, which falls back to grep without it. Neither is on the `PATH` a
fresh shell inherits; `lib/scan.js` and `setup/verify.js` look in the winget Packages
directory and in `~/.local/bin`.

Not installed and not needed: `grype` and `gitleaks` (trivy covers images and secrets),
`osv-scanner` (`dep-gate.js` queries the OSV API directly), `syft` (only for an SBOM),
`guarddog` (Docker-only on Windows, marginal once `dep-gate.js` blocks everything OSV
knows).

## Configuration

`~/.claude/secops-guard/config.json`. Optional - the defaults below apply without it.
Only you edit this file; `guard.js` blocks Claude from writing anything under that
directory.

```json
{
  "cooldownDays": 7,
  "packageSeverityBlock": "ANY",
  "lockfileSeverityBlock": "HIGH",
  "imageSeverityBlock": "HIGH",
  "failOpen": false,
  "allow": ["npm:some-pkg", "pypi:some-pkg@1.2.3", "image:nginx:1.27"],
  "allowRegistries": ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
                      "download.pytorch.org", "crates.io", "index.crates.io"]
}
```

| Key | Default | Effect |
|---|---|---|
| `cooldownDays` | `7` | A package version younger than this is not installed. An explicit install resolves down to the newest version that is old enough; an exact pin that is too new is denied, naming the version to use instead. |
| `packageSeverityBlock` | `"ANY"` | Severity threshold for an explicitly named package. `"ANY"` means any known vulnerability blocks. Scale: `LOW < MODERATE < HIGH < CRITICAL`. |
| `lockfileSeverityBlock` | `"HIGH"` | Threshold for a bare `npm install` / `uv sync` / `cargo build`, where the lockfile is scanned. Below the threshold is allowed with a summary passed to Claude. |
| `imageSeverityBlock` | `"HIGH"` | Threshold for a Docker image, scanned with grype / trivy / docker scout if one is on PATH. No scanner means allowed with a note. `build-gate.js` reuses it as the floor for which CVEs it names in its report, but never blocks on them. |
| `failOpen` | `false` | What to do when OSV or a registry cannot be reached. `false` denies with "could not verify; retry". Set `true` only if you work offline and accept the gap. |
| `allow` | `[]` | The escape hatch. See below. |
| `allowRegistries` | npm, PyPI, crates.io hosts | Registry hosts that are considered normal. A fetch from anywhere else is treated as suspicious. |

An `MAL-*` OSV id is always `MALICIOUS` and always blocks, whatever the thresholds say.
Unknown severity counts as `HIGH`.

Environment overrides, for one shell: `SECOPS_COOLDOWN_DAYS`, `SECOPS_FAIL_OPEN=1`,
`SECOPS_DISABLE=1`, `SECOPS_STATE_DIR`, `SECOPS_BUILD_BUDGET_MS` (Side B scan budget,
default 90000 ms; a scan that runs out of budget produces context, never a deny).

### The allowlist escape hatch

When a block is wrong - an internal package, a CVE that does not apply to you, a
version you need today - add an entry to `allow`:

```json
"allow": [
  "npm:@acme/internal-ui",          // any version
  "pypi:torch@2.9.0",               // that exact version
  "crates:my-fork",
  "image:nginx:1.27"
]
```

An allowlisted package skips the cooldown, the OSV check and the registry-existence
check. It is still pinned to a resolvable version. **You** edit this file - Claude
cannot, which is the point: an agent that can edit its own allowlist has no allowlist.

### Turning it off temporarily

In **your own shell**, before launching Claude Code:

```powershell
$env:SECOPS_DISABLE = "1"; claude     # PowerShell
```
```bash
SECOPS_DISABLE=1 claude               # bash
```

Every hook becomes a no-op for that session. Do not put this in `settings.json`'s `env`
block - that would disable it permanently and silently, which is exactly the failure
mode the plugin exists to prevent.

## The permission deny rules

`setup/settings.snippet.json` is merged into `~/.claude/settings.json`. Deny rules are
enforced even in bypass mode, which is what makes them worth having. JSON has no
comments, so each rule is justified here.

`defaultMode` is deliberately **not** set - you chose bypass, the installer leaves that
alone. All 33 rules are applied by default; `-NoDenyRules` / `--no-deny-rules` declines
them without you having to hand-edit a file we shipped.

**These rules overlap with `guard.js` on purpose. Do not "clean up the duplication."**
The hook is the primary control: it covers these paths for `Read`/`Grep`/`Glob` *and*
for shell commands, which permission rules cannot see. The rules are the **backstop** -
the part that still works if hooks are disabled, crash, or time out. Each layer covers
the other's failure mode. Deleting either because it looks redundant removes a whole
layer.

### Upgrading from a pre-release snippet

`-Uninstall` removes deny rules by **exact string match**, so rules that were dropped
from the snippet after you applied it stay in your `settings.json` forever - the
installer no longer knows about them. If you applied a build before 2026-10-24, delete
these five lines from `permissions.deny` in `~/.claude/settings.json` by hand:

```
"Read(~/.ssh/id_*)",              <- replaced by the four explicit private-key names
"Read(~/.npmrc)",
"Read(~/.docker/config.json)",
"Read(~/.kube/config)",
"Edit(~/.claude/hooks/**)",
```

Leaving them is not dangerous, only friction: they block reads and edits that are part
of normal work. Back the file up first; `node setup/verify.js` confirms it still parses.

Rules were deliberately **not** added for `~/.npmrc`, `~/.docker/config.json`,
`~/.kube/config`, `~/.ssh/*.pub` or `~/.claude/hooks/**`: each is read during normal
work (npm config debugging, `credsStore` setups that hold no secret, cluster and
context names, public keys, your own hook development). `guard.js` covers the
exfiltration case for all of them, which is the actual threat.

| Rule | Why |
|---|---|
| `Read(~/.ssh/id_rsa)`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `Read(~/.ssh/*.pem)`, `Read(~/.ssh/*.key)` | Private keys, named explicitly so that **`.pub` public keys stay readable** - asking Claude for your public key is normal work. `config` and `known_hosts` stay readable too. |
| `Read(~/.aws/credentials)`, `Read(~/.aws/sso/cache/**)` | Long-lived AWS keys and cached SSO tokens. |
| `Read(~/.config/gcloud/...)`, `Read(~/AppData/Roaming/gcloud/...)` | GCP application-default credentials and the token databases, on both path layouts. |
| `Read(~/.pypirc)` | PyPI upload token. |
| `Read(~/.netrc)`, `Read(~/_netrc)` | Plaintext passwords for arbitrary hosts. `_netrc` is the Windows spelling. |
| `Read(~/.git-credentials)` | Plaintext git passwords and PATs. |
| `Read(~/.cargo/credentials.toml)` | crates.io publish token. |
| `Read(~/.config/gh/hosts.yml)`, `Read(~/AppData/Roaming/GitHub CLI/hosts.yml)` | The GitHub CLI's stored OAuth token - the most directly useful secret on a developer laptop. |
| `Read(.../Login Data)`, `Read(.../logins.json)`, `Read(.../key4.db)` | Chrome, Edge and Firefox saved-password stores. |
| `Edit(~/.claude/plugins/marketplaces/secops-guard/**)`, `Edit(~/.claude/plugins/repos/**/secops-guard/**)` | Claude must not edit the installed copy of its own guard. Develop the plugin in this repo instead, where editing is allowed. |
| `Edit(~/.claude/secops-guard/**)` | The state directory: config, allowlist, OSV cache, plugin snapshot. An agent that can edit the allowlist has no allowlist. |
| `Edit(//.../managed-settings.json)` | Enterprise policy, on all three platforms. Should be root-owned anyway; this is belt and braces. |

Note the shape: **`Read(...)` and `Edit(...)` only.** `Write(path)` and `Glob(path)`
rules never match in Claude Code, so they would be decoration. Shell access to the same
files (`cat ~/.ssh/id_rsa`) is not covered by permission rules at all - that is
`guard.js`'s job.

## Known limits

Read these before trusting it.

- **A guardrail, not a sandbox.** Everything here is heuristics over text. A determined
  attacker with code execution works around it. It raises the cost of an accident and of
  a commodity attack; it does not contain a targeted one.
- **You can turn it off, so anything running as you can too.** In bypass mode, the
  agent could in principle edit `settings.json` and remove the hooks. `plugin-integrity.js`
  reports tampering at the next session start, which is detection, not prevention. For
  real enforcement use `managed-settings.json` with `allowManagedHooksOnly` - see
  `RELEASE.md`.
- **Destructive commands are covered by `block-dangerous.js`, not `guard.js`.** It
  catches `rm -rf /`, `git reset --hard`, `DROP TABLE`, `mkfs`, `dd` and force-pushes to
  protected branches. Like the other hooks it is pattern matching over the command text,
  so a sufficiently indirect command gets past it.
- **PostToolUse cannot undo anything.** By the time `post-install-scan.js` runs, the
  `postinstall` script has already run as you. It reports; it does not roll back. The
  same holds for `build-gate.js` on a build: the artifact with the secret in it is
  already on disk. The deny it can still make is the one before the publish.
- **Side B does nothing without trivy.** grype and docker-scout cannot scan a
  filesystem, so with only those installed, bundles, wheels and release binaries are
  accepted unchecked and no secret detection runs at all. Image CVE scanning still works
  through them.
- **Side B reports CVEs and never blocks on them**, on build and on publish alike. It
  will hand you a list of criticals in your base image and still let the push run. That
  is the chosen policy.
- **The `.dockerignore` check reads the hook payload's `cwd`, not the build-context
  argument.** `docker build -t app ./sub` checks the wrong directory and under-warns.
- **`gh release upload dist/*` with an unexpanded glob scans nothing.** Side B takes the
  literal asset paths off the command line and skips those that do not exist on disk; a
  glob the shell did not expand is one of them. At most 5 assets are scanned.
- **`cargo build` without `--release` is not treated as a build** and is not scanned.
- **No transitive protection before the fact.** Without a lockfile, `dep-gate.js` sees
  only the package you named. Its dependencies are checked after installation. With a
  lockfile, the whole tree is checked first.
- **Cooldowns do not catch slow burns.** `faster_log` on crates.io sat for four months.
  A cooldown catches the hours-to-days attacks, which is nearly all of them; OSV catches
  the rest, later.
- **Network checks need the network.** With `failOpen: false` (the default) an install
  is denied when OSV is unreachable. That is the safe choice and it will annoy you on a
  plane.
- **`ignore-scripts=true` breaks native addons.** esbuild, sharp and friends need
  `npm rebuild <pkg> --foreground-scripts` afterwards. Opt out with `-SkipIgnoreScripts`.
- **Hooks fail open** on crash or timeout, except `dep-gate.js`, which is configured to
  block.
- **Uninstall deletes the keys it added rather than restoring your previous values.** If
  you had `ignore-scripts=false` before, uninstall leaves the key absent, not `false`.
  The backup holds your original file and the restore command is printed; add
  `-RestoreBackups` for a full rollback.
- **A private key with a non-standard filename is covered by the hook, not by the
  permission rules.** A permission glob cannot express "everything in `~/.ssh` except
  `*.pub`", and blocking public keys would break normal work, so the deny rules name
  only `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*.pem` and `*.key`. `guard.js`
  closes the gap by inverting the match: everything directly under `~/.ssh` is secret
  material except an explicit allow set (`*.pub`, `known_hosts`, `config`,
  `authorized_keys`). Measured, not assumed:

  | `~/.ssh/...` | deny rules | `guard.js` (Read tool and shell) |
  |---|---|---|
  | `id_rsa` | denied | denied |
  | `id_rsa.pub` | allowed (correct - public) | allowed (correct) |
  | `work_github` | allowed | **denied** |

  So the exposure only returns if the hook is disabled, which is the general shape of
  every limit on this list.
- **A project-level install does nothing, silently.** See the install section. This is
  the failure mode most likely to bite you, which is why `verify.js` prints
  `ENFORCEMENT: ACTIVE` or `INACTIVE` as its last line.

## Layout

```
secops-guard/
  .claude-plugin/marketplace.json   standalone marketplace manifest
  CONTRACT.md                       internal build contract
  README.md  RELEASE.md
  plugins/secops-guard/             the plugin: hooks, lib, skills, tests
  setup/
    install.ps1  install.sh         machine setup, dry run by default
    merge-settings.js               JSON merge shared by both installers
    verify.js                       post-install self-check
    settings.snippet.json           the deny rules above
    configs/                        the per-manager snippets the installer merges
    tools.md                        optional scanner matrix
```

## License

MIT. See `LICENSE`.
