# Dependency and CI Supply Chain

**CWE:** CWE-1357 (Reliance on Insufficiently Trustworthy Component), CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere), CWE-494 (Download of Code Without Integrity Check), CWE-1104 (Use of Unmaintained Third-Party Components), CWE-506 (Embedded Malicious Code)

Code you did not write runs with your privileges — at install time, at build time, and in CI. The attacker's entry point is a package name, a version bump, or an unpinned GitHub Action, not your source.

**Use the tooling in this plugin instead of hand-auditing.** The `dep-gate` PreToolUse hook already blocks installs of vulnerable, malicious or <7-day-old packages and rewrites the command to pin the resolved version, so the cooldown and the pin are enforced at install time. In a review, recommend `/secops-guard:dep-audit` (scans the committed lockfiles) rather than reading dependency trees by hand, and `/secops-guard:plugin-audit` for installed plugins.

## How it gets introduced

- An unfamiliar import is installed without checking that the package is real and established — a typo of a popular name (`python-dateutil` vs `python-dateutils`), or **slopsquatting**: a package name an LLM or a developer invented that someone has since registered.
- An internal package name (`acme-common`) exists only in a private index while `--extra-index-url`, or a plain `npm install`, lets the public registry answer with a higher version — **dependency confusion**.
- Installs run arbitrary code: npm `preinstall`/`postinstall`, or a pip sdist executing `setup.py` on the build machine.
- The lockfile is gitignored or regenerated in CI, installs use `npm install` / `pip install -r` instead of `npm ci` / `uv sync --frozen` / `pip install --require-hashes`, and a lockfile diff that changes a `resolved` URL or an `integrity` hash is waved through as churn.
- A brand-new version is adopted within hours of publication, so a compromised-maintainer or new-maintainer release lands before anyone notices.
- CI floats (`uses: actions/checkout@v4`), `pull_request_target` checks out and runs the PR head with base-repo secrets, and `GITHUB_TOKEN` keeps its repo-wide default permissions.
- A transitive advisory is "fixed" by upgrading blindly, or dismissed without checking whether the vulnerable path is reachable.

## Python packaging (uv / pip)

```bash
# vulnerable
pip install -r requirements.txt            # no hashes, no lock, sdists build arbitrary setup.py
pip install acme-common --extra-index-url https://pypi.acme.internal/simple   # public may answer
```

```toml
# fixed — pyproject.toml: one authoritative index, internal packages pinned to it
[[tool.uv.index]]
name = "internal"
url = "https://pypi.acme.internal/simple"
default = true                 # replaces PyPI rather than being searched alongside it

[tool.uv.sources]
acme-common = { index = "internal" }     # name bound to an index: public cannot shadow it
```

```bash
# fixed
uv lock                                  # commit uv.lock
uv sync --frozen                         # fails if the lock does not match pyproject
uv sync --frozen --no-install-project    # CI: no project build either
pip install --require-hashes -r requirements.lock   # every artifact hash-checked
pip install --only-binary=:all: -r requirements.lock  # wheels only: no setup.py executes
```

Pin internal/private resolution with `--index-url` (replaces the default), never `--extra-index-url` (adds a competitor that can win on version). Before adding any unfamiliar package: confirm the name on the registry, check the repository link resolves, the release history predates today by months, and the maintainer set did not change this week. If `dep-gate` blocks the install, that is the control doing its job — verify, do not bypass.

## JS / TS packaging (npm / pnpm)

```bash
# vulnerable — package.json: { "acme-common": "^2.0.0", "left-pad": "latest" } (floating, unscoped)
npm install                 # mutates the lockfile, runs every package's install scripts
```

```jsonc
// fixed — package.json: internal packages are scoped, the scope is bound to the private registry
{ "dependencies": { "@acme/common": "2.3.1", "left-pad": "1.3.0" } }
```

```ini
# fixed — .npmrc (committed)
@acme:registry=https://npm.acme.internal/
ignore-scripts=true          # no preinstall/postinstall; allowlist the few that need it
audit-level=high
```

```bash
# fixed
npm ci --ignore-scripts      # installs exactly the lockfile; fails if package.json drifted
pnpm install --frozen-lockfile --ignore-scripts
pnpm why <pkg>               # is the vulnerable transitive path actually pulled in?
```

Commit `package-lock.json` / `pnpm-lock.yaml`. Review lockfile diffs: a changed `resolved` host, a changed `integrity` hash on an unchanged version, or a new transitive package with install scripts are all findings. `pnpm` additionally supports `onlyBuiltDependencies` as an explicit build-script allowlist.

## GitHub Actions

```yaml
# vulnerable
on: pull_request_target            # runs with base-repo secrets and a write token
jobs:
  test:
    permissions: write-all
    steps:
      - uses: actions/checkout@v4                       # floating tag
        with: { ref: "${{ github.event.pull_request.head.sha }}" }   # fork code, trusted context
      - run: npm install && npm test                    # fork's install scripts, with secrets in env
```

```yaml
# fixed
on: pull_request                   # fork PRs run without secrets and with a read-only token
permissions:
  contents: read                   # narrow at workflow level; widen per job only where needed
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<40-char-commit-sha>   # v4.3.0 — SHA-pinned
      - uses: astral-sh/setup-uv@<40-char-commit-sha>  # v6.4.3
      - run: uv sync --frozen
      - run: npm ci --ignore-scripts
      - run: npx --yes osv-scanner@<pinned-version> scan --lockfile=uv.lock --lockfile=package-lock.json
```

Pin every third-party action to a full 40-char commit SHA with the version in a trailing comment, so the tag stays readable while the SHA is what actually resolves; let Dependabot bump the SHA. The placeholders above are placeholders on purpose — never copy a SHA out of a document. Resolve the real one yourself and check what it points at:

```bash
gh api repos/actions/checkout/commits/v4 --jq .sha       # tag -> the SHA to pin
gh api repos/actions/checkout/commits/<sha> --jq .commit.committer.date   # confirm it is the commit you expect
```
 Keep secrets out of jobs that touch untrusted PR content, split "build untrusted code" and "publish" into separate workflows, and use OIDC for cloud credentials instead of long-lived secrets.

## The safe API, per framework

| Tool | Control to use |
|---|---|
| `uv` | `uv lock` committed; `uv sync --frozen`; `[tool.uv.sources]` binding internal names to the private index |
| `pip` | `--require-hashes`, `--only-binary=:all:`, `--index-url` (never `--extra-index-url` for private) |
| `npm` | `npm ci --ignore-scripts`; committed `package-lock.json`; scoped internal names + `@scope:registry` in `.npmrc` |
| `pnpm` | `--frozen-lockfile`, `--ignore-scripts`, `onlyBuiltDependencies` allowlist |
| GitHub Actions | SHA-pinned `uses:`; `permissions: contents: read`; `pull_request` not `pull_request_target`; OIDC |
| Dependabot / Renovate | Grouped PRs plus a cooldown/`minimumReleaseAge` so brand-new versions are not auto-merged |
| OSV / osv-scanner | Lockfile scan in CI; advisories triaged by reachability, not by count |
| SBOM | CycloneDX or SPDX generated at build, stored with the artifact |
| This plugin | `dep-gate` hook (blocks malicious / vulnerable / <7-day-old installs, rewrites to a pinned version); `/secops-guard:dep-audit` (lockfile scan); `/secops-guard:plugin-audit` |

## Grep for

```
rg -n 'uses:\s*[\w.-]+/[\w.-]+@(v?\d|main|master|latest)' .github/   # action pinned to a tag or branch, not a SHA
rg -n 'pull_request_target' .github/                                  # fork code + base secrets; check what it checks out
rg -n 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head'            # checkout of PR head in a trusted context
rg -n 'permissions:\s*(write-all|$)' -A3 .github/                     # missing or repo-wide token permissions
rg -n '\$\{\{\s*github\.event\.(issue|pull_request|comment)\.[a-z_]*(title|body|ref|label)' .github/  # untrusted text into a run: script injection
rg -n 'secrets\.[A-Z_]+' .github/ -B10 | rg -n 'pull_request_target|fork'  # secrets reachable from fork input
rg -n -- '--extra-index-url'                                          # public index can outbid the private one
rg -n 'pip install (?!.*--require-hashes)' -P                         # unhashed install path
rg -n '"[^"]+":\s*"(\^|~|\*|latest|>=)'  package.json                 # floating version ranges in a deployed app
rg -n 'ignore-scripts' .npmrc                                         # absence is the finding
rg -n '^(package-lock\.json|pnpm-lock\.yaml|uv\.lock|poetry\.lock)$' .gitignore  # lockfile not committed
rg -n 'resolved":\s*"https?://(?!registry\.npmjs\.org)' -P package-lock.json  # artifact fetched from an unexpected host
```

## False positives

- A floating range (`^1.2.3`) in a published library's `package.json` — libraries intentionally float; the *application's committed lockfile* is what must pin.
- `postinstall` on a package that legitimately builds a native addon (`esbuild`, `sharp`, Prisma engines) — allowlist it rather than removing `ignore-scripts` globally.
- `uses: ./.github/actions/x` or `uses: acme-org/...` for an action in your own org on a protected ref — same trust boundary; SHA-pinning is still preferred, not a blocker.
- `--extra-index-url` pointing at a private index for packages that are **also** bound by name to that index (`[tool.uv.sources]`) — the binding, not the flag, is the control.
- An open advisory on a transitive dependency whose vulnerable function is never reachable from your code (a Node-only path in a browser bundle, a parser you never call) — this is where **NEEDS-CONTEXT** belongs: record the reachability argument and the advisory id, do not just close it.
- A <7-day-old version that `dep-gate` blocked and a human explicitly approved after checking the publisher and the diff; `pull_request_target` in a workflow that only labels or triages and never checks out PR code.

## Regression test

CI must fail on the policy violation, not on a scanner's mood. Add these as repo tests/steps:

```yaml
# .github/workflows/supply-chain.yml
name: supply-chain
on: [pull_request]
permissions:
  contents: read
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<40-char-commit-sha>   # v4.3.0
      - name: every action is SHA-pinned
        run: |
          if grep -rEn 'uses:[[:space:]]*[^.][^[:space:]]*@(v?[0-9][^[:space:]]*|main|master|latest)' .github/workflows; then
            echo "::error::unpinned action — use a full 40-char commit SHA"; exit 1
          fi
      - name: lockfiles are authoritative
        run: |
          uv sync --frozen            # fails if uv.lock is missing or stale
          npm ci --ignore-scripts     # fails if package-lock.json drifted from package.json
          git diff --exit-code uv.lock package-lock.json   # install must not rewrite the lock
      - name: no vulnerable or malicious dependency
        run: npx --yes osv-scanner@<pinned-version> scan --lockfile=uv.lock --lockfile=package-lock.json
```

```python
# tests/test_supply_chain_policy.py — fails before the fix, passes after
import re, pathlib

WORKFLOWS = list(pathlib.Path(".github/workflows").glob("*.y*ml"))
PINNED = re.compile(r"uses:\s*[\w.-]+/[\w.-]+@[0-9a-f]{40}")
USES = re.compile(r"uses:\s*(?!\./)([\w.-]+/[\w.-]+@\S+)")

def test_all_third_party_actions_are_sha_pinned():
    unpinned = [m.group(1) for wf in WORKFLOWS for m in USES.finditer(wf.read_text())
                if not PINNED.search(m.group(0))]
    assert unpinned == [], f"unpinned actions: {unpinned}"

def test_lockfiles_are_committed():
    for lock in ("uv.lock", "package-lock.json"):
        assert pathlib.Path(lock).is_file(), f"{lock} must be committed"

def test_install_scripts_are_disabled():
    assert "ignore-scripts=true" in pathlib.Path(".npmrc").read_text()
```

