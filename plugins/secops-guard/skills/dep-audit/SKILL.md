---
name: dep-audit
description: >
  Use when the user asks to audit dependencies, check for vulnerable packages, run a CVE scan,
  SCA, a supply chain check, or an SBOM review, or asks "is this package safe" / "are my deps OK".
  Covers npm, pnpm, yarn, bun, pip/uv/poetry/pipenv, and Cargo lockfiles, plus Dockerfile base
  images and GitHub Actions pinning.
---

# Dependency audit (SCA)

Find vulnerable, malicious, and too-new dependencies. Prove which findings are reachable.
Propose the smallest safe fix. Every step before "Apply fixes" is read-only: run it without asking.

## 1. Scan (always)

```bash
node "${CLAUDE_PLUGIN_ROOT}/skills/dep-audit/scripts/audit.js" --cwd "<project dir>" --recursive --json
```

- Drop `--recursive` for a single-package repo. Drop `--json` for a human table.
- The script queries OSV.dev for every lockfile package. It checks registry publish dates for direct deps only.
  It also flags missing lockfiles, floating `FROM` images, and `uses:` not pinned to a 40-char SHA.
- It always exits 0. Read the `errors` array. A failed OSV query means the result is **incomplete**, not clean.
- `MAL-*` ids are `MALICIOUS`. Treat them as an incident: stop, tell the user, recommend rotating credentials
  on any machine that installed the package.

## 2. Cross-check with external scanners (only if on PATH)

Check with `command -v osv-scanner grype trivy` (PowerShell: `Get-Command`). Run what exists and merge by advisory id:

| Tool | Command |
|---|---|
| osv-scanner | `osv-scanner scan source -r --format json <dir>` |
| grype | `grype dir:<dir> -o json` |
| trivy | `trivy fs --scanners vuln --format json <dir>`. Run `trivy --version` first. **v0.69.4 to v0.69.6 are malicious** (CVE-2026-33634): do not run them. Report them as an incident and tell the user to rotate credentials. |

None installed: continue with the script output. Do not install anything without asking.
In the report you may suggest `winget install Google.OSVScanner` / `winget install Anchore.Grype`
(macOS/Linux: `brew install osv-scanner grype`). For an SBOM, suggest `syft dir:<dir> -o cyclonedx-json`
(`winget install Anchore.syft`).

## 3. Reachability: prove it (each HIGH, CRITICAL, MALICIOUS)

The lockfile only shows that a package is installed. It does not show that the vulnerable code runs.
For each finding:

1. Get the affected function or module from the advisory: `https://api.osv.dev/v1/vulns/<id>` (WebFetch).
   Read `details`, `affected[].ecosystem_specific`, and `database_specific`.
2. Use Grep to find imports of the package (`require('pkg')`, `from pkg import`, `use pkg::`).
   Then find calls of the affected API. Exclude `node_modules`, `.venv`, and `target`.
3. Label each finding:
   - `REACHABLE`: the affected API is called from first-party code. Cite `file:line`.
   - `NOT-REACHED`: the package is imported, but the affected API is not called.
     Or the package is only a transitive dep that you never import.
   - `UNKNOWN`: dynamic import, reflection, or the advisory names no function. Treat as reachable.
4. A dev-only dep (test or build) lowers urgency, but not to zero. Build tools run on developer laptops and in CI.

## 4. Remediation (propose; never apply without the user's OK)

- Target the **first fixed version** that is at least `cooldownDays` (default 7) old. Resolve the newest
  old-enough version in the fixed range (ecosystem is `npm`, `pypi`, or `crates`):
  ```bash
  node -e "require(process.argv[1]).resolveVersion(process.argv[2],process.argv[3],process.argv[4],7).then(r=>console.log(JSON.stringify(r)))" "${CLAUDE_PLUGIN_ROOT}/hooks/lib/registries.js" npm lodash ">=4.17.21"
  ```
  This returns the newest match. If the user wants the minimal bump, confirm that the exact first-fixed
  version is at least 7 days old, and prefer it.
- Flag a major-version bump (`MAJOR`) and name the breaking-change risk.
- A transitive-only vuln: prefer an upgrade of the direct parent. If no fixed parent exists, use an override.

| Manager | Direct | Transitive override |
|---|---|---|
| npm | `npm install pkg@X.Y.Z` | `"overrides": {"pkg": "X.Y.Z"}` then `npm install` |
| pnpm | `pnpm add pkg@X.Y.Z` | `"pnpm": {"overrides": {"pkg": "X.Y.Z"}}` |
| yarn | `yarn add pkg@X.Y.Z` | `"resolutions": {"pkg": "X.Y.Z"}` |
| uv | `uv add "pkg==X.Y.Z"` | `uv lock --upgrade-package pkg` |
| poetry | `poetry add pkg@X.Y.Z` | `poetry update pkg` |
| pip | pin `pkg==X.Y.Z` in requirements | same |
| cargo | `cargo update -p pkg --precise X.Y.Z` | same |

- Docker: pin `FROM image:<exact tag>@sha256:<digest>`. To get the digest: `docker buildx imagetools inspect image:tag`.
- Actions: `uses: owner/repo@<40-char sha> # vX.Y`. To get the SHA: `git ls-remote https://github.com/owner/repo refs/tags/vX.Y`.
- Too-new direct deps: pin the previous release that is old enough, or wait for the cooldown.

The secops-guard `dep-gate` hook re-checks every install command you run. A denial is the hook doing its job.
Pick the version that the denial names.

## 5. Report

```markdown
# Dependency audit: <project> (<date>)
**Summary:** MALICIOUS n · CRITICAL n · HIGH n · MODERATE n · LOW n · too-new n · missing lockfiles n
**Scanners:** audit.js (OSV) [+ osv-scanner / grype / trivy]

| Sev | ID (CVE) | Package@version | Fixed | Reachability | Evidence | Lockfile |
|---|---|---|---|---|---|---|

## Fixes (proposed, not applied)
1. `<command>`: fixes <ids>. [MAJOR bump: <risk>]

## Supply-chain hygiene
Missing lockfiles, floating images, unpinned Actions, too-new deps.

## Residual risk
Unfixed advisories, UNKNOWN reachability, scanners not run, OSV errors.
```

## Common mistakes

- You report "no vulns" when `errors` is non-empty. Say the scan was incomplete.
- You upgrade to `latest` instead of the first old-enough fixed version.
- You run fix commands before the user approves them.
- You call a finding NOT-REACHED without a grep. Absence needs evidence too: name the search you ran.
