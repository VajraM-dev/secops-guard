---
name: sast-scan
description: >
  Use when the user asks for a security scan, SAST, to scan code for vulnerabilities, to find secrets
  or hardcoded keys/tokens/passwords, an IaC scan (Terraform, Kubernetes, Dockerfile, CloudFormation),
  or a security review of a repo, directory, or the current diff/PR.
---

# SAST scan with triage

Scanners find candidates. You prove them. Report only findings that you confirmed or that need context.
Every finding gets a verdict with reasoning. Every step is read-only except tool installs.

**Rules (defensive scope)**
- Scan only the user's own source tree. Never point a scanner at a URL, a host, a third-party system,
  or production.
- "Prove it" means an evidence chain in the source: `file:line` from source to sink. The most you
  may add is a proposed regression test that fails before the fix. Never run an exploit, never send
  traffic to any host, and never write ready-to-run attack payloads.
- Never print a full secret value. Show the first 4 chars, then `…`, then the length.
- Ask before a global install (`uv tool install`, `brew`, `winget`, `scoop`). Ephemeral `uvx` and
  `docker run --rm` with pinned versions need no approval.

## 1. Scope

- Full scan: the repo root, or the path the user gave.
- Diff mode (`--diff`, "scan my changes", PR review): use only the changed files.
  ```bash
  base=$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main)
  git diff --name-only --diff-filter=ACMR "$base"...HEAD; git diff --name-only; git ls-files --others --exclude-standard
  ```
- Detect languages, frameworks, and IaC from manifests and extensions with Glob. Note the entry points:
  routes, handlers, CLI, queue consumers, LLM tool calls. These are the **sources** for triage.

## 2. Run the available tools

Check with `command -v` or `Get-Command`. Exact commands, pinned versions, and Windows notes are in
`references/tools.md`. Read it now.

| Need | Preferred | Fallback, no install |
|---|---|---|
| Multi-language SAST | `semgrep` | `uvx semgrep@<pinned>` (Linux/macOS, or `docker run --rm`). If neither works, do manual review (step 3). |
| Python | `bandit` | `uvx bandit@<pinned>` |
| Secrets | `gitleaks` | Grep with the regex list in `references/tools.md` |
| IaC | `checkov` / `trivy config` | `uvx checkov@<pinned>`, or manual review of IaC against `references/tools.md` |
| Dependencies | the dep-audit skill | |

Write the tool output to the scratchpad as JSON. Do not paste the raw output into the context.
A tool that fails or is missing goes into the report's "Coverage" section.

## 3. Manual review (always; it is the only option when no tools run)

Load only the vuln-class guides that match the stack and the findings:
`${CLAUDE_PLUGIN_ROOT}/skills/appsec-review/references/<class>.md`.
The classes are: sqli, xss, idor-authz, ssrf, authn-jwt, rce-injection, path-traversal, xxe, csrf,
race-conditions, business-logic, deserialization, secrets-crypto, llm-prompt-injection, supply-chain.
For framework-specific sinks and controls, see `frameworks.md` in the same directory.

If the user wants a deep manual review (threat model, authz matrix, business logic) instead of a
tool-driven scan, hand off to the `appsec-review` skill.

Trace from the sources (step 1) to the dangerous sinks: query builders, shell/exec, file paths,
HTTP clients, templates, deserializers, and authz checks.

**Large repo** (> ~300 source files, or > 50 raw findings): dispatch parallel subagents
(Agent tool, one message). Give each agent one vuln class or one module. Give each agent the relevant
reference path, the source list, and the raw findings for its class. Each agent returns findings in the
triage format below. You merge them and remove duplicates.

## 4. Triage: every candidate gets a verdict

Read `references/triage.md` for the false-positive heuristics and the severity rubric. For each candidate:

```
[TRUE|FALSE|NEEDS-CONTEXT] <SEV> <class> <file:line>
Source -> sink: <untrusted input> (file:line) -> <transforms> -> <sink> (file:line)
Why: <one or two sentences; for FALSE name the heuristic, e.g. "constant arg", "parameterised">
Regression test (TRUE and HIGH+ only, proposed, not run): <a test name, and what it asserts, that fails before the fix>
Fix: <minimal diff>
```

A sink without a reachable untrusted source is FALSE or NEEDS-CONTEXT, never TRUE.

## 5. Report

```markdown
# Security scan: <target> (<full | diff vs main>) (<date>)
**Confirmed:** CRITICAL n · HIGH n · MEDIUM n · LOW n | **Needs context:** n | **Dismissed:** n false positives
**Coverage:** tools run / skipped (+why), classes reviewed, files in scope

## Findings
### [HIGH] SQL injection in /api/orders (`src/orders.py:42`)
Data flow (file:line chain), impact, regression test, fix diff

## Needs context
Question for the user per item

## Secrets
Location, type, redacted value, rotate? (assume it is compromised if it was ever committed)
```

Propose the fix diffs. Apply them only when the user says so. Committed secrets need rotation.
A code fix alone does not fix them. Tell the user, and point to `git filter-repo` for history rewrites.

## Common mistakes

- You copy scanner output verbatim. Untriaged output is noise. Triage every finding or drop it.
- You mark a finding TRUE without a source-to-sink trace.
- You print secret values in the report.
- You skip the manual review because "semgrep found nothing". Most authz, IDOR, and business-logic
  bugs are invisible to the tools.
