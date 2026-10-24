---
name: appsec-review
description: >
  Secure code review of your OWN codebase: find, prove, and fix vulnerability classes
  during review, with file:line evidence and a minimal fix diff. Use whenever the user asks for a
  "security review", "review this code for vulnerabilities", "is this endpoint safe", "secure code
  review", "threat model", "check authz", "harden this", "did I introduce a vuln", "review my PR for
  security", or asks whether some input is validated, escaped, parameterized, or authorized.
  Also use when reviewing auth, session, upload, template, query, deserialization, LLM-tool or
  dependency code, and when triaging a scanner finding into TRUE / FALSE / NEEDS-CONTEXT.
  Trigger even when only one endpoint or one function is in scope — the trust-boundary pass is
  what catches the bug.
---

# appsec-review

A defender-side knowledge base for reviewing and fixing your own code. Sibling skill `sast-scan`
runs the scanners and triages their output; it loads the per-class reference files here by name, so
their filenames are a contract — do not rename them.

## Scope

This skill reads source, reasons about it, and **proposes** fixes. It is defensive knowledge only.

- **Verification** means reading the user's own code and, at most, a regression test against their
  own locally running app. Never send traffic to a host the user does not own, and never to a
  production, staging, shared, or third-party system — including to "confirm" a finding.
- **Vulnerable snippets** exist only to make a pattern recognizable; the safe pattern is the point
  and gets the space. Do not write attack scripts, exploit chains, or payload collections.
- **Nothing** about evading detection, disabling security controls, or hiding activity. If a
  finding depends on logging or monitoring, the fix is to improve it, not to work around it.
- **Fixes are proposals.** Apply nothing that breaks an API contract, requires a migration, or
  invalidates sessions, tokens, or keys until the user has seen it and agreed. Small, local,
  behavior-preserving fixes may be applied when the user asked for fixes — say what you changed.

## Workflow

### 1. Scope the review

Establish what is actually in scope before reading anything:

- Changed surface: `git diff --name-only <base>...HEAD`, or the files/endpoints the user named.
- Entry points reachable from those files: HTTP routes, CLI args, queue consumers, webhooks,
  scheduled jobs, LLM tool handlers, file uploads, websockets.
- **Trust boundaries** and the data that crosses each one. Everything outside your process that
  you do not fully control is untrusted: the browser, other services, the database when it holds
  user-supplied strings, S3 object contents, LLM output, environment of a multi-tenant request.

Write the boundary list down — it drives everything after this. `references/methodology.md` has
the per-boundary checklist.

### 2. Pick the vuln classes, load only those references

Match the stack and the boundaries to the table below and read only the files that apply. Reading
all of them wastes context and dilutes the review.

| Reference | Load when |
|---|---|
| `references/methodology.md` | Always — the review pass itself and the per-boundary checklist |
| `references/severity-rubric.md` | Always, before you assign any severity |
| `references/report-template.md` | Always, when writing the output |
| `references/sqli.md` | Raw SQL, `text()`, query builders, ORM `filter()` with f-strings, dynamic ORDER BY |
| `references/xss.md` | Any HTML/template rendering, React `dangerouslySetInnerHTML`, Jinja `\|safe`, markdown |
| `references/idor-authz.md` | Any route taking an object id, multi-tenant data, admin routes, GraphQL |
| `references/ssrf.md` | Server fetches a user-supplied URL: webhooks, imports, previews, file-from-URL |
| `references/authn-jwt.md` | Login, sessions, tokens, JWT verify, password reset, MFA, API keys |
| `references/rce-injection.md` | `subprocess`, `eval`, `exec`, templates compiled at runtime, LDAP, NoSQL, shell |
| `references/path-traversal.md` | File read/write/download/upload with any user-influenced path |
| `references/xxe.md` | XML, SVG, DOCX/XLSX/SAML parsing, SOAP, RSS |
| `references/csrf.md` | Cookie-authenticated state-changing routes, SameSite config, CORS |
| `references/race-conditions.md` | Balance/quota/coupon/idempotency logic, check-then-act, TOCTOU |
| `references/business-logic.md` | Pricing, workflow state machines, limits, refunds, invite flows |
| `references/deserialization.md` | `pickle`, `yaml.load`, `torch.load`, Node `vm`, JSON revivers, msgpack |
| `references/secrets-crypto.md` | Hardcoded keys, token/ID generation, hashing, encryption, TLS config |
| `references/llm-prompt-injection.md` | Prompts, LangChain/LangGraph agents, tools, RAG, MCP, model output used downstream |
| `references/supply-chain.md` | Dependency adds/bumps, lockfiles, CI workflows, install scripts |
| `references/frameworks.md` | Which secure defaults the stack gives you, and how they get disabled |

### 3. Trace, don't pattern-match

For each class, trace untrusted input from **source** (where it enters) to **sink** (where it does
something dangerous), recording `path/to/file.py:123` at each hop. A grep hit is a lead, not a
finding. The trace is what distinguishes a real bug from noise, and it is also what tells you the
cheapest place to put the fix — usually one hop before the sink, in shared code.

### 4. Classify every lead

| Verdict | Requires |
|---|---|
| **TRUE** | A reachable source, a real sink, and a stated reason why the existing controls do not stop it |
| **FALSE** | A specific control that does stop it, cited at `file:line` |
| **NEEDS-CONTEXT** | You cannot see one of the three — the caller is out of scope, the control is in infra, the value's origin is unknown |

NEEDS-CONTEXT is the honest default, not a weak TRUE. Shipping a confident finding you cannot
substantiate is how a review loses its reader; list what you'd need to resolve it instead. Equally,
do not downgrade a real bug to NEEDS-CONTEXT to be polite — if the three parts are there, call it.

### 5. Severity

Score with `references/severity-rubric.md` (impact x exploitability x exposure). Use the worked
examples there rather than inventing a number; consistency across findings matters more than the
absolute value.

### 6. Fix

One minimal diff per finding. Order of preference:

1. The framework's built-in control (parameterized query, auto-escaping template, `Depends()` authz,
   `SameSite` cookie, `defusedxml`) — see `references/frameworks.md`.
2. An existing helper in this codebase — grep for one before writing a new one.
3. New code, as small as possible.

Hand-rolled sanitizers, denylists, and regex validators are a last resort; say so when you propose
one.

Every diff is a proposal. Mark any fix that needs a migration, invalidates sessions/tokens/keys, or
breaks an API contract with **BREAKING** and a one-line rollout note, and stop there — those are
the user's call, not yours, and applying one unasked turns a review into an outage.

### 7. Parallelize large reviews

Above roughly 10 files or 4 vuln classes, dispatch one subagent per class with the Agent tool, in a
single message so they run concurrently. Give each agent: the exact file list, the one reference
file to load, and the instruction to return findings in the report-template finding format with
file:line evidence and the TRUE/FALSE/NEEDS-CONTEXT verdict. Then merge, dedupe findings that share
a root cause, and re-rank severity across the whole set yourself — per-class agents systematically
over-rate their own class.

### 8. Report

Output with `references/report-template.md`. Always fill in "what was not reviewed" — an unscoped
review implies coverage you did not provide.

## Related

- `sast-scan` — runs scanners and triages findings; loads these references by name.
- `dep-audit` and the `dep-gate` hook — dependency and supply-chain enforcement.
