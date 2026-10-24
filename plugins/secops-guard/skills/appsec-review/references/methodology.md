# Review methodology

How to run the pass itself. The goal is coverage you can defend, not a long list.

## The one rule

A finding is a **path**, not a pattern. Source (where untrusted data enters) → hops (what it passes
through) → sink (what it makes happen) → why the existing controls do not stop it. If you cannot
name all four, you have a lead, not a finding. Every grep in the class references exists to produce
leads; the trace is what turns one into a finding.

## 0. Orient (5 minutes, before reading any code)

```bash
git diff --stat <base>...HEAD            # what changed
git log --oneline <base>...HEAD          # why
rg -n 'router|@app\.|app\.(get|post|put|delete)|@task|@tool' --glob '!test*'   # entry points
```

Read, in this order: the dependency manifest (what framework and version), the app factory /
`main.py` (what middleware is wired), the auth dependency (what "authenticated" means here), the
base repository or DB session helper (whether tenant scoping is default). Those four files tell you
which controls exist globally, which is what lets you clear most leads quickly later.

## 1. Map trust boundaries

A trust boundary is any place data crosses from something you do not control into something you do.
List each one in scope with: what crosses it, what validates it, what it reaches.

Typical boundaries, in rough order of how often they are the bug:

| Boundary | Untrusted thing | Usually missing |
|---|---|---|
| HTTP request → handler | Body, query, path params, headers, cookies, uploaded files | Strict schema; size limits |
| Handler → data layer | Object ids, filters, sort fields | Ownership/tenant predicate in the query |
| App → database (raw SQL) | Any string that reaches `text()` | Bound parameters |
| App → shell / filesystem | Paths, filenames, args | Allowlist, resolve-and-contain |
| App → outbound HTTP | User-supplied URL | Host allowlist, no redirects |
| DB/cache/queue → app | Stored strings, pickled payloads | Treating stored data as trusted |
| App → browser | Any value rendered | Context-correct escaping |
| Model/LLM → app | Tool args, generated text, generated SQL | Output validation, tool allowlist |
| Third party → app | Webhooks, OAuth callbacks, SSO assertions | Signature verification, replay defense |
| Registry/CI → build | Dependencies, actions | Pinning, lockfile, integrity |

Internal service-to-service calls are a boundary too, unless there is mTLS or a signed token and
the callee verifies it. "It's behind the VPC" is a network control, not an authorization control —
note it as a compensating control, not as a reason to skip the check.

## 2. Per-boundary checklist

For each boundary, answer these. A "no" is a lead; an "I can't tell" is NEEDS-CONTEXT.

**Identity and authorization**
- Is the caller authenticated, and where is that enforced — a global dependency, or per-route?
- Is there an *object-level* check, and is it in the query (`WHERE ... AND tenant_id = :t`) rather
  than an `if` after the fetch?
- Can the client set a field it should not (role, owner_id, price, status)? Is the request model
  separate from the DB model, with `extra="forbid"`?

**Input**
- Is there a schema, is it strict, and does it bound sizes/lengths/ranges?
- Are enums enums, or free strings compared later?
- Is there a request body size limit and an upload size/type limit?

**Processing**
- Which sinks does this data reach? (query, shell, filesystem, URL fetch, deserializer, template,
  LLM prompt, logger.) Walk each one.
- Is any decision check-then-act under concurrency?
- Is any arithmetic money or quota, and is it `Decimal`/integer-minor-units with a DB constraint?

**Output**
- Escaping correct for the context it lands in (HTML body vs attribute vs JS vs URL vs SQL)?
- Does the response leak more than the caller should see — other tenants' fields, internal ids,
  stack traces, timing differences that enumerate users?
- Do logs/traces/LLM prompts contain secrets or PII?

**Failure**
- What happens on exception — does it fail closed? A `try/except: pass` around an authz check, or a
  middleware that returns the response when the verifier throws, is a full bypass.

## 3. Order of attack on an unfamiliar codebase

Highest yield per minute, in order:

1. **Routes with no authz dependency.** Enumerate routes, diff against routes that declare a
   `Depends(require_*)`. The gap list is usually short and usually has one real bug.
2. **Raw SQL.** `rg -n 'text\(|execute\(|\$queryRawUnsafe|\.raw\('`.
3. **Sinks with any dynamic argument**: `subprocess`, `open(`, `eval`, `pickle`, `yaml.load`,
   `requests.get(`/`httpx.get(` on a variable, `dangerouslySetInnerHTML`.
4. **The auth code itself** — one bug there outranks everything else.
5. **Anything the diff touched that the tests do not cover.**
6. **Config**: CORS, cookie flags, debug mode, `verify=False`, default credentials.

## 4. Clearing leads honestly

Most leads die. Kill them explicitly and cite the control:

- "Parameterized at `repo/users.py:44`" → FALSE.
- "Value comes from an enum validated by `Pydantic` at `schemas.py:12`" → FALSE.
- "Reachable only from an internal Celery task whose payload we produce" → FALSE, but note it
  becomes TRUE if that queue ever accepts external input.
- "Caller is in a repo I cannot see" → NEEDS-CONTEXT, say what would resolve it.

Keep a running list of the global controls you confirmed (auto-escaping on, strict Pydantic
everywhere, tenant scoping in the base repository). It is both fast triage and the honest content
of the report's "residual risk" section — those controls are the reason the other findings are not
findings, so if one of them regresses, a lot regresses at once.

## 5. Verifying without attacking anything

Allowed, in order of preference:

1. Read the code path again, end to end, including the middleware stack.
2. Write a unit/integration test against the **local** app that asserts the unsafe behavior — it
   fails today and passes after the fix. This is the strongest evidence and it ships with the fix.
3. Run the app locally and exercise your own endpoint with a benign marker value.

Never run anything against staging, production, a shared environment, or a third-party host.

## 6. Budgeting

| Scope | Approach |
|---|---|
| 1-3 files, one feature | Inline, 2-4 classes, no subagents |
| A PR, up to ~10 files | Inline, full boundary pass, pick classes from the diff |
| A service or a first-time audit | One subagent per class in parallel, then merge and re-rank |
| "Review the whole monorepo" | Scope it down with the user first; an unscoped review is a false promise |

When merging subagent output: dedupe by root cause (five routes missing the same dependency is one
finding with five locations), re-score severity across the whole set, and drop any finding whose
evidence chain does not survive your own reading.
