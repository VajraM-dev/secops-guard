# Report template

Use this structure verbatim. Drop sections that are empty rather than writing "N/A" — except
**Residual risk** and **Not reviewed**, which are always filled in, because omitting them implies
coverage you did not provide.

Keep the whole report readable in one pass: findings ordered by severity, evidence as `file:line`,
one diff per finding.

---

````markdown
# Security review — <scope>

<One line: what was reviewed, against what baseline.>
Reviewed: <N files / commit range / endpoints>  ·  Date: <YYYY-MM-DD>

| Severity | TRUE | NEEDS-CONTEXT |
|---|---|---|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 0 | 0 |
| Low | 0 | 0 |

<One or two sentences: the headline. If there is one thing to fix today, name it here.
If nothing was found, say that plainly and point at Residual risk.>

---

## F-1 — <short title> · <Critical|High|Medium|Low> · <TRUE|NEEDS-CONTEXT>

**Class:** <SQL injection / Broken object-level authorization / …> · **CWE:** CWE-nn
**Severity:** <band> (impact <n> x exploitability <n> x exposure <n> = <score><, +1 band: reason>)
**Location:** `path/to/file.py:120-134`<, and 3 more — see Locations>

**Evidence chain**
1. Source — `routes/documents.py:41` — `doc_id` from the path, no constraint beyond `str`.
2. Hop — `services/documents.py:77` — passed straight to the repository.
3. Sink — `repo/documents.py:19` — `select(Doc).where(Doc.id == doc_id)`; no tenant predicate.
4. Why controls do not stop it — `require_role("viewer")` at `routes/documents.py:38` proves the
   caller is *a* user, not that they own this document. No row-level policy on the table
   (`migrations/0007_*.py`).

**Impact** <One or two lines: what an attacker gets, concretely.>

**Fix** <Which control and why this one. Prefix with **BREAKING** and add a one-line rollout
note if it needs a migration, invalidates sessions/tokens/keys, or changes an API contract —
those are proposals for the user to accept, not changes to apply.>

```diff
- stmt = select(Doc).where(Doc.id == doc_id)
+ stmt = select(Doc).where(Doc.id == doc_id, Doc.tenant_id == user.tenant_id)
```

**Test** <One test that fails before and passes after.>

```python
async def test_cross_tenant_document_is_404(client, doc_in_other_tenant):
    r = await client.get(f"/api/v1/documents/{doc_in_other_tenant.id}")
    assert r.status_code == 404
```

**Locations** <Only when the same root cause appears in several places.>
- `repo/documents.py:19`
- `repo/comments.py:31`

---

## F-2 — … <repeat per finding>

---

## Cleared (FALSE)

Leads checked and dismissed, with the control that dismisses them. Short — one line each.

| Lead | Why it is not a finding |
|---|---|
| `text()` at `repo/stats.py:22` | Bound parameters only; the sole interpolated value is an enum validated at `schemas.py:12` |
| `dangerouslySetInnerHTML` at `Post.tsx:60` | Input passes `DOMPurify.sanitize` at `Post.tsx:54` |

## Residual risk

What stays risky even after every fix above lands. Include the global controls the whole review
leaned on, because if one regresses, many findings come back at once.

- Tenant isolation depends entirely on the base repository scoping at `repo/base.py:28`; any query
  written outside it reopens F-1's class. Consider row-level security as a backstop.
- No rate limit on authentication routes; out of scope here, tracked separately.

## Not reviewed

- <Paths, services, or layers excluded, and why.>
- <Infrastructure assumed but unverified: WAF, egress policy, TLS termination, IAM.>
- <Dependencies: say whether `/secops-guard:dep-audit` was run, or that it was not.>
- Dynamic behavior: this was a source review; no running system was exercised beyond <local tests>.
````

---

## Writing notes

- **Order findings by severity**, then by fix cost within a band — the reader works top-down.
- **One finding per root cause.** Five routes missing the same dependency is one finding with five
  locations; five separate entries bury the actual fix.
- **Diffs stay minimal.** Show the lines that change plus a line of context. A diff longer than
  about 15 lines means the fix needs prose, not a patch.
- **Name the framework control** in the fix ("use `select().where()` with the tenant predicate",
  "use `defusedxml.ElementTree`"), not a hand-rolled sanitizer, unless no control exists.
- **NEEDS-CONTEXT findings** state the one question that resolves them and who can answer it. They
  are not filler: a reviewer who lists three precise open questions is more useful than one who
  guesses.
- **No finding without `file:line`.** If you cannot cite it, it is not ready to publish.
