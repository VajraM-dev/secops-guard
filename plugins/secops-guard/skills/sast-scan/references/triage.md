# Triage guide

## Verdicts

- **TRUE**: an untrusted source reaches the sink, no effective control sits in between, and you can cite every hop as `file:line`.
- **FALSE**: name the heuristic below that rules it out.
- **NEEDS-CONTEXT**: the decision depends on something outside the code you can see: deployment, the caller,
  config, or an upstream gateway. Write the exact question for the user.

## False-positive heuristics (check in order)

1. **Not reachable.** Dead code, test code, a fixture, an example, a migration that ran once,
   or a dev-only script that is not shipped. Lower the finding. Do not dismiss secrets in tests if they look real.
2. **Not attacker-controlled.** The value is a constant, an enum, server config, a value from a trusted internal
   service, or the output of the app's own validated model (for example a Pydantic `strict` model with `Literal`
   or `constr(pattern=...)`).
3. **Safe API.** The query is parameterised (`?`, `%s` with args, ORM filter kwargs). The subprocess call uses an
   arg list with `shell=False`. Jinja2/React auto-escape is on and `|safe` / `dangerouslySetInnerHTML` is not used.
   The deserializer is `yaml.safe_load` or `json`. The path is joined, `resolve()`d, then checked against a base dir.
4. **Effective sanitiser.** An allowlist or type coercion (`int()`, UUID parse) sits between source and sink.
   A denylist or regex blacklist is **not** effective: treat it as no control.
5. **Framework control.** CSRF middleware is on for cookie-auth routes. An ORM-level tenant filter is applied globally.
   An authz decorator or dependency sits on the route. Verify it actually covers this route.
6. **Placeholder secret.** `changeme`, `xxx`, `<token>`, `your-key-here`, `example`, all-same characters,
   documented test keys (`AKIAIOSFODNN7EXAMPLE`, Stripe `sk_test_`), or a value read from env at that line.
7. **Weak crypto in a non-security use.** MD5/SHA1 for cache keys or ETags, or `random` for jitter or sampling.
   These are FALSE. The same primitives for passwords, tokens, signatures, or IDs that grant access are TRUE.

Rules of thumb:
- A sanitiser that is applied in one path but not another is TRUE for the other path.
- "Admin-only" is NEEDS-CONTEXT unless the admin check is visible.
- A client-side check is never a control.
- An LLM output or tool result that reaches a sink (SQL, shell, file path, URL fetch, HTML) is an
  untrusted source, the same as user input.

## Severity rubric (CVSS-lite)

Start from the **impact**. Then adjust by **exploitability**.

| Impact if exploited | Base |
|---|---|
| RCE, auth bypass to any account, read/write of all tenants' data, leaked prod secret with broad scope (cloud root, DB admin, signing key) | CRITICAL |
| Read/write of other users' data (IDOR), SSRF to internal network or metadata, stored XSS in a privileged view, SQLi on a limited DB user, path traversal to arbitrary file read | HIGH |
| Reflected XSS, CSRF on state-changing actions, open redirect used in an auth flow, info leak of internal details or PII of one user, DoS by a single request | MEDIUM |
| Missing hardening headers, verbose errors without secrets, weak crypto in a low-value context, best-practice gaps | LOW |

Adjustments, at most two steps in total:
- **Minus one**: needs an authenticated, privileged role. Needs user interaction plus an unlikely precondition.
  Reachable only from an internal network that you confirmed.
- **Minus one**: the impact is limited by a strong mitigating control (read-only DB user, sandboxed worker, egress blocked).
- **Plus one**: unauthenticated and internet-facing. Or the finding chains with another TRUE finding to raise its impact.
- Secrets: CRITICAL if live-looking and prod-scoped. HIGH if the scope is unknown. LOW only if clearly test/sandbox (`sk_test_`).

## Evidence (TRUE and HIGH+ only)

Prove a finding with source evidence, never with a live exploit:

1. **Chain.** Cite every hop as `file:line`: the untrusted source, each transform or missing check, and the sink.
2. **Missing control.** Name the control that should be there (parameterised query, allowlist, authz check)
   and the line where it belongs.
3. **Regression test (proposed).** Describe one unit or integration test that fails before the fix and passes
   after it. For example: "a request as user A for user B's invoice id returns 403", or
   "a filename containing a parent-directory segment resolves inside the upload root or is rejected".
   Write the test in the project's own test framework. Do not run it against anything but the local test suite.
   Use a neutral marker value in the test, not a working attack payload.

Do not send requests to any server, do not start services to attack them, and do not include ready-to-run
payloads in the report.
