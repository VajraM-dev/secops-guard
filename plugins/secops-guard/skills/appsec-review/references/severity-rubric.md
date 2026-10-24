# Severity rubric (CVSS-lite)

CVSS vectors are slow and argued about. This rubric gets a defensible number in under a minute and,
more importantly, ranks findings consistently against each other — which is what the reader uses it
for.

## Score

```
score = impact x exploitability x exposure
```

### Impact — what the attacker gets

| | Value | Means |
|---|---|---|
| Critical | 5 | RCE, full DB read/write, auth bypass as any user, key material disclosure |
| High | 4 | Another tenant's or user's data read or modified; privilege escalation to admin |
| Medium | 3 | Limited data disclosure (one record, metadata), state change within the user's own scope that should not be possible, stored XSS in a shared view |
| Low | 2 | Information leak with no direct use (version strings, internal ids), self-XSS, DoS of own session |
| Info | 1 | Hardening gap with no demonstrated effect |

### Exploitability — what it takes

| | Value | Means |
|---|---|---|
| Trivial | 3 | One crafted request, no special state, no race, works first try |
| Moderate | 2 | Needs a specific valid id, a second account, a known-value guess, a narrow race window, or user interaction (a click on a link you control) |
| Hard | 1 | Needs a long race, brute force over a large space, local access, or a prior unrelated compromise |

### Exposure — who can reach it

| | Value | Means |
|---|---|---|
| Public | 3 | Unauthenticated internet-reachable endpoint |
| Authenticated | 2 | Any registered user, including self-signup |
| Privileged / internal | 1 | Admin-only, internal network only, or reachable only by a trusted job |

### Band

| Score | Severity | Expectation |
|---|---|---|
| 30-45 | **Critical** | Fix now; consider whether it has already been exploited |
| 16-29 | **High** | Fix this sprint; do not ship the feature with it |
| 8-15 | **Medium** | Fix before the next release |
| 4-7 | **Low** | Backlog with a date |
| 1-3 | **Info** | Note it; fix if the file is open anyway |

## Adjustments

Apply at most one or two, and say in the finding that you did.

- **+1 band** if it is already in production, or if exploitation leaves no trace in logs.
- **+1 band** if the data is regulated (PHI, payment, credentials) — breach cost is not linear.
- **-1 band** if a deployed compensating control genuinely narrows it (WAF rule, egress deny-all,
  endpoint only reachable from one allowlisted IP). Name the control; "we have a WAF" alone is not
  one, because a WAF stops generic payloads, not logic.
- **No adjustment** for "the attacker would need to know our schema" or "the UI doesn't expose it".
  Obscurity is not exposure.

## Worked examples

**1. Tenant id missing from the query**
`GET /api/v1/documents/{id}` fetches by primary key only; any logged-in user reads any tenant's
document. Impact High (4, cross-tenant read) x Trivial (3, change one number) x Authenticated (2)
= **24 → High**. Regulated customer data would push it to Critical.

**2. f-string into `text()` on an admin report**
Admin-only endpoint concatenates a date filter into raw SQL. Impact Critical (5, full DB read via
the DB role) x Trivial (3) x Privileged (1) = **15 → Medium**, and worth saying out loud that this
is only Medium because of exposure — if the route ever loses its admin dependency it is Critical.
Fix is one line, so fix it regardless of band.

**3. Reflected XSS on the public marketing search page**
Impact Medium (3, session theft needs the victim logged in and the cookie is `HttpOnly`,
so realistically phishing/defacement) x Moderate (2, needs a click) x Public (3) = **18 → High**.
Drop impact to 2 and it is Medium — state the assumption you made about cookie flags.

**4. `pickle.loads` on a Redis cache value**
Impact Critical (5, RCE) x Hard (1, requires Redis access first) x Internal (1) = **5 → Low** by
score. This is the case where the score under-reads the risk: note it as Low-with-a-caveat, because
it converts any future Redis exposure or SSRF into RCE. Fix cost is one line (`json`), so the band
should not decide this.

**5. Password reset token is `random.randint(100000, 999999)`, 60-minute expiry, no attempt limit**
Impact Critical (5, account takeover) x Trivial (3, 10^6 space with no lockout is one short script)
x Public (3) = **45 → Critical**.

**6. Missing `SameSite` on the session cookie, API also accepts a bearer token**
Impact Medium (3, state change as the victim) x Moderate (2, needs a click) x Authenticated (2)
= **12 → Medium**. If every state-changing route also requires a custom header the browser will not
send cross-site, this is FALSE, not a Low.

**7. Unpinned third-party GitHub Action in the release workflow**
Impact Critical (5, build and secrets compromise) x Hard (1, requires compromising the action's
repo or tag) x Internal (1) = **5 → Low**, +1 band for "no trace in logs" → **Medium**. Pinning to
a SHA is cheap; recommend it as Medium with a one-line fix.

## Calibration notes

- Score findings relative to each other before you publish. If your list has six Highs and nothing
  else, the ranking has told the reader nothing.
- Fix cost belongs in the fix section, not the severity. A trivial fix for a Low is still a Low —
  but say "one-line fix" so it gets done.
- NEEDS-CONTEXT findings get a **provisional** severity with the assumption stated:
  "High *if* this route is reachable without the admin dependency — confirm at `routes.py:88`."
- Chained findings: score the chain as one finding at the chain's impact, and list the links. Two
  Mediums that compose into account takeover are one Critical.
