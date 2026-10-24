# CSRF and CORS

**CWE:** CWE-352 (Cross-Site Request Forgery), CWE-1275 (Sensitive Cookie with Improper SameSite), CWE-346 (Origin Validation Error), CWE-942 (Overly Permissive Cross-domain Policy)

CSRF exists only where the browser attaches credentials by itself. A site you do not control submits a request to yours, the browser adds the cookie, and the server cannot tell the difference.

**Scope first, before reporting anything.** CSRF applies when the credential is ambient: a session cookie, HTTP Basic, NTLM/Kerberos, or a client certificate. An API that authenticates solely from an `Authorization: Bearer` header that JS must attach is **not** CSRF-exposed — a cross-site page cannot read the token or make the browser add it. Do not file CSRF on a pure bearer-token API; file it the moment any route accepts a session cookie. A hybrid app (cookie for the web UI, bearer for mobile) is exposed on its cookie path.

## How it gets introduced

- The app moves from bearer tokens to cookie sessions (SSR, "remember me", an httpOnly refresh cookie) and no token check is added.
- FastAPI/Starlette is assumed to protect like Django; it has **no** built-in CSRF middleware at all.
- `SameSite=None` is set to make a third-party embed or a subdomain work, removing the only default protection.
- `@csrf_exempt` on a Django view to unblock a webhook or an AJAX call, and it stays.
- Express still mounts the deprecated `csurf`, or the token is generated but never compared.
- A state-changing action is served over `GET` (`/account/delete?id=5`), reachable by an `<img>` tag.
- CORS is opened up during debugging: `allow_origins=["*"]` with `allow_credentials=True`, or the Origin header reflected back verbatim.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
app.add_middleware(SessionMiddleware, secret_key=KEY)               # cookie session, no same_site
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"])     # Starlette silently drops the wildcard here

@app.post("/account/email")                                         # no CSRF token, no Origin check
async def change_email(body: EmailIn, u: User = Depends(current_user)): ...
```

```python
# fixed
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_key.get_secret_value(),
    https_only=True, same_site="lax",      # Lax is the baseline, not the whole control
)

ALLOWED = {"https://app.example.com"}      # explicit list; no "*", no reflection, no open regex
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(ALLOWED),
    allow_credentials=True,                # only ever valid with an explicit origin list
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["authorization", "content-type", "x-csrf-token"],
)

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

@app.middleware("http")
async def csrf(request: Request, call_next):
    """Origin check + synchronizer token. FastAPI ships neither."""
    if request.method in UNSAFE and request.cookies.get("session"):
        origin = request.headers.get("origin") or request.headers.get("referer", "")
        if not origin or urlparse(origin).scheme + "://" + urlparse(origin).netloc not in ALLOWED:
            return JSONResponse({"detail": "bad origin"}, 403)      # CWE-346
        sent = request.headers.get("x-csrf-token", "")
        expected = request.session.get("csrf")
        if not expected or not hmac.compare_digest(sent, expected): # constant time
            return JSONResponse({"detail": "csrf"}, 403)
    return await call_next(request)
```

Mint the token per session with `secrets.token_urlsafe(32)`, store it in the session, and hand it to the page (a `<meta>` tag or a non-httpOnly `XSRF-TOKEN` cookie the JS echoes into `X-CSRF-Token`). `fastapi-csrf-protect` does the same thing if a dependency is preferred.

**Never pair `allow_origins=["*"]` with `allow_credentials=True`.** Starlette ignores the wildcard in that combination (no origin is allowed, requests fail confusingly) and the browser would reject it anyway — the real-world "fix" people then apply is reflecting the Origin, which is the actual vulnerability (CWE-942). Reflecting `Origin` with credentials lets any site read authenticated responses. Also reject `Origin: null` (sandboxed iframes, `data:` URLs) and avoid regexes like `allow_origin_regex=r"https://.*\.example\.com"` — it matches `https://evil.example.com.attacker.tld` without an anchored `$`.

## JS / TS / Node / React

```ts
// vulnerable
app.use(cors({ origin: true, credentials: true }));   // origin:true reflects any Origin
app.use(session({ secret: S, cookie: { sameSite: "none", secure: true } }));
app.post("/api/transfer", requireSession, transfer);  // no token check
app.get("/api/account/delete", requireSession, del);  // state change on GET
```

```ts
// fixed
import { doubleCsrf } from "csrf-csrf";               // csurf is deprecated and unmaintained

app.use(cors({ origin: ["https://app.example.com"], credentials: true }));  // explicit allowlist
app.use(session({
  secret: process.env.SESSION_SECRET!,
  cookie: { httpOnly: true, secure: true, sameSite: "lax" },
}));

const { doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET!,
  getSessionIdentifier: (req) => req.session.id,      // binds the token to the session (signed double-submit)
  cookieName: "__Host-psifi.x-csrf-token",
  cookieOptions: { sameSite: "lax", secure: true, httpOnly: true },
});
app.use(doubleCsrfProtection);                        // mounted before the routes, not per-route

app.post("/api/transfer", requireSession, transfer);
app.delete("/api/account", requireSession, del);      // state change on a non-safe verb
```

Next.js: server actions carry a built-in Origin/Host check against `allowedOrigins`, which covers the common case — but a route handler (`app/api/*/route.ts`) that reads the session cookie gets no such protection and needs its own token or Origin check. Fastify: `@fastify/csrf-protection`.

Plain double-submit (cookie value echoed in a header, unverified) is weak: a subdomain XSS or a cookie-injection bug can set both halves. Prefer a signed/session-bound double-submit or a synchronizer token.

## The safe API, per framework

| Framework | Built-in control to use |
|---|---|
| FastAPI / Starlette | **None built in.** `SessionMiddleware(same_site="lax", https_only=True)` + an Origin check + a synchronizer token, or `fastapi-csrf-protect` |
| Django | `CsrfViewMiddleware` (on by default), `{% csrf_token %}`, `CSRF_TRUSTED_ORIGINS`; audit every `@csrf_exempt` |
| Flask | `Flask-WTF` `CSRFProtect` |
| Express | `csrf-csrf` (`doubleCsrf`) — `csurf` is deprecated |
| Fastify | `@fastify/csrf-protection` |
| Next.js | Server actions check Origin vs `allowedOrigins`; route handlers need their own check |
| Cookies, any stack | `SameSite=Lax` (or `Strict`), `Secure`, `httpOnly`, `__Host-` prefix |
| CORS, any stack | Explicit origin allowlist; `credentials` only with that list; never `*` + credentials, never reflection |

What `SameSite=Lax` does and does not cover: it blocks cross-site POST/PUT/PATCH/DELETE and cross-site subresource requests, so it kills classic form-POST CSRF. It still **allows top-level GET navigation**, so any state-changing GET remains exploitable. It is **not** an origin boundary — `SameSite` means same registrable domain, so `evil.example.com` is same-site with `app.example.com` and Lax gives you nothing against a compromised or user-controlled subdomain. Some clients also apply a two-minute "Lax + POST" grace window to brand-new cookies. Treat Lax as defence in depth and still check the token or Origin.

## Grep for

```
rg -n 'allow_origins\s*=\s*\[[\x27"]\*[\x27"]\]' -A3            # wildcard CORS: fatal if allow_credentials=True
rg -n 'allow_credentials\s*=\s*True' -B3 -A3                    # read the origin list right above it
rg -n 'allow_origin_regex\s*=' -A1                              # unanchored regex matches attacker domains
rg -n 'origin:\s*(true|\*|req\.headers\.origin)'                # Express CORS reflecting any Origin
rg -n 'Access-Control-Allow-Origin.*(\*|req\.|request\.)'       # header set by hand from the request
rg -n 'same_?site\s*[=:]\s*[\x27"]?[Nn]one'                     # SameSite=None removes the default protection
rg -n 'SessionMiddleware\((?!.*same_site)' -P                   # Starlette session with no SameSite set
rg -n '@csrf_exempt|csrf_exempt\(' -B2                          # Django view opted out of CSRF
rg -n 'CSRF_COOKIE_SECURE\s*=\s*False|CSRF_TRUSTED_ORIGINS'     # weakened Django CSRF config
rg -n 'require\([\x27"]csurf[\x27"]\)|from [\x27"]csurf[\x27"]' # deprecated csurf
rg -n '@(app|router)\.get\(.*(delete|remove|update|create|transfer|approve|reset)' -i  # state change on GET
rg -n 'methods\s*=\s*\[[\x27"]GET[\x27"]\]' -B2 -A5             # GET-only route that mutates
rg -n 'allowedOrigins'                                          # Next.js server action origin config
rg -n 'csrf' -i --glob '!**/node_modules/**' -l                 # is there any CSRF handling at all?
```

## False positives

- A stateless API whose every route takes `Authorization: Bearer` and sets no session cookie — not CSRF-exposed; say so and move on.
- `allow_origins=["*"]` with `allow_credentials=False` on a genuinely public, unauthenticated read API: no credentials ride along, so there is nothing to forge.
- A webhook receiver with `@csrf_exempt` that authenticates by HMAC signature over the raw body — that is its own, stronger check.
- A `GET` route whose name sounds mutating but only reads (`/get_delete_preview`, `/updates`).
- A route handler already behind a global CSRF middleware, so the per-route code shows no token check.
- `SameSite=None` on a cookie that carries no authority (a locale or theme cookie, an analytics id).
- A login form POST with no CSRF token where login CSRF is explicitly accepted — note it, do not rank it with account-takeover findings.

## Regression test

```python
# tests/test_csrf.py
import pytest

@pytest.mark.anyio
async def test_cookie_session_post_without_token_is_rejected(client, login_cookie):
    r = await client.post("/account/email", json={"email": "attacker@evil.test"},
                          cookies=login_cookie,
                          headers={"Origin": "https://evil.test"})
    assert r.status_code == 403            # forged cross-site POST refused

@pytest.mark.anyio
async def test_post_with_valid_token_and_origin_succeeds(client, login_cookie, csrf_token):
    r = await client.post("/account/email", json={"email": "me@example.com"},
                          cookies=login_cookie,
                          headers={"Origin": "https://app.example.com", "X-CSRF-Token": csrf_token})
    assert r.status_code == 200

@pytest.mark.anyio
async def test_cors_does_not_reflect_an_arbitrary_origin(client):
    r = await client.get("/api/me", headers={"Origin": "https://evil.test"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.test"
    assert r.headers.get("access-control-allow-origin") in (None, "https://app.example.com")

@pytest.mark.anyio
async def test_null_origin_is_rejected(client, login_cookie, csrf_token):
    r = await client.post("/account/email", json={"email": "x@y.test"}, cookies=login_cookie,
                          headers={"Origin": "null", "X-CSRF-Token": csrf_token})
    assert r.status_code == 403

@pytest.mark.anyio
async def test_session_cookie_is_lax_and_secure(client, creds):
    raw = (await client.post("/auth/login", json=creds)).headers["set-cookie"].lower()
    assert "samesite=lax" in raw and "secure" in raw and "httponly" in raw
```

```ts
// csrf.test.ts (vitest)
it("rejects a cross-site state change that carries only the session cookie", async () => {
  const res = await app.inject({
    method: "POST", url: "/api/transfer",
    headers: { cookie: sessionCookie, origin: "https://evil.test" },
    payload: { to: "attacker", amount: 100 },
  });
  expect(res.statusCode).toBe(403);
  expect(await balanceOf("victim")).toBe(startingBalance);   // assert no side effect, not the message
});
```
