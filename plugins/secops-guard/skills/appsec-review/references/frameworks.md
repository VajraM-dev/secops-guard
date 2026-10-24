# Framework secure defaults, and how they get disabled

Most real bugs are not missing controls — they are a framework default that someone turned off,
usually to fix a symptom ("the HTML was escaped", "CORS was blocking me", "the type check failed").
Check the defaults first; the "how it breaks" column is the grep list.

## FastAPI / Starlette

| Area | Default | How it breaks |
|---|---|---|
| Input validation | Pydantic model validation on typed params | `dict`/`Any`/`Request` body read raw with `await request.json()`; no `extra="forbid"`, so extra fields silently pass to a `**data` constructor |
| Authz | **None.** No implicit auth; every route is public until a dependency says otherwise | A new route added without `Depends(require_*)`. There is no global default — `dependencies=[...]` on the router or app is the only way to make it one |
| SQL | Nothing; SQLAlchemy's job | See below |
| HTML | Nothing; returns JSON. `HTMLResponse`/`Jinja2Templates` is opt-in | `HTMLResponse(f"<p>{x}</p>")` |
| CSRF | **None at all** | Cookie auth added later without `SameSite` or an Origin check — see `csrf.md` |
| CORS | Off until `CORSMiddleware` is added | `allow_origins=["*"]` with `allow_credentials=True` (Starlette refuses to send the wildcard with credentials, so people "fix" it by reflecting the Origin, which is the actual vuln); `allow_origin_regex` that forgets to anchor (`.*\.example\.com` matches `evil-example.com.attacker.tld`) |
| Errors | Generic 500, no traceback in the response | `debug=True` in production; a custom handler that returns `str(exc)` |
| Docs | `/docs` and `/openapi.json` are public | Left public on an internal service — Info, not a finding by itself |
| Body size | **No limit** (ASGI server may impose one) | Unbounded upload / JSON bomb; limit at the proxy and validate `content-length` |
| Headers | None | `security_headers_middleware` never wired; see the house `security` skill |

Dependency order matters: a `Depends` that raises 403 runs before the handler, but a middleware
that catches exceptions broadly can swallow it. Check the middleware stack in `main.py`.

## SQLAlchemy 2.x

| Area | Default | How it breaks |
|---|---|---|
| Parameterization | ORM `select().where()` and `text(":p")` bind parameters | f-string into `text()`; `.filter(text(f"..."))`; `exec_driver_sql` |
| Identifiers | Not parameterizable at all | Dynamic `ORDER BY`/table/column from user input — needs an allowlist mapped to column objects, nothing else works |
| Tenant scoping | None | A query written outside the base repository; `session.get(Model, id)` which is PK-only by construction |
| Lazy loading | Emits queries on attribute access | Not a security bug, but it hides queries from the reviewer — read the model too |
| `autoflush` / transactions | Session-scoped | A read-modify-write across requests without a lock; see `race-conditions.md` |

## Pydantic v2

| Area | Default | How it breaks |
|---|---|---|
| Extra fields | `extra="ignore"` — silently dropped | Fine for input, dangerous when the model is then `.model_dump()`ed into an ORM constructor. Use `extra="forbid"` on request models |
| Coercion | Lax by default (`"1"` → `1`) | `strict=True` is opt-in; lax mode plus a union can pick a surprising member |
| Secrets | `SecretStr` masks `repr` only | `.get_secret_value()` passed to a logger or an LLM prompt |
| Bounds | None unless declared | No `max_length` on a free-text field reaching a prompt, a filename, or a query |
| Validators | Run in field order; `model_validator(mode="after")` last | A validator that only runs on `mode="before"` and is skipped by `model_construct()` |

Rule of thumb: separate the request model from the DB model. Mass assignment is the whole reason.

## Django

| Area | Default | How it breaks |
|---|---|---|
| Templates | Autoescaping **on** | `{{ x|safe }}`, `{% autoescape off %}`, `mark_safe()`, `format_html` with an unescaped arg |
| CSRF | `CsrfViewMiddleware` on | `@csrf_exempt`, or middleware removed from `MIDDLEWARE` |
| SQL | ORM parameterizes | `.raw()`, `.extra()`, `RawSQL`, `connection.cursor().execute(f"...")` |
| Clickjacking | `XFrameOptionsMiddleware` on | Removed, or `@xframe_options_exempt` |
| Passwords | PBKDF2, strong | A custom hasher |
| Cookies | `SESSION_COOKIE_HTTPONLY=True` | `SECURE=False` in prod, `SAMESITE=None` |
| Debug | `DEBUG=False` in the deploy checklist | `DEBUG=True` with `ALLOWED_HOSTS=["*"]` |
| Authz | **None per-view** | Missing `@login_required`/`PermissionRequiredMixin`; object-level checks are always hand-written |

`python manage.py check --deploy` catches most of the config half; run it before hand-auditing.

## Flask

| Area | Default | How it breaks |
|---|---|---|
| Templates | Jinja autoescape on for `.html`/`.htm`/`.xml` only | A `.txt` or string template; `Environment()` constructed directly (autoescape defaults to **False**); `render_template_string` with user input = SSTI |
| Sessions | Signed cookie, **not encrypted** | Putting secrets in `session`; a weak or committed `SECRET_KEY` |
| CSRF | None (needs Flask-WTF) | Assumed present because Django has it |
| Debug | Off | `debug=True` exposes the Werkzeug console = RCE |

## Express

| Area | Default | How it breaks |
|---|---|---|
| Headers | None | `helmet()` not installed |
| Body | `express.json()` has a 100kb limit | `limit: '50mb'` copy-pasted |
| CORS | None | `cors()` with no options = reflect any origin |
| SQL | Driver-dependent | String-concatenated queries; `knex.raw` with interpolation |
| Templates | Engine-dependent | EJS `<%- %>` (unescaped) vs `<%= %>` |
| Errors | Stack trace in dev only (`NODE_ENV`) | `NODE_ENV` unset in the container |
| Authz | None | Middleware applied with `app.use` *after* the route it was meant to protect — order is everything |
| Prototype pollution | `req.query`/`req.body` are plain objects | `lodash.merge`/`Object.assign` of a request body into config or a user record |

## Next.js / React

| Area | Default | How it breaks |
|---|---|---|
| JSX text | Escaped | `dangerouslySetInnerHTML` |
| URLs | Not validated | `<a href={userUrl}>` with a `javascript:` or `data:` URL |
| Env vars | Server-only unless prefixed | `NEXT_PUBLIC_` on a secret ships it to the browser |
| Server actions | POST-only, framework-generated ids; same-origin checked | Treated as authenticated — they are **not**; every action re-checks auth and authz itself, exactly like a route |
| Route handlers | No auth | Middleware `matcher` that misses a path; auth in middleware only, with the handler trusting it |
| `getServerSideProps` / RSC | Runs server-side | Returning the whole DB row, including fields the client should not see — over-fetch becomes disclosure |
| Images / rewrites | — | `next.config` `remotePatterns`/rewrites with a wildcard host = an SSRF proxy |

## Celery

- Serializer: `json` by default since 4.0 — `pickle` in config is RCE on any broker write access.
- Broker credentials and task payloads are often logged; payloads are a trust boundary if anything
  outside the app can enqueue.
- `acks_late` + retries means a task can run twice: side effects need idempotency keys.

## LangChain / LangGraph

| Area | Default | How it breaks |
|---|---|---|
| Prompts | `ChatPromptTemplate` input variables are substituted, not interpreted | Building the template with an f-string over user text |
| Tools | Every bound tool is callable on any turn | No per-agent allowlist; a destructive tool bound "just for testing" |
| Side effects | No approval gate | No `interrupt` / human-in-the-loop before payment, email, delete, write, shell |
| Identity | Tools run with the service account | Taking `user_id` from the model's tool arguments instead of the request context |
| Output | Free text | Fed to `eval`, SQL, shell, or `dangerouslySetInnerHTML` without parsing into a validated model |

See `llm-prompt-injection.md`. The controls live outside the model; prompt wording is not one.

## Quick config sweep

```bash
rg -n 'debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\(.*debug'      # debug mode
rg -n 'allow_origins\s*=\s*\[\s*"\*"|cors\(\)|allow_origin_regex' # CORS
rg -n 'verify\s*=\s*False|rejectUnauthorized:\s*false'            # TLS off
rg -n 'csrf_exempt|csrf.*False|SAMESITE.*None'                    # CSRF off
rg -n 'autoescape\s*=\s*False|\|safe|mark_safe|dangerouslySetInnerHTML'  # escaping off
rg -n 'NEXT_PUBLIC_\w*(SECRET|KEY|TOKEN|PASSWORD)'                # leaked to the client
rg -n 'task_serializer|CELERY_TASK_SERIALIZER' -A1                # pickle broker
```

Each hit is a lead. Confirm it is reachable and that no other control covers it before calling it
a finding — see `methodology.md`.
