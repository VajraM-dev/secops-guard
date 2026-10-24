# Cross-Site Scripting (XSS)

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation), CWE-80 (Improper Neutralization of Script-Related HTML Tags), CWE-116 (Improper Encoding or Escaping of Output)

Untrusted data reaches the browser in a context where it is parsed as markup or script. Reflected (from the request), stored (from the database), or DOM-based (written client-side by JS).

## How it gets introduced

- A FastAPI handler returns `HTMLResponse(f"<p>{user_input}</p>")` — no template engine, no escaping.
- Jinja2 autoescape is off: bare `Environment()` defaults to `autoescape=False`, and `select_autoescape()` does not cover `.txt`, `.md`, `.csv` or `.xml` templates that later get rendered into HTML or email.
- `|safe`, `Markup(...)`, `{% autoescape false %}` applied to a value that is user-controlled anywhere up the chain.
- React `dangerouslySetInnerHTML={{ __html: value }}`, or raw DOM writes: `el.innerHTML`, `insertAdjacentHTML`, `document.write`, `$(el).html()`.
- `href={userUrl}` / `src={userUrl}` where the value can be `javascript:` or `data:text/html`; the same for `<a href>` built in a template.
- User markdown rendered to HTML and inserted without sanitizing; `marked`/`markdown-it` configured with `html: true`.
- Server data embedded in a `<script>` tag with `JSON.stringify` alone, which does not escape `</script>`, `<!--`, U+2028 or U+2029.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
from jinja2 import Environment, FileSystemLoader  # autoescape defaults to False

env = Environment(loader=FileSystemLoader("templates"))

@app.get("/search", response_class=HTMLResponse)
async def search(q: str):
    return HTMLResponse(f"<h1>Results for {q}</h1>")
```

```python
# fixed
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
import nh3  # Rust ammonia binding; bleach is the older equivalent

templates = Jinja2Templates(directory="templates")          # autoescape on for html/xml
templates.env.autoescape = select_autoescape(
    enabled_extensions=("html", "htm", "xml", "txt", "md"),  # cover text templates that end up in HTML/email
    default_for_string=True,
)

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: Annotated[str, Query(max_length=200)]):
    # q is escaped by the template; never pre-wrap it in Markup()
    return templates.TemplateResponse(request, "search.html", {"q": q})

@app.post("/comments")
async def create_comment(body: CommentIn, session: AsyncSession = Depends(get_session)):
    # sanitize rendered markdown ONCE, on write, with an allowlist; store the clean HTML
    html = nh3.clean(
        markdown.markdown(body.text),
        tags={"p", "br", "strong", "em", "code", "pre", "ul", "ol", "li", "a", "blockquote"},
        attributes={"a": {"href", "title", "rel"}},
        url_schemes={"http", "https", "mailto"},   # drops javascript: and data:
        link_rel="nofollow noopener noreferrer",
    )
    session.add(Comment(html=html))
```

In the template, `{{ comment.html | safe }}` is acceptable only because the value was sanitized by `nh3` at write time; everything else stays unmarked.

## JS / TS / Node / React

```tsx
// vulnerable
export function Profile({ bio, site }: Props) {
  return (
    <>
      <div dangerouslySetInnerHTML={{ __html: bio }} />
      <a href={site}>homepage</a>  {/* site = "javascript:fetch('/api/keys')..." */}
    </>
  );
}
```

```tsx
// fixed
import DOMPurify from "dompurify";

const SAFE_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

function safeHref(raw: string): string | undefined {
  try {
    const u = new URL(raw, window.location.origin);
    return SAFE_PROTOCOLS.has(u.protocol) ? u.href : undefined;
  } catch {
    return undefined;
  }
}

export function Profile({ bio, site }: Props) {
  const href = safeHref(site);
  return (
    <>
      {/* plain children are escaped by React; only sanitized HTML may bypass that */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio, { USE_PROFILES: { html: true } }) }} />
      {href ? <a href={href} rel="noopener noreferrer">homepage</a> : <span>{site}</span>}
    </>
  );
}
```

Server state in the page:

```ts
// vulnerable — JSON.stringify leaves "</script>", "<!--", U+2028 and U+2029 intact
res.send(`<script>window.__STATE__ = ${JSON.stringify(data)}</script>`);
```

```ts
// fixed — a non-executable data block, parsed by the client
res.send(
  `<script id="state" type="application/json">` +
    serialize(data) +            // devalue / serialize-javascript; do not hand-roll the escaping
    `</script>`,
);
// client: JSON.parse(document.getElementById("state").textContent)
```

In React/Next.js, pass the data as props and let the framework serialize it; do not build a `<script>` string.

## The safe API, per framework

| Framework | Use |
|---|---|
| Jinja2 / FastAPI | `Jinja2Templates` + `select_autoescape`; never `Markup`/`\|safe` on raw input |
| FastAPI JSON | default `JSONResponse` — no HTML context, nothing to escape |
| React / Next.js | JSX children (auto-escaped); `dangerouslySetInnerHTML` only with DOMPurify output |
| Next.js | props + framework serialization; `next/script`, never a string-built `<script>` |
| Vanilla DOM | `textContent`, `setAttribute`, `el.append(node)` — never `innerHTML` |
| URLs | `new URL()` + protocol allowlist before a value reaches `href`/`src`/`formaction` |
| Markdown | `nh3`/`bleach` (Python) or DOMPurify (JS) after rendering; `html: false` in the renderer |
| Headers | `Content-Security-Policy` with nonces, `X-Content-Type-Options: nosniff` |

CSP is defense in depth. A strict nonce-based CSP limits the blast radius; it does not make unescaped output correct, and it does not stop injected markup such as a phishing form that needs no script.

## Grep for

```
rg -n 'HTMLResponse\(\s*f["\x27]'                      # f-string HTML built in a handler
rg -n 'media_type=["\x27]text/html'                    # hand-built HTML response — check how the body was made
rg -n 'Environment\(' -g '*.py' -A2 | rg -v autoescape # Jinja2 Environment with autoescape left off
rg -n '\|\s*safe\b|\{%-?\s*autoescape\s+false'         # explicit escaping bypass in a template
rg -n 'Markup\(|markupsafe\.Markup'                    # marks a string as trusted HTML
rg -n 'dangerouslySetInnerHTML'                        # every hit needs a sanitizer on the same value
rg -n '\.innerHTML\s*=|insertAdjacentHTML|document\.write\(|\.html\('  # raw DOM sinks
rg -n '(href|src)=\{[a-zA-Z_]'                         # URL from a variable — check the protocol
rg -n 'marked\(|markdown-it|markdown\.markdown\(' -A2 | rg -v 'sanitize|nh3|bleach|DOMPurify'  # unsanitized markdown
rg -n '<script[^>]*>[^<]*\$\{|JSON\.stringify\([^)]*\)\s*\}\s*</script'  # JSON inlined into a script tag
rg -n 'DOMPurify\.sanitize\([^)]*(ADD_ATTR|ADD_TAGS|ALLOWED_URI_REGEXP)' # weakened sanitizer config
```

## False positives

- `dangerouslySetInnerHTML` fed by `DOMPurify.sanitize(...)` in the same expression, or by a build-time constant / MDX compiled from repo files.
- `|safe` on a value produced by `nh3.clean` / `bleach.clean` at write time, or on template-authored markup containing no request data.
- `innerHTML = ""` and `innerHTML = SOME_CONSTANT` — an empty or literal assignment injects nothing.
- `href={url}` where `url` came through a Pydantic `HttpUrl`/`AnyHttpUrl` field or an upstream `new URL()` protocol check.
- JSON returned by a FastAPI/Express JSON endpoint and consumed with `fetch` — never parsed as HTML.
- `Markup("").join(...)` over fragments that each went through `escape()`.

## Regression test

```python
# tests/test_xss.py
import pytest

PAYLOAD = "<img src=x onerror=alert(1)>"

@pytest.mark.anyio
async def test_reflected_search_is_escaped(client):
    r = await client.get("/search", params={"q": PAYLOAD})
    assert r.status_code == 200
    assert PAYLOAD not in r.text              # the raw tag must not survive
    assert "&lt;img" in r.text                # it came back as text

@pytest.mark.anyio
async def test_stored_comment_is_sanitized(client, session):
    await client.post("/comments", json={"text": "[x](javascript:alert(1)) <script>alert(1)</script>"})
    html = await session.scalar(select(Comment.html))
    assert "<script" not in html
    assert "javascript:" not in html
```

```tsx
// Profile.test.tsx (vitest + @testing-library/react)
import { render, screen } from "@testing-library/react";

it("does not render injected markup from a bio", () => {
  const { container } = render(<Profile bio='<img src=x onerror="alert(1)">' site="https://ok.test" />);
  expect(container.querySelector("img[onerror]")).toBeNull();
});

it("drops a javascript: homepage link", () => {
  render(<Profile bio="" site="javascript:alert(1)" />);
  expect(screen.queryByRole("link")).toBeNull();   // rendered as text, not as a link
});
```
