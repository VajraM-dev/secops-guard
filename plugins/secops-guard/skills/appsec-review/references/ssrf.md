# Server-Side Request Forgery

**CWE:** CWE-918 (Server-Side Request Forgery), CWE-1385 (Missing Origin Validation / DNS Rebinding), CWE-610 (Externally Controlled Reference to a Resource in Another Sphere)

The server fetches a URL that a user controls, so the attacker borrows the server's network position — internal services, cloud metadata, localhost admin ports. A denylist of bad IPs does not hold; an allowlist plus egress control does.

## How it gets introduced

- A feature that takes a URL by design: webhook registration, "import from URL", link preview, avatar fetch, HTML-to-PDF rendering, OpenAPI/`$ref` fetchers, SAML/OIDC metadata URLs, LLM tools that browse.
- The URL is validated once (regex, `urlparse().hostname not in DENY`) then handed to the client, which re-resolves DNS at connect time — check and connection see different IPs.
- Redirects left on: `httpx.AsyncClient(follow_redirects=True)`, `requests.get` (on by default), `fetch` (default `redirect: "follow"`), axios (`maxRedirects: 5`). Hop one passes validation, hop two goes to `169.254.169.254`.
- A denylist of literal strings (`127.0.0.1`, `169.254.169.254`, `localhost`) that misses `[::1]`, `::ffff:127.0.0.1`, `2130706433`, `0177.0.0.1`, `0.0.0.0`, `127.1`, a DNS name resolving to a private IP, and the whole of `10/8`, `172.16/12`, `192.168/16`, `100.64/10`.
- Scheme never pinned (`file:///etc/passwd`, `gopher://`, `dict://`, `ftp://` reach the client), or a user segment concatenated into an internal base URL (`f"http://{tenant}.internal/v1"`).
- The response body, status, or latency is echoed to the user — that turns a blind SSRF into an internal port scanner.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
BLOCKED = {"localhost", "127.0.0.1", "169.254.169.254"}

@app.post("/import")
async def import_feed(url: str):
    if urlparse(url).hostname in BLOCKED:
        raise HTTPException(400, "blocked")
    async with httpx.AsyncClient(follow_redirects=True) as c:   # re-resolves; follows to metadata
        return (await c.get(url)).text   # body echoed back: full read SSRF
```

Fix in layers. Resolve, validate every resolved IP, then connect pinned to that IP so DNS cannot change under you; no redirects; strict scheme; small timeout and response cap.

```python
# fixed
import ipaddress, socket, anyio, httpx
from pydantic import BaseModel, HttpUrl, field_validator

ALLOWED_HOSTS = {"api.partner.test", "cdn.partner.test"}   # use this whenever the set is knowable
MAX_BYTES = 2 * 1024 * 1024

class ImportReq(BaseModel):
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def scheme_and_port(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme not in {"http", "https"} or v.port not in (None, 80, 443):
            raise ValueError("scheme or port not allowed")   # kills file://, gopher://, dict://
        return v

def _public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    a = a.ipv4_mapped or a                               # ::ffff:127.0.0.1 is loopback
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified or a in ipaddress.ip_network("100.64.0.0/10"))

async def resolve_checked(host: str, port: int) -> str:
    infos = await anyio.to_thread.run_sync(lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    ips = {i[4][0] for i in infos}
    if not ips or not all(_public(ip) for ip in ips):    # all, not any: a rebinding name returns both
        raise HTTPException(400, "host not allowed")
    return next(iter(ips))

@app.post("/import")
async def import_feed(req: ImportReq):
    host, port = req.url.host, req.url.port or (443 if req.url.scheme == "https" else 80)
    ip = await resolve_checked(host, port) if host not in ALLOWED_HOSTS else host
    # connect to the validated IP, keep SNI/Host on the real name: no second DNS lookup to race
    async with httpx.AsyncClient(
        follow_redirects=False,                          # httpx default is already False — keep it
        timeout=httpx.Timeout(5.0, connect=2.0),
        proxy="http://egress-proxy.internal:3128",       # the control that actually holds
    ) as c:
        r = await c.get(str(req.url).replace(host, ip, 1), headers={"Host": host}, extensions={"sni_hostname": host})
        if r.is_redirect:                                # re-validate each hop, bounded count
            raise HTTPException(400, "redirects not allowed")
        if int(r.headers.get("content-length") or 0) > MAX_BYTES: raise HTTPException(413, "too large")
    return {"ok": True}                                  # do not echo the body or the upstream status
```

Celery and background fetchers call the same function — never a second, looser fetch path for workers.

## JS / TS / Node / React

```ts
// vulnerable
app.post("/preview", async (req, res) => {
  const { url } = req.body;
  if (url.includes("169.254.169.254")) return res.status(400).end();
  const r = await fetch(url);              // redirect: "follow" by default
  res.send(await r.text());
});
```

```ts
// fixed
import dns from "node:dns/promises";
import ipaddr from "ipaddr.js";
const ALLOWED = new Set(["api.partner.test"]);

function isPublic(ip: string) {
  const a = ipaddr.parse(ip);
  const v4 = a.kind() === "ipv6" && (a as ipaddr.IPv6).isIPv4MappedAddress()
    ? (a as ipaddr.IPv6).toIPv4Address() : a;
  return v4.range() === "unicast";          // excludes loopback, private, linkLocal, carrierGradeNat, reserved
}

async function safeFetch(raw: string) {
  const u = new URL(raw);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("scheme");
  if (!ALLOWED.has(u.hostname)) {
    const ips = await dns.lookup(u.hostname, { all: true });
    if (!ips.length || !ips.every((i) => isPublic(i.address))) throw new Error("host");
  }
  return fetch(u, {
    redirect: "manual",                     // never "follow": validate each hop yourself
    signal: AbortSignal.timeout(5000),
    // @ts-expect-error undici option — pin the socket to a validated IP
    dispatcher: new Agent({ connect: { lookup: pinnedLookup(u.hostname) } }),
  });
}
```

axios: set `maxRedirects: 0` and check `status` yourself; `validateStatus` does not stop a redirect being followed.

## The safe API, per framework

| Stack | Control |
|---|---|
| httpx | `follow_redirects=False` (the default — do not turn it on), explicit `timeout`, a `proxy=` egress proxy |
| requests | redirects are **on** by default: pass `allow_redirects=False`; prefer httpx in new code |
| Pydantic v2 | `HttpUrl` + a `field_validator` for scheme/port; never a bare `str` for a fetched URL |
| aiohttp | `allow_redirects=False`, `ClientTimeout`, and a resolver you control |
| Node fetch/undici | `redirect: "manual"`, `AbortSignal.timeout`, an `Agent` with a pinned `connect.lookup` |
| axios | `maxRedirects: 0`, `timeout`, `httpAgent`/`httpsAgent` with a pinned lookup (same for Next.js route handlers and server actions) |
| Cloud (AWS) | enforce IMDSv2 (`HttpTokens: required`, `HttpPutResponseHopLimit: 1`) — mitigates, does not fix |
| Network | NetworkPolicy / security group / NAT egress allowlist, or a forward proxy — the only control that survives rebinding |

## Grep for

```
rg -n 'follow_redirects\s*=\s*True'                       # httpx redirect chaining; first hop passes, later hops do not
rg -n 'requests\.(get|post|put|head)\(' -g '*.py'          # requests follows redirects by default unless allow_redirects=False
rg -n '(httpx|requests|aiohttp)[^\n]*\b(url|target|endpoint|callback|webhook|src|image_url|link)\b'  # request-derived URL reaching a client
rg -n 'def [a-z_]+\([^)]*\burl\s*:\s*str\b'                # URL typed as str, so no Pydantic scheme/host validation
rg -n '169\.254\.169\.254|127\.0\.0\.1|localhost' -g '*.py' -g '*.ts'   # a denylist: weak by construction, review the whole check
rg -n 'urlparse\([^)]*\)\.(hostname|netloc)\s*(not )?in'   # validate-then-fetch with no resolve/pin: rebinding window
rg -n 'redirect:\s*["\x27]follow|maxRedirects:\s*[1-9]'    # Node/axios following redirects on a user URL
rg -n 'fetch\(\s*(req|request)\.(body|query|params)'       # user input straight into fetch
rg -n 'file://|gopher://|dict://|ftp://'                   # scheme never restricted (or a test proving it is)
rg -n 'IMDSv1|HttpTokens.*optional'                        # metadata service reachable without a token
```

## False positives

- A URL built entirely from config/env with a path from an allowlisted enum, or `follow_redirects=True` against a hardcoded first-party host — no request data reaches the host.
- A fetch inside a sandbox/VPC whose egress allowlist denies RFC1918 and the metadata IP — the network control is the real one; still require `redirect: "manual"`.
- `HttpUrl` fields only stored and rendered as links in the UI, never fetched server-side.
- A browser-side `fetch` in React of a user URL (the user's own network, not the server's — a CORS/XSS question), or an SSRF-shaped helper reached only by a CLI or admin script; confirm by grepping its callers.

## Regression test

```python
# tests/test_import_ssrf.py
import pytest, respx, httpx

@pytest.mark.anyio
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8000/admin", "http://[::1]/",
    "http://2130706433/", "http://0177.0.0.1/",   # decimal- and octal-encoded loopback
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_FLUSHALL",
])
async def test_internal_targets_rejected(client, url):
    assert (await client.post("/import", json={"url": url})).status_code in (400, 422)

@pytest.mark.anyio
@respx.mock
async def test_redirect_to_internal_is_not_followed(client):
    respx.get("https://api.partner.test/feed").mock(
        return_value=httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    )
    r = await client.post("/import", json={"url": "https://api.partner.test/feed"})
    assert r.status_code == 400 and not respx.calls.last.request.url.host.startswith("169.254")

@pytest.mark.anyio
async def test_dns_name_resolving_private_is_rejected(client, monkeypatch):
    monkeypatch.setattr("app.ssrf.socket.getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 80))])
    assert (await client.post("/import", json={"url": "http://rebind.example.com/"})).status_code == 400
```

```ts
// preview.ssrf.test.ts
it("rejects a redirect into link-local space", async () => {
  nock("https://api.partner.test").get("/p").reply(302, "", { Location: "http://169.254.169.254/" });
  const res = await request(app).post("/preview").send({ url: "https://api.partner.test/p" });
  expect(res.status).toBe(400);
  expect(nock.pendingMocks()).toHaveLength(0);
  expect(res.text).not.toMatch(/meta-data/);
});
```
