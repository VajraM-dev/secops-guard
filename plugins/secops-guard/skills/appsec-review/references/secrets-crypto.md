# Secrets Handling and Cryptography

**CWE:** CWE-798 (Hardcoded Credentials), CWE-312 (Cleartext Storage of Sensitive Information), CWE-532 (Secret in Log File), CWE-330 (Insufficiently Random Values), CWE-327 (Broken Crypto Algorithm), CWE-328 (Weak Hash), CWE-295 (Improper Certificate Validation)

Secrets leak through the places nobody reviews — logs, tracebacks, prompts, Docker layers, CI output. Crypto fails through defaults — a guessable token, a reused IV, a hash chosen for speed.

## How it gets introduced

- A key is pasted as a module-level default "just to get it running", or `.env` is committed because a teammate needed it.
- A config object, request, or exception is logged whole, so the API key inside it lands in the log aggregator.
- Secrets flow into an LLM prompt, an error response body, or a Sentry breadcrumb along with the context object.
- `ENV SECRET=...` / `ARG` in a Dockerfile, or `echo $TOKEN` in a CI step — both persist in the layer or the build log.
- `random`/`Math.random()` generates a reset token, invite code, or nonce because it was the import already present.
- MD5/SHA1 kept for "signature" checks; AES in ECB mode or with a constant IV; hand-rolled XOR/base64 "encryption" instead of a library AEAD.
- `verify=False` added to get past a corporate TLS proxy, or `rejectUnauthorized: false` in a Node client, and both ship.
- Keys have no rotation path: one value, in every environment, since the first deploy.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
STRIPE_KEY = "sk_live_51H8xQ2abcdef..."                    # hardcoded, now in git history forever
logger.info("config=%s", settings.model_dump())            # whole config, secrets included
token = str(random.randint(10**9, 10**10))                 # predictable reset token
sig = hashlib.md5(payload + SECRET).hexdigest()            # broken hash, length-extension shaped
if provided_sig == sig: ...                                # non-constant-time compare
r = httpx.get(url, verify=False)                           # TLS verification off
cipher = AES.new(KEY, AES.MODE_ECB)                        # ECB leaks plaintext structure
```

```python
# fixed
import hmac, secrets
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")   # .env is gitignored, never committed
    stripe_key: SecretStr                      # repr/log of the model shows SecretStr('**********')
    webhook_secret: SecretStr
    data_key: SecretStr                        # 32 bytes, base64; rotated via DATA_KEY_V2 + a key_id column

settings = Settings()                          # missing env var -> startup fails loudly, no silent default

reset_token = secrets.token_urlsafe(32)        # CSPRNG; store only sha256(token), expire in 30 min, single use

def verify_webhook(body: bytes, sig: str) -> bool:
    expected = hmac.new(settings.webhook_secret.get_secret_value().encode(),
                        body, "sha256").hexdigest()
    return hmac.compare_digest(sig, expected)  # SHA-256 HMAC + constant time

def encrypt(plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    key = base64.b64decode(settings.data_key.get_secret_value())
    nonce = secrets.token_bytes(12)            # fresh per message; NEVER reuse a nonce with one key
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)   # or cryptography.fernet if you want no choices

r = await client.get(url)                      # verify defaults to True; for a private CA pass verify="/path/ca.pem"
```

`SecretStr` hides the value in `repr()`, `str()`, tracebacks and `model_dump()` — **it does not protect `.get_secret_value()`**. The moment that call result reaches a log line, an f-string, an exception message, or an LLM prompt, the secret is in cleartext. Call it only at the point of use, and add a logging filter that redacts known secret values and `authorization`/`api[-_]?key`/`token` fields from structured logs and from FastAPI exception handlers (never return `str(exc)` to a client).

Rotation: give every key a `key_id`, support decrypting with the previous key while encrypting with the current one, and make rotation a config change, not a migration.

## JS / TS / Node / React

```ts
// vulnerable
const API_KEY = "sk-proj-abc123...";                            // hardcoded
console.log("req", { headers: req.headers });                   // logs Authorization and Cookie
const token = Math.random().toString(36).slice(2);              // not a CSPRNG
const hash = crypto.createHash("sha1").update(secret).digest("hex");
if (sigFromClient === hash) { /* timing leak */ }
const agent = new https.Agent({ rejectUnauthorized: false });   // TLS off
```

```ts
// fixed
import { randomBytes, randomUUID, createHmac, timingSafeEqual,
         createCipheriv, createDecipheriv } from "node:crypto";

const env = z.object({ API_KEY: z.string().min(20), DATA_KEY: z.string().length(44) }).parse(process.env);

const token = randomBytes(32).toString("base64url");            // or randomUUID() for an id, not a secret
const REDACT = /^(authorization|cookie|set-cookie|x-api-key)$/i;
logger.info({ headers: Object.fromEntries(
  Object.entries(req.headers).filter(([k]) => !REDACT.test(k))) });

const expected = createHmac("sha256", env.API_KEY).update(rawBody).digest();
const given = Buffer.from(sigHeader, "hex");
const ok = given.length === expected.length && timingSafeEqual(given, expected);

function encrypt(plain: Buffer, key: Buffer) {                  // AES-256-GCM, fresh 12-byte IV per message
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
}
```

Anything in a React bundle or a `NEXT_PUBLIC_*` variable is public. A server-only secret belongs in a server action, a route handler, or an API route — never imported into a client component.

## The safe API, per framework

| Need | Use |
|---|---|
| Config + secrets (Python) | `pydantic-settings` `BaseSettings` with `SecretStr`; `.env` gitignored; real values from the platform's secret store |
| Random tokens (Python) | `secrets.token_urlsafe(32)` / `secrets.token_bytes(32)` — never `random`; `uuid_utils.uuid7()` for ids (a UUID is not a secret) |
| Secret comparison (Python) | `hmac.compare_digest` |
| Symmetric encryption (Python) | `cryptography.fernet.Fernet` (no choices to get wrong) or `AESGCM` with a fresh 12-byte nonce |
| Hashing (Python) | SHA-256 for integrity; argon2id/bcrypt for passwords; never MD5/SHA1 |
| HTTP client (Python) | `httpx` with default `verify=True`; a CA bundle path for private CAs |
| Random/crypto (Node) | `node:crypto` — `randomBytes`, `randomUUID`, `timingSafeEqual`, `createCipheriv("aes-256-gcm")` |
| Env validation (Node) | `zod`-parsed `process.env` at boot; `NEXT_PUBLIC_*` is public by definition |
| Secret storage | AWS Secrets Manager / Vault / Doppler, injected at runtime, not baked into an image; `gitleaks` or `detect-secrets` in CI and as a pre-commit hook |

## Grep for

```
rg -n '(sk-[A-Za-z0-9_-]{16,}|sk_live_|xox[baprs]-|ghp_|github_pat_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})'  # live key shapes
rg -n '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'            # private key committed
rg -n '(password|passwd|secret|token|api_?key)\s*[=:]\s*[\x27"][^\x27"$\{][^\x27"]{7,}' -i   # literal credential, not an env ref
rg -n '^\s*\.env$' .gitignore                                      # is .env actually ignored? also: git log -- .env
rg -n '(ENV|ARG)\s+\w*(SECRET|TOKEN|KEY|PASSWORD)' --glob 'Dockerfile*'   # secret baked into a layer
rg -n 'echo\s+.*\$\{?\w*(SECRET|TOKEN|KEY|PASSWORD)' --glob '.github/**'  # secret echoed into CI logs
rg -n 'verify\s*=\s*False|rejectUnauthorized:\s*false|InsecureRequestWarning|NODE_TLS_REJECT_UNAUTHORIZED' # TLS verification off
rg -n 'hashlib\.(md5|sha1)\(|createHash\([\x27"](md5|sha1)[\x27"]\)' # broken hash
rg -n 'MODE_ECB|aes-\d+-ecb'                                        # ECB mode
rg -n 'iv\s*=\s*[\x27"b]|IV\s*=\s*bytes\(|Buffer\.alloc\(1[26]\)'   # constant or zero IV
rg -n '\brandom\.(random|randint|choice|sample)\(|Math\.random\(\)' # non-CSPRNG where a token is made
rg -n '(token|secret|signature|api_?key|hmac)\s*==\s*' -i           # non-constant-time secret compare
rg -n '(log|logger|print|console\.(log|error))\(.*(settings|config|token|secret|password|headers|api_?key)' -i  # secret into a log
rg -n 'str\(e\)|str\(exc\)|exc\.detail|error\.message' -g '*handler*' # exception text returned to the client
rg -n 'NEXT_PUBLIC_\w*(SECRET|KEY|TOKEN|PASSWORD)'                  # server secret exposed to the browser
rg -n 'get_secret_value\(\)' -B2 -A2                                # each call: where does the plaintext go?
```

## False positives

- Test fixtures, `conftest.py`, `.env.example`, and docs using obvious placeholders (`sk-test-xxxx`, `changeme`, `dummy`) — still confirm they are not real, and that `.env.example` holds no live value.
- `hashlib.md5(..., usedforsecurity=False)` or SHA-1 used as a cache key, ETag, or content fingerprint — not a security boundary.
- `verify=False` inside a test against a local self-signed server, guarded so it cannot run in production config.
- `Math.random()` or `random.Random(seed)` for jitter, retry backoff, UI shuffling, or a deterministic simulation — no secrecy required.
- A long hex string that is a checksum, a commit SHA, a public key, or a test vector.
- `NEXT_PUBLIC_` variables that are genuinely public (a publishable Stripe key, a PostHog project key).

## Regression test

```python
# tests/test_secrets_crypto.py
import re, secrets, pytest
from app.config import settings
from app.crypto import encrypt, decrypt, verify_webhook

def test_settings_never_render_the_secret():
    assert "sk_" not in repr(settings) and "sk_" not in str(settings.model_dump())

def test_no_secret_reaches_the_logs(client, caplog):
    client.get("/health")
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert settings.stripe_key.get_secret_value() not in blob
    assert not re.search(r"(sk_live_|Bearer\s+[A-Za-z0-9._-]{20,})", blob)

def test_error_response_does_not_leak_internals(client):
    r = client.get("/boom")                       # a route that raises
    assert r.status_code == 500
    assert "Traceback" not in r.text and settings.stripe_key.get_secret_value() not in r.text

def test_ciphertext_is_nondeterministic():        # fails under ECB or a fixed IV
    a, b = encrypt(b"same plaintext", b"aad"), encrypt(b"same plaintext", b"aad")
    assert a != b
    assert decrypt(*a, b"aad") == b"same plaintext"

def test_tampered_ciphertext_and_forged_signature_are_rejected():
    nonce, ct = encrypt(b"money: 100", b"aad")
    with pytest.raises(Exception):
        decrypt(nonce, ct[:-1] + bytes([ct[-1] ^ 0x01]), b"aad")   # AEAD catches the flip
    assert verify_webhook(b"{}", "00" * 32) is False

def test_tokens_are_unpredictable():
    t = {make_reset_token() for _ in range(1000)}
    assert len(t) == 1000 and all(len(x) >= 32 for x in t)

def test_key_rotation_keeps_old_ciphertext_readable(rotate_to_v2):
    nonce, ct = encrypt(b"old", b"aad")          # written under v1
    rotate_to_v2()
    assert decrypt(nonce, ct, b"aad") == b"old"  # v1 still decrypts after rotation
```

```ts
// crypto.test.ts (vitest)
it("rejects a tampered auth tag", () => {
  const blob = encrypt(Buffer.from("amount=10"), key);
  blob[blob.length - 1] ^= 1;
  expect(() => decrypt(blob, key)).toThrow();
});
it("never ships a server secret to the client bundle", async () => {
  const bundle = await readFile(".next/static/chunks/main.js", "utf8");
  expect(bundle).not.toContain(process.env.API_KEY!);
});
```
