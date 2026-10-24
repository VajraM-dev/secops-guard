# Authentication, Sessions and JWT

**CWE:** CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature), CWE-384 (Session Fixation), CWE-613 (Insufficient Session Expiration), CWE-916 (Weak Password Hash), CWE-307 (Improper Restriction of Excessive Authentication Attempts)

A token the server does not fully verify is a token the client writes. Decoding is not verifying, and a correct signature is only one of the claims that must hold.

## How it gets introduced

- `jwt.decode(token, key)` without `algorithms=[...]`, letting the token's own `alg` header pick the verifier (`none`, or HS256 verified against a public RSA key the attacker already has).
- `options={"verify_signature": False}` left over from debugging, or `verify_aud=False` copied from a Stack Overflow answer; no `aud`/`iss` check, so a token from a sibling service is accepted.
- Access tokens with a multi-day `exp` and no revocation path, so logout and "disable user" do nothing; refresh tokens that never rotate, so one stolen token is permanent access.
- JWTs stored in `localStorage`, so any XSS exfiltrates them.
- The session id is not regenerated at login, so a pre-set cookie survives authentication (fixation).
- Passwords hashed with `sha256(salt + password)` or a single MD5 round because "it's salted".
- `token == stored_token` for API keys and reset tokens; `random.randint` or `uuid4()` fragments for reset tokens.
- Distinct responses for "unknown user" vs "wrong password", and no rate limit on the login route.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
def current_user(token: str = Depends(oauth2)):
    return jwt.decode(token, SECRET)["sub"]                # no algorithms=, no aud/iss, no exp require

def check_pw(raw, row):  return hashlib.sha256((SALT + raw).encode()).hexdigest() == row.pw  # fast hash + ==
```

```python
# fixed
import jwt, hmac, secrets                       # pyjwt; python-jose is unmaintained -> pyjwt or joserfc
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()                           # argon2id defaults; bcrypt(cost>=12) also acceptable

def decode_access(token: str) -> dict:
    return jwt.decode(
        token, settings.jwt_public_key.get_secret_value(),
        algorithms=["RS256"],                   # allowlist, fixed; never read alg from the header
        audience=settings.jwt_audience, issuer=settings.jwt_issuer,   # aud and iss pinned
        options={"require": ["exp", "iat", "sub", "aud", "iss"], "verify_exp": True},
        leeway=30,
    )

async def current_user(token=Depends(oauth2), s: AsyncSession = Depends(db)) -> User:
    try:
        claims = decode_access(token)
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token")
    if await revoked(claims["jti"]):            # short TTL + a jti denylist = real logout
        raise HTTPException(401, "invalid token")
    return await s.get(User, UUID(claims["sub"]))

async def login(email: str, password: str, s: AsyncSession, request: Request) -> Tokens:
    await rate_limit(f"login:{request.client.host}:{email}")   # CWE-307, per-IP and per-account
    user = await s.scalar(select(User).where(User.email == email))
    try:
        ph.verify(user.password_hash if user else DUMMY_HASH, password)  # always hash: constant work
        if user is None:
            raise VerifyMismatchError
    except VerifyMismatchError:
        raise HTTPException(401, "invalid credentials")        # one message for both failures
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)                 # transparent parameter upgrade
    await request.session.regenerate()                         # CWE-384: new session id at login
    return await issue_tokens(user)                            # access ~15 min, refresh rotated

async def refresh(presented: str, s: AsyncSession) -> Tokens:
    row = await s.scalar(select(RefreshToken).where(
        RefreshToken.hash == sha256(presented)))               # store the hash, never the token
    if row is None or row.expires_at < now():
        raise HTTPException(401)
    if row.used_at is not None:                                # reuse detection: the family is compromised
        await revoke_family(s, row.family_id)
        raise HTTPException(401, "token reuse detected")
    row.used_at = now()                                        # single use, then rotate
    return await issue_tokens(row.user, family_id=row.family_id)
# API keys and reset tokens: hmac.compare_digest(presented, stored), never ==
```

Password reset tokens: `secrets.token_urlsafe(32)`, store only the hash, expire in 15-60 minutes, single use, invalidate on password change, and return the same "if that address exists, we sent a link" response for every email.

## JS / TS / Node / React

```ts
// vulnerable
const claims = jwt.verify(token, process.env.JWT_SECRET!);     // no algorithms/audience/issuer
localStorage.setItem("token", res.data.access);                // XSS-readable
```

```ts
// fixed
import { jwtVerify, createRemoteJWKSet } from "jose";
const JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URL!));

export async function verifyAccess(token: string) {
  const { payload } = await jwtVerify(token, JWKS, {
    algorithms: ["RS256"],                 // pinned allowlist
    audience: process.env.JWT_AUD, issuer: process.env.JWT_ISS, clockTolerance: 30,
  });
  if (!payload.sub || !payload.jti) throw new Error("invalid token");
  return payload;
}

// the browser never holds the token in JS-reachable storage
res.cookie("session", sid, {
  httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 15 * 60_000,
});

import argon2 from "argon2";
import { timingSafeEqual, randomBytes } from "node:crypto";
const ok = await argon2.verify(user.passwordHash, password);   // never createHash("sha256")
const eq = (a: Buffer, b: Buffer) => a.length === b.length && timingSafeEqual(a, b);
const resetToken = randomBytes(32).toString("base64url");      // never Math.random()
```

React: keep the access token in memory (a module variable or context) and the refresh token in an httpOnly, `SameSite=Lax`, `Secure` cookie. `localStorage` turns any XSS into full account takeover.

## The safe API, per framework

| Framework / need | Built-in control to use |
|---|---|
| Python JWT | `pyjwt` with `algorithms=[...]`, `audience=`, `issuer=`, `options={"require": [...]}`; or `joserfc`. Avoid `python-jose` |
| Password hashing (Py) | `argon2-cffi` (`PasswordHasher`) or `bcrypt` cost >= 12; `check_needs_rehash` for upgrades |
| Secrets (Py) | `hmac.compare_digest` to compare; `secrets.token_urlsafe(32)` to generate |
| FastAPI | `OAuth2PasswordBearer` + a `current_user` dependency; `slowapi`/gateway limits on `/login` |
| Node JWT | `jose` (`jwtVerify` + `createRemoteJWKSet`) over `jsonwebtoken` |
| Password hashing (JS) | `argon2` or `bcrypt`; never `crypto.createHash` |
| Secrets (JS) | `crypto.timingSafeEqual` on equal-length buffers; `randomBytes(32)` to generate |
| Sessions / storage | `express-session` with `regenerate()` on login; Next.js `auth.js`; httpOnly + Secure + SameSite cookie, access token in memory |

## Grep for

```
rg -n 'jwt\.decode\((?!.*algorithms)' -P                   # PyJWT decode with no algorithms allowlist
rg -n 'verify_(signature|aud|exp|iss|iat)["\x27]?\s*:\s*False'  # signature or a claim check disabled
rg -n 'algorithms\s*=\s*\[[^\]]*(none|HS256.*RS256|RS256.*HS256)' # alg confusion or alg:none accepted
rg -n 'jwt\.verify\([^,]+,[^,]+\)\s*;?$'                   # jsonwebtoken verify with no options object
rg -n 'hashlib\.(md5|sha1|sha256)\(.*(pass|pwd|secret)' -i # fast hash on a credential; same for createHash in Node
rg -n '(token|secret|key|signature|hash|otp)\s*==\s*'      # non-constant-time comparison of a secret
rg -n 'localStorage\.(set|get)Item\(.*(token|jwt|auth)' -i # JWT reachable by XSS
rg -n 'exp.*timedelta\((days|weeks)=' -i                   # multi-day access token lifetime
rg -n 'import jose|from jose import'                       # python-jose unmaintained: move to pyjwt/joserfc
rg -n 'random\.(random|randint|choice)|Math\.random\(\)'   # non-CSPRNG used for a token
rg -n 'def login|/login|signIn' -A10                       # check rate limit, session regeneration, httpOnly cookie
rg -n '(User|user) (not found|does not exist)|Invalid password' # distinct errors: user enumeration
```

## False positives

- `jwt.decode(..., options={"verify_signature": False})` used only to read `kid`/`iss` before selecting a key, where a real verified decode follows in the same function.
- `jwt.decode` without `algorithms=` inside a test fixture or a token-minting script that never runs in the request path.
- `sha256` over a refresh token or API key *before storage* — a lookup digest of a high-entropy value, not password hashing; the comparison must still be constant-time.
- `==` on a token inside a test, or on a non-secret identifier such as a `kid` or a username.
- Long `exp` on an identity token exchanged at the gateway for a short-lived internal token; `localStorage` holding a non-credential UI preference whose key merely contains "auth" (`authModalSeen`).

## Regression test

```python
# tests/test_authn.py
import jwt, pytest

CLAIMS = {"sub": "admin", "aud": AUD, "iss": ISS}

@pytest.mark.anyio
@pytest.mark.parametrize("key,alg", [("", "none"), (RSA_PUBLIC_PEM, "HS256")])  # alg:none and alg confusion
async def test_forged_signature_is_rejected(client, key, alg):
    forged = jwt.encode(CLAIMS, key, algorithm=alg)
    assert (await client.get("/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401

@pytest.mark.anyio
async def test_wrong_audience_or_expired_token_is_rejected(client, mint):
    for bad in (mint(aud="other-svc"), mint(exp=-60)):
        assert (await client.get("/me", headers={"Authorization": f"Bearer {bad}"})).status_code == 401

@pytest.mark.anyio
async def test_refresh_token_rotates_and_reuse_kills_the_family(client, refresh_token):
    first = await client.post("/auth/refresh", json={"refresh": refresh_token})
    assert first.status_code == 200
    new = first.json()["refresh"]
    assert new != refresh_token                                   # rotated
    replay = await client.post("/auth/refresh", json={"refresh": refresh_token})
    assert replay.status_code == 401                              # reuse detected
    assert (await client.post("/auth/refresh", json={"refresh": new})).status_code == 401  # family revoked

@pytest.mark.anyio
async def test_login_does_not_reveal_whether_the_account_exists(client, existing_user):
    a = await client.post("/auth/login", json={"email": existing_user.email, "password": "wrong"})
    b = await client.post("/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()

@pytest.mark.anyio
async def test_session_id_changes_on_login(client, creds):
    pre = (await client.get("/")).cookies.get("session")
    assert (await client.post("/auth/login", json=creds)).cookies.get("session") not in (None, pre)

def test_password_is_not_stored_with_a_fast_hash(created_user):
    assert created_user.password_hash.startswith(("$argon2id$", "$2b$"))
```
