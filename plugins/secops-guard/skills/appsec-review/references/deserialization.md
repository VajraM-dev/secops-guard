# Unsafe Deserialization and Prototype Pollution

**CWE:** CWE-502 (Deserialization of Untrusted Data), CWE-1321 (Prototype Pollution), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

A format that can reconstruct arbitrary objects is parsed from data the attacker can reach — `pickle`, `yaml.load`, a `.pt` checkpoint, a JSON body merged into an object. Reconstruction runs code or rewrites shared state. Use a format that only carries data, and sign anything you must round-trip.

## How it gets introduced

- `pickle.load`/`loads` on anything crossing a trust boundary: a Redis/Memcached cache value, a Celery message body, a session cookie, a file upload, an inter-service queue. "It's internal" stops being true the moment Redis is exposed, shared, or writable by another tenant.
- Celery configured with `task_serializer="pickle"` / `accept_content=["pickle"]` — the broker becomes a remote code execution channel. The default is `json`; someone changed it to ship a dataclass or a `datetime`.
- `yaml.load(data)` without a loader, or with `Loader=yaml.Loader`/`UnsafeLoader`/`FullLoader` — `!!python/object/apply` constructs arbitrary callables.
- ML artifacts loaded from a hub, a bucket, or a user upload: `torch.load(path)` (pre-2.6 default `weights_only=False`), `joblib.load`, `numpy.load(..., allow_pickle=True)`, `pandas.read_pickle` — all pickle under the hood.
- `jsonpickle.decode`, `dill.loads`, `shelve` or `marshal` on external data; in Node, `node-serialize`'s `unserialize` (it executes an `_$$ND_FUNC$$_` field) or `serialize-javascript` output eval'd back.
- Deep merge of a parsed JSON body into a config/options/user object (`lodash.merge`, `Object.assign` in a recursive helper, `deepmerge`, query-string parsers) — `__proto__` or `constructor.prototype` keys reach `Object.prototype` and change behaviour for every object in the process.
- Round-tripping state through the client (a cursor, a "signed" state blob, a resume token) with no MAC, so the client can author the object that gets deserialized.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
async def get_profile(uid: str):
    raw = await redis.get(f"profile:{uid}")
    return pickle.loads(raw) if raw else await load_profile(uid)

cfg = yaml.load(await upload.read())                       # full constructor set
model = torch.load(user_checkpoint_path)                   # arbitrary code at load time
app_celery.conf.task_serializer = "pickle"                 # broker becomes an RCE channel
```

```python
# fixed
from pydantic import BaseModel

class Profile(BaseModel):
    id: str
    display_name: str
    plan: Literal["free", "pro"]

async def get_profile(uid: str) -> Profile:
    raw = await redis.get(f"profile:{uid}")
    if raw:
        return Profile.model_validate_json(raw)            # JSON in, schema-checked, no object graph
    p = await load_profile(uid)
    await redis.set(f"profile:{uid}", p.model_dump_json(), ex=300)
    return p

cfg = ConfigModel.model_validate(yaml.safe_load(await upload.read()))   # SafeLoader + a schema

# Celery: keep the json default; pass ids and primitives, not objects
app_celery.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"])

@app_celery.task
def reindex(doc_id: str) -> None: ...                      # not reindex(doc_obj)
```

ML artifacts — safetensors is the real fix; `weights_only=True` is the floor:

```python
# fixed
from safetensors.torch import load_file
model.load_state_dict(load_file(path))                     # tensors only, no pickle opcodes
torch.load(path, map_location="cpu", weights_only=True)    # torch >= 2.6 defaults True; set it explicitly anyway
np.load(path, allow_pickle=False)                          # the default; never flip it to load an object array
```

If a blob genuinely must round-trip through an untrusted hop, sign it and verify before parsing:

```python
# fixed
import hmac, hashlib, base64

def unseal(token: str, key: bytes) -> bytes:
    blob = base64.urlsafe_b64decode(token)
    mac, payload = blob[:32], blob[32:]
    if not hmac.compare_digest(mac, hmac.new(key, payload, hashlib.sha256).digest()):
        raise ValueError("bad signature")                  # verify BEFORE any parse
    return payload                                         # seal() is the same two lines in reverse
```

A signature authenticates the sender; it does not make pickle safe. Sign **and** keep the format JSON.

## JS / TS / Node / React

```ts
// vulnerable
const opts = _.merge({}, DEFAULTS, req.body);              // __proto__ in the body pollutes every object
const state = unserialize(req.cookies.state);              // node-serialize executes functions
```

```ts
// fixed
import { z } from "zod";

const Opts = z.object({ theme: z.enum(["light", "dark"]), pageSize: z.number().int().max(100) }).strict();
const opts = { ...DEFAULTS, ...Opts.parse(req.body) };     // shallow spread of validated primitives

// when a deep merge is unavoidable, refuse the three dangerous keys at every level
const BAD = new Set(["__proto__", "constructor", "prototype"]);
function safeMerge(dst: Record<string, unknown>, src: Record<string, unknown>) {
  for (const k of Object.keys(src)) {
    if (BAD.has(k)) continue;
    const v = src[k];
    dst[k] = v && typeof v === "object" && !Array.isArray(v)
      ? safeMerge((dst[k] as Record<string, unknown>) ?? Object.create(null), v as Record<string, unknown>)
      : v;
  }
  return dst;
}

// parse into a null-prototype object so a "__proto__" key is an ordinary own property
const parsed = JSON.parse(body, (k, v) =>
  k === "__proto__" ? undefined : v && typeof v === "object" && !Array.isArray(v) ? Object.assign(Object.create(null), v) : v
);
const copy = structuredClone(value);                       // never eval/serialize round-trips for cloning
```

Run Node with `--disable-proto=throw` where you can. `JSON.parse` itself is safe; the reviver and whatever consumes the result are where pollution lands.

## The safe API, per framework

| Format / stack | Use |
|---|---|
| Python objects over a boundary | JSON + `Model.model_validate_json`; never `pickle` |
| YAML | `yaml.safe_load` (or `SafeLoader`), then a Pydantic model |
| Celery | `task_serializer="json"`, `accept_content=["json"]`, primitive task args |
| Cache / Redis | JSON strings; version the key when the schema changes |
| PyTorch | `safetensors`; else `torch.load(..., weights_only=True)` |
| numpy / joblib / pandas | `allow_pickle=False`; prefer `.npz`/parquet/arrow over `.pkl` |
| scikit-learn models | ONNX or skops; `joblib.load` only on artifacts you built and stored yourself |
| Node clone | `structuredClone`; never `eval(serialize(x))` |
| Node merge | zod/valibot `.strict()` + shallow spread; `Object.create(null)` for maps |
| Must round-trip through a client | HMAC-SHA256 (or an existing JWT/itsdangerous/`cookie-signature`) verified before parsing |

## Grep for

```
rg -n '\bpickle\.(load|loads)\(|cPickle|_pickle'          # any untrusted source here is RCE
rg -n 'read_pickle\(|to_pickle\(|dill\.(load|loads)\(|jsonpickle\.decode' # pickle by another name
rg -n 'yaml\.load\((?!.*SafeLoader)' -P                   # yaml.load without SafeLoader
rg -n 'Loader\s*=\s*yaml\.(Unsafe|Full|)Loader'           # unsafe/full loaders construct Python objects
rg -n 'task_serializer|accept_content|result_serializer'  # confirm every one of these is json
rg -n 'CELERY_[A-Z_]*SERIALIZER'                          # old-style config, often left at pickle
rg -n 'torch\.load\(' -g '*.py'                           # needs weights_only=True, or move to safetensors
rg -n 'allow_pickle\s*=\s*True'                           # numpy object arrays execute on load
rg -n 'joblib\.load\(|skops|\.pkl["\x27]|\.joblib["\x27]' # artifact loads: check provenance
rg -n 'node-serialize|unserialize\(|funcster'             # executes functions on parse
rg -n 'JSON\.parse\([^,)]+,\s*(function|\()'              # a reviver: check it cannot write __proto__
rg -n '_\.(merge|mergeWith|defaultsDeep|set|setWith)\(|deepmerge|deep-extend|object-path|dot-prop'  # deep-write sinks
rg -n '__proto__|constructor\s*\[|\bprototype\b\s*\]'     # explicit prototype access; a hit inside a guard is good
rg -n 'redis\.(get|set)\(' -A2 | rg 'pickle|dumps\('      # pickled cache values
```

## False positives

- `pickle` used entirely inside one process (`multiprocessing`, a `functools` cache, joblib parallelism) where the bytes never leave memory or a trusted disk path.
- `yaml.safe_load`, and `yaml.load(x, Loader=yaml.SafeLoader)`; `torch.load` with `weights_only=True`, or on a checkpoint your own training job wrote to your own bucket with an integrity check.
- `JSON.parse` with no reviver whose result is validated by zod before use — pollution needs a *write* of parsed keys onto an existing object.
- `_.merge` whose source is a literal or a server-built object, `structuredClone`, and spreads of a `.strict()`-parsed object.
- A `__proto__` string inside a denylist, fixture, or security test — read the surrounding lines before flagging.

## Regression test

```python
# tests/test_cache_deserialization.py
import pickle, pytest, yaml

@pytest.mark.anyio
async def test_poisoned_cache_entry_is_rejected_not_unpickled(client, redis, tmp_path):
    class Boom:
        def __reduce__(self):                      # marker object: proves load-time execution if it runs
            return (open, (str(tmp_path / "pwned"), "w"))
    await redis.set("profile:u1", pickle.dumps(Boom()))
    r = await client.get("/profile/u1")
    assert r.status_code in (422, 500)             # JSON parse fails; it does not reconstruct
    assert not (tmp_path / "pwned").exists()

def test_yaml_upload_rejects_python_tags(client):
    doc = "!!python/object/apply:os.system ['true']\n"
    assert client.post("/config", files={"f": ("c.yaml", doc)}).status_code in (400, 422)

def test_celery_refuses_pickle_messages(celery_app):
    assert celery_app.conf.accept_content == ["json"] and celery_app.conf.task_serializer == "json"
```

```ts
// options.pollution.test.ts
import { describe, it, expect } from "vitest";

it("a __proto__ key in the body does not reach Object.prototype", async () => {
  const res = await request(app).post("/options").send(JSON.parse('{"__proto__":{"isAdmin":true}}'));
  expect(res.status).toBeLessThan(500);
  expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();   // fails before the fix
  expect(Object.prototype.hasOwnProperty.call(Object.prototype, "isAdmin")).toBe(false);
});

it("rejects a constructor.prototype path", async () => {
  await request(app).post("/options").send(JSON.parse('{"constructor":{"prototype":{"polluted":1}}}'));
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
});
```
