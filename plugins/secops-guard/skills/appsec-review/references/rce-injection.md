# Remote Code Execution and Injection

**CWE:** CWE-78 (OS Command Injection), CWE-77 (Command Injection), CWE-88 (Argument Injection), CWE-94 (Code Injection), CWE-95 (Eval Injection), CWE-1336 (Template Injection), CWE-943 (Query Logic Injection / NoSQL), CWE-90 (LDAP Injection)

Untrusted input reaches an interpreter — a shell, the Python/JS evaluator, a template compiler, or a query engine — and is parsed as code instead of data. The fix is always the same shape: pass data through a channel that cannot carry syntax.

## How it gets introduced

- `subprocess.run(f"convert {path} out.png", shell=True)` / `os.system` / `os.popen`: an f-string plus a shell, so `;`, `|`, `$()`, backticks and newlines are operators.
- Node `child_process.exec`/`execSync` with a template string — `exec` spawns `/bin/sh`, `execFile`/`spawn` with an array does not.
- `eval`, `exec`, `compile`, `new Function`, `vm.runInNewContext` fed a request field — a "calculator", a rules engine, a "formula" column, an admin "run this snippet" box. Pickle-style loaders are the same class: see `deserialization.md`.
- `Template(user_string).render(...)` or `render_template_string(user_string)`: the template language is a full interpreter, so SSTI is RCE. Rendering user data *into* a pre-compiled template is fine; compiling a user string is not.
- `getattr(obj, user_name)`, `__import__(user_name)`, `importlib.import_module(user_name)`, `operator.attrgetter(user_path)` — reaches `__class__`, `__globals__`, `os`.
- Shell-free but still injectable: a user value that becomes an **argument** is read as a flag (`--output`, `--config`, `-o`, `@file`, `--use-askpass`), or a filename starting with `-`.
- NoSQL: a JSON body spread into a Mongo filter (`{email: req.body.email}` where `email` is `{"$ne": null}`), `$where`/`$function` with a string, or an LDAP filter built by concatenation so `*)(uid=*` widens it.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
@app.post("/thumbnail")
async def thumb(name: str, size: str):
    subprocess.run(f"convert /data/{name} -resize {size} /out/{name}.png", shell=True, check=True)

@app.post("/render")
async def render(tpl: str):
    return Template(tpl).render(user=current_user)      # SSTI == RCE

@app.get("/calc")
async def calc(expr: str):
    return {"v": eval(expr)}
```

```python
# fixed
import asyncio, shutil
from pathlib import Path
from typing import Annotated, Literal
from pydantic import BaseModel, StringConstraints

Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}\.(png|jpg)$")]
DATA = Path("/data").resolve()

class ThumbReq(BaseModel):
    name: Name
    size: Literal["64x64", "128x128", "512x512"]        # closed set beats any escaping

@app.post("/thumbnail")
async def thumb(req: ThumbReq):
    src = (DATA / req.name).resolve()
    if not src.is_relative_to(DATA):                    # traversal check after resolve
        raise HTTPException(400, "bad path")
    proc = await asyncio.create_subprocess_exec(        # argv list: no shell, no metacharacters
        shutil.which("convert") or "/usr/bin/convert",
        "--", str(src), "-resize", req.size, f"/out/{req.name}.png",
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.wait_for(proc.communicate(), timeout=20)
    if proc.returncode:
        raise HTTPException(422, "convert failed")      # never return stderr to the client
```

`--` ends option parsing, so a value starting with `-` is read as a filename, not a flag. `shlex.quote` is the weaker fallback for when a shell is unavoidable — it protects values, never a whole command, and does nothing against argument injection.

Templates and dynamic attributes:

```python
# fixed
env = Environment(loader=FileSystemLoader("templates"), autoescape=True)   # templates from disk only
return env.get_template("invoice.html").render(user=user, note=note)   # data in, template fixed
fn = {"csv": to_csv, "pdf": to_pdf}.get(fmt) or abort(400)   # dict dispatch, not getattr/__import__
```

Instead of `eval` for a user formula: a Pydantic-modelled operation (`{"op": "add", "a": 1, "b": 2}`), or a sandboxed expression library with no attribute access (`asteval`, `simpleeval`) — never bare `eval` with a stripped `__builtins__`, which is bypassable.

Mongo from FastAPI: type the filter, never pass the raw body.

```python
await db.users.find_one(req_json)                       # vulnerable: {"email": {"$ne": null}} logs in as anyone

# fixed
class Lookup(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    email: EmailStr
await db.users.find_one({"email": lookup.email})        # a str can never become an operator
```

## JS / TS / Node / React

```ts
// vulnerable
exec(`git clone ${repo} /tmp/${name}`);                  // shell; also --upload-pack= in repo
const out = new Function("ctx", `return ${req.body.expr}`)(ctx);
const user = await User.findOne(req.body);               // operator injection
```

```ts
// fixed
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const run = promisify(execFile);

const REPO = /^https:\/\/github\.com\/[\w.-]{1,39}\/[\w.-]{1,100}\.git$/;
if (!REPO.test(repo)) throw new BadRequest("repo");
await run("git", ["clone", "--", repo, dest], { timeout: 60_000, shell: false, env: { PATH: "/usr/bin" } });

// no dynamic code: a closed map of operations
const OPS = { add: (a: number, b: number) => a + b, mul: (a: number, b: number) => a * b } as const;
const op = OPS[body.op as keyof typeof OPS];
if (!op) throw new BadRequest("op");

const q = z.object({ email: z.string().email() }).parse(req.body);   // primitives first
const user = await User.findOne({ email: q.email });     // never findOne(req.body)
```

`shell: false` is the default for `execFile`/`spawn` — the bug is passing `{ shell: true }` or using `exec`. `vm`/`vm2` is not a security boundary; `isolated-vm` or a separate process with seccomp is.

## The safe API, per framework

| Need | Use |
|---|---|
| Run a program (Python) | `asyncio.create_subprocess_exec` / `subprocess.run([...])`, `shell=False`, `--` before user values |
| Run a program (Node) | `execFile` / `spawn` with an argv array; never `exec`, never `shell: true` |
| Shell truly required | `shlex.quote` per value (Python) — fallback only; still vulnerable to argument injection |
| Templating | pre-compiled templates via `Environment.get_template` / `render_template`; never `Template(user)` or `render_template_string(user)` |
| Dynamic dispatch | a `dict`/`Record` allowlist; never `getattr`, `__import__`, `importlib.import_module` on user text |
| User expressions | a Pydantic/zod operation model, or `simpleeval`/`asteval`; never `eval`/`exec`/`new Function`/`vm` |
| Mongo | typed model (Pydantic `strict=True`, `extra="forbid"` / zod), explicit filter keys; disable `$where`, never `$function` |
| LDAP | `ldap3`'s escaping (`escape_filter_chars`) or parameterized filters; `ldapts` `escapeFilter` |
| Celery | pass ids and primitives as task args; never a command string the worker shells out |

## Grep for

```
rg -n 'shell\s*=\s*True'                                  # any user data in that command string is RCE
rg -n 'os\.(system|popen)\(|commands\.getoutput'          # always a shell; no safe form
rg -n 'subprocess\.(run|Popen|call|check_output)\(\s*f["\x27]'  # f-string command: shell or not, argv is built from input
rg -n '\b(eval|exec)\s*\(' -g '*.py'                      # confirm the argument is not request-derived
rg -n 'compile\([^,]*,\s*["\x27]<' -g '*.py'              # compile() of a dynamic source string
rg -n 'Template\(\s*[a-z_]+\s*\)|render_template_string\(' # SSTI: template compiled from a variable
rg -n 'getattr\([^,]+,\s*(request|req|body|params|payload|user_)' # attribute name from input
rg -n '__import__\(|importlib\.import_module\(\s*[a-z_]+\)'       # dynamic import of a user string
rg -n '\bexec(Sync)?\(\s*`|shell:\s*true'                 # template literal into a shell, or execFile/spawn downgraded to one
rg -n 'new Function\(|vm\.(runIn|Script)|eval\(' -g '*.ts' -g '*.js'  # dynamic code evaluation
rg -n '\$where|\$function|\$accumulator'                  # Mongo server-side JS
rg -n 'find(One)?\(\s*(req|request)\.(body|query|params)' # operator injection straight from JSON
rg -n '\(uid=|\(cn=|\(&\(' -g '*.py' -g '*.ts'            # LDAP filter built by hand; check for concatenation
rg -n '"--?[a-z-]+=?"\s*\+|`--?[a-z-]+=\$\{'              # user value concatenated into a CLI flag
```

## False positives

- `subprocess.run([...])` with a list and no `shell=True` — argv elements cannot be re-parsed. Still check for argument injection if a value can start with `-` and `--` is absent.
- `eval`/`exec` in a migration, a notebook, a build script, or on a literal defined in the same file — grep the callers to confirm no route reaches it. Same for `getattr(self, f"handle_{verb}")` where `verb` came from a `Literal`/enum: the type is the allowlist.
- `Template(...)` where the argument is a module constant or a file read from the repo, not from a request.
- `exec()` in Node on a fully static command string, and Jinja rendering *user data* into a static template with `autoescape=True` (an XSS question, not SSTI).
- A Mongo query spreading a body already parsed by a strict zod/Pydantic model into primitives.

## Regression test

```python
# tests/test_thumbnail_injection.py
import pytest

@pytest.mark.anyio
@pytest.mark.parametrize("name", [
    "a.png; touch /tmp/pwned", "a.png && id", "$(id).png", "../../etc/passwd",
    "-o/tmp/evil.png",            # argument injection: value read as a flag
])
async def test_command_metacharacters_rejected(client, name, tmp_path):
    r = await client.post("/thumbnail", json={"name": name, "size": "64x64"})
    assert r.status_code in (400, 422)
    assert not (tmp_path / "pwned").exists()

@pytest.mark.anyio
async def test_template_string_is_not_compiled(client):
    r = await client.post("/render", json={"tpl": "{{ 7*7 }}"})
    assert r.status_code in (400, 404, 422)
    assert "49" not in r.text          # proves the string was never evaluated

@pytest.mark.anyio
async def test_mongo_operator_rejected(client):
    r = await client.post("/login", json={"email": {"$ne": None}, "password": {"$ne": None}})
    assert r.status_code == 422        # strict typing rejects a dict where a str is declared
```

```ts
// clone.injection.test.ts
it("refuses shell metacharacters and flag-shaped values", async () => {
  for (const repo of ["https://x.git; id", "--upload-pack=touch /tmp/pwned", "`id`"]) {
    const res = await request(app).post("/clone").send({ repo });
    expect(res.status).toBe(400);
  }
  expect(existsSync("/tmp/pwned")).toBe(false);
});

it("does not evaluate an expression body", async () => {
  expect((await request(app).post("/calc").send({ expr: "process.exit(1)" })).status).toBe(400);
});
```
