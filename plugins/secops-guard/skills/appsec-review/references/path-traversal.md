# Path Traversal

**CWE:** CWE-22 (Path Traversal), CWE-23 (Relative Path Traversal), CWE-59 (Link Following), CWE-434 (Unrestricted Upload of File with Dangerous Type)

A request-controlled string is used to build a filesystem path, so the caller escapes the intended directory and reads or writes arbitrary files. Also known as directory traversal or, on extraction, zip-slip.

## How it gets introduced

- Joining a user-supplied name onto a base directory and opening it with no containment check: `open(BASE + "/" + name)`, `FileResponse(f"{BASE}/{name}")`.
- `os.path.join(BASE, name)` where `name` is absolute (`/etc/passwd`, `C:\Windows\...`) — join silently **discards** the base and returns the absolute path.
- Stripping `../` once, or blocking only the literal `..`, instead of resolving the final path. `....//` survives one strip; `%2e%2e%2f` and `..%5c` survive naive string checks after the framework decodes them.
- Archive extraction that trusts member names: `zipfile.extractall`, `tarfile.extractall` (pre-3.12 default), `unzipper`/`tar` in Node — entries may be `../../etc/cron.d/x` or symlinks.
- Uploads stored under the client-supplied filename (`UploadFile.filename`, `file.originalname`), which carries the path and the extension the attacker chose.
- Downloads served by name: `send_file`, `res.sendFile`, `res.download`, Next.js route handlers reading from `public/` or a data dir by slug.
- Resolving through a symlink that points outside the base, or checking containment before resolving instead of after.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
BASE = Path("/srv/reports")

@app.get("/reports/{name}")
async def download(name: str):
    return FileResponse(os.path.join(BASE, name))   # name="../../etc/passwd" or "/etc/passwd"
```

```python
# fixed
from pathlib import Path
from fastapi import HTTPException

BASE = Path("/srv/reports").resolve()

def safe_path(base: Path, name: str) -> Path:
    # resolve() collapses .. and follows symlinks; check containment AFTER resolving
    candidate = (base / name).resolve()
    if not candidate.is_relative_to(base):          # py3.9+; else os.path.commonpath([base, candidate]) == str(base)
        raise HTTPException(404)                    # 404, not 403: do not confirm what exists outside
    if candidate.is_symlink() or not candidate.is_file():
        raise HTTPException(404)
    return candidate

@app.get("/reports/{report_id}")
async def download(report_id: UUID, session: AsyncSession = Depends(get_session)):
    # best pattern: the client never names a file. Look up a stored id, use the server-generated name.
    report = await session.get(Report, report_id)
    if report is None:
        raise HTTPException(404)
    return FileResponse(safe_path(BASE, report.stored_name), filename=report.display_name)
```

Uploads — generate the name, keep the original only as a label:

```python
# fixed
import uuid, mimetypes

ALLOWED = {"application/pdf": ".pdf", "image/png": ".png"}

async def save_upload(f: UploadFile) -> str:
    ext = ALLOWED.get(f.content_type)
    if ext is None:
        raise HTTPException(415)
    stored = f"{uuid.uuid4().hex}{ext}"             # never f.filename on disk
    (BASE / stored).write_bytes(await f.read())
    return stored
```

Archive extraction:

```python
# fixed
with zipfile.ZipFile(src) as z:
    for m in z.infolist():
        dest = (BASE / m.filename).resolve()
        if not dest.is_relative_to(BASE):
            raise ValueError(f"zip-slip entry: {m.filename}")
    z.extractall(BASE)
# tarfile on 3.12+: tar.extractall(BASE, filter="data")  — rejects absolute paths, .., links, devices
```

Windows: `Path.resolve()` normalizes `\` and `/`, drive letters and `\\?\`/UNC prefixes. Do not hand-roll a separator check — `..\\`, `..%5c` and `C:..\x` all need the resolve step. Reject names containing a drive letter or starting with `\\` before joining.

## JS / TS / Node / React

```ts
// vulnerable
app.get("/reports/:name", (req, res) => {
  res.sendFile(path.join(BASE, req.params.name));  // join does not contain; absolute wins
});
```

```ts
// fixed
import path from "node:path";
import fs from "node:fs/promises";

const BASE = path.resolve("/srv/reports");

export function safePath(name: string): string {
  const candidate = path.resolve(BASE, name);
  const rel = path.relative(BASE, candidate);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) throw new NotFound();
  return candidate;
}

app.get("/reports/:id", async (req, res) => {
  const report = await db.report.findUnique({ where: { id: req.params.id } });
  if (!report) return res.sendStatus(404);
  const file = safePath(report.storedName);
  const st = await fs.lstat(file);
  if (st.isSymbolicLink() || !st.isFile()) return res.sendStatus(404);
  res.sendFile(file, { dotfiles: "deny" });
});
```

`res.sendFile(name, { root: BASE })` is the built-in containment: Express rejects `..` and absolute paths when `root` is set. Prefer it over a hand-built absolute path.

## The safe API, per framework

| Framework | Use |
|---|---|
| Python stdlib | `(base / name).resolve()` then `Path.is_relative_to(base)`; `os.path.commonpath` pre-3.9 |
| FastAPI / Starlette | `StaticFiles(directory=...)` for static assets; `FileResponse` only on a validated path |
| Flask | `send_from_directory(dir, name)` (contains internally); `werkzeug.utils.secure_filename` for upload labels |
| tarfile (3.12+) | `extractall(dest, filter="data")` |
| zipfile | pre-validate every `infolist()` entry against the resolved base |
| Express | `res.sendFile(name, { root })` / `express.static(dir, { dotfiles: "deny" })` |
| Node generic | `path.resolve` + `path.relative(base, p)` not starting with `..` |
| Next.js route handlers | map a slug through an allowlist or DB row; never `fs.readFile(join(dir, params.slug))` |
| Uploads anywhere | server-generated UUID name + extension from an allowlisted content type |

## Grep for

```
rg -n 'os\.path\.join\([^)]*(request|params|query|filename|name)' -g '*.py'  # join with request data — absolute arg wipes the base
rg -n 'open\(\s*[^)]*\+\s*|open\(\s*f["\x27]' -g '*.py'          # path built by concatenation or f-string
rg -n 'FileResponse\(|send_file\(|send_from_directory\('          # file served by name — check containment
rg -n 'extractall\(' -g '*.py' | rg -v 'filter='                  # zip/tar extraction with no member validation
rg -n '\.filename|originalname' -A3 | rg 'join|open|write|save'   # client filename reaching the filesystem
rg -n 'res\.(sendFile|download)\(' -A1 | rg -v 'root:'            # Express file send without a root
rg -n 'path\.join\([^)]*req\.(params|query|body)'                 # Node join with request data
rg -n 'replace\(["\x27]\.\./|strip\(["\x27]\.\.|\breplace\(/\.\.\//'  # blacklist cleanup instead of resolve+contain
rg -n 'readFile(Sync)?\([^)]*(params|query|slug)'                 # Next.js/Node read keyed by a URL segment
rg -n 'is_relative_to|commonpath|path\.relative\('                # the control itself — confirm it runs AFTER resolve
```

## False positives

- A path built from a literal, a config value, or an enum member with no request-reachable source.
- `send_from_directory`, `express.static` and `res.sendFile(name, { root })` — containment is inside the API.
- `os.path.join(BASE, uuid4().hex)` or any server-generated name: no user bytes in the path.
- A name already validated against a dict/`Literal` allowlist, or a parsed `UUID` path param (FastAPI rejects anything else with 422 before the handler runs).
- `secure_filename()` output used as a *label* while the on-disk name is generated — the label never reaches `open()`.
- `extractall(dest, filter="data")` on Python 3.12+, and extraction into a fresh temp dir that is discarded, where escape still matters only if the dir is a parent of real data — verify, do not assume.

## Regression test

```python
# tests/test_path_traversal.py
import pytest

ESCAPE_INPUTS = [
    "../../etc/passwd",
    "/etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..\\..\\windows\\win.ini",
    "..%5c..%5cwindows%5cwin.ini",
]

@pytest.mark.parametrize("name", ESCAPE_INPUTS)
@pytest.mark.anyio
async def test_download_rejects_escape(client, name):
    r = await client.get(f"/reports/{name}")
    assert r.status_code in (404, 422)
    assert b"root:" not in r.content        # nothing from outside the base leaked

@pytest.mark.anyio
async def test_symlink_out_of_base_is_refused(client, tmp_base):
    (tmp_base / "escape.txt").symlink_to("/etc/passwd")
    r = await client.get("/reports/escape.txt")
    assert r.status_code == 404

def test_zip_slip_entry_is_rejected(tmp_path, make_zip):
    evil = make_zip({"../../pwned.txt": b"x"})
    with pytest.raises(ValueError):
        extract_archive(evil, tmp_path)
    assert not (tmp_path.parent.parent / "pwned.txt").exists()

@pytest.mark.anyio
async def test_upload_does_not_use_client_filename(client, tmp_base):
    r = await client.post("/upload", files={"file": ("../../evil.pdf", b"%PDF-", "application/pdf")})
    assert r.status_code == 200
    assert not (tmp_base.parent.parent / "evil.pdf").exists()
```

```ts
// reports.traversal.test.ts
it.each(["../../etc/passwd", "/etc/passwd", "..%2f..%2fetc%2fpasswd"])("refuses %s", async (p) => {
  const res = await request(app).get(`/reports/${encodeURIComponent(p)}`);
  expect(res.status).toBe(404);
  expect(res.text).not.toContain("root:");
});
```
