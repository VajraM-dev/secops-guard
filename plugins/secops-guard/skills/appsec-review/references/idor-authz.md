# IDOR and Broken Authorization

**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-285 (Improper Authorization), CWE-915 (Mass Assignment)

Authentication proves who the caller is. Authorization decides what that caller may touch. A route that only checks the first one hands every object to every logged-in user who can guess an id.

## How it gets introduced

- A handler loads by primary key alone (`session.get(Doc, doc_id)`) and never compares the row's owner or tenant to the caller.
- The ownership check lives in an `if` *after* the fetch, so a later refactor, an early `return`, or a new branch skips it.
- `tenant_id` is in the model and in the JWT but missing from the `where()` of some queries — usually the newest ones, or list/export/bulk endpoints.
- A request model is reused as the DB write model, so an extra JSON key (`role`, `owner_id`, `is_admin`, `tenant_id`) flows straight into the ORM object.
- A new route is added without `Depends(require_role(...))` because the decorator is per-route, not per-router.
- The UI hides the admin button, and the backend route behind it is left unguarded ("nobody can see it").
- Nested/related objects are authorized at the parent only: `/projects/{pid}/docs/{did}` checks `pid` and then fetches `did` globally.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
@router.patch("/docs/{doc_id}")
async def update_doc(doc_id: UUID, body: DocIn, s: AsyncSession = Depends(db), u: User = Depends(current_user)):
    doc = await s.get(Doc, doc_id)              # no tenant, no owner
    for k, v in body.model_dump().items():      # body carries owner_id, role...
        setattr(doc, k, v)
    await s.commit()
    return doc
```

```python
# fixed
class DocUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown keys outright
    title: str | None = None
    body: str | None = None
    # owner_id / tenant_id / status deliberately absent: server-owned fields

def tenant_scoped(stmt, u: User):
    """Every read of a tenant-owned table goes through here."""
    return stmt.where(Doc.tenant_id == u.tenant_id, Doc.deleted_at.is_(None))

async def get_owned_doc(doc_id: UUID, s: AsyncSession, u: User) -> Doc:
    # ownership is a predicate in the query, not a branch after it
    stmt = tenant_scoped(select(Doc).where(Doc.id == doc_id), u)
    doc = (await s.execute(stmt)).scalar_one_or_none()
    if doc is None:
        raise HTTPException(404)                # 404 before 403: no enumeration oracle
    return doc

@router.patch("/docs/{doc_id}", dependencies=[Depends(require_role("editor"))])
async def update_doc(doc_id: UUID, body: DocUpdate,
                     s: AsyncSession = Depends(db), u: User = Depends(current_user)):
    doc = await get_owned_doc(doc_id, s, u)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(doc, k, v)
    await s.commit()
    return DocOut.model_validate(doc)           # separate response model
```

Make tenant scoping the default, not a thing to remember: one repository/base-query layer that every handler calls, so an unscoped `select(Doc)` in a route is visible in review. Add `APIRouter(dependencies=[Depends(require_role("admin"))])` for admin routers so a forgotten decorator cannot happen per-route.

Sequential integer ids make enumeration trivial; UUIDv7 (`uuid_utils.uuid7`) reduces discoverability but is **not** a control — the query predicate is the control.

Error ordering: return **404** for an object outside the caller's tenant and **403** only for an object the caller can see but may not act on. A 403 on a row that is not theirs confirms the row exists.

## JS / TS / Node / React

```ts
// vulnerable
app.get("/api/invoices/:id", requireAuth, async (req, res) => {
  const inv = await db.invoice.findUnique({ where: { id: req.params.id } });
  res.json(inv);                       // any authenticated user reads any invoice
});
```

```ts
// fixed
// one helper; routes never call findUnique on a tenant table directly
const scoped = (user: AuthUser) => ({ tenantId: user.tenantId, deletedAt: null });

app.get("/api/invoices/:id", requireAuth, async (req, res) => {
  const inv = await db.invoice.findFirst({
    where: { id: req.params.id, ...scoped(req.user) },   // tenant in the WHERE
  });
  if (!inv) return res.sendStatus(404);
  res.json(invoiceDto(inv));                              // explicit field allowlist
});

// Next.js server action: the session is the only source of identity
export async function updateInvoice(id: string, form: FormData) {
  const session = await auth();
  if (!session) throw new Error("unauthorized");
  const parsed = InvoiceUpdate.parse(Object.fromEntries(form)); // zod .strict()
  const { count } = await db.invoice.updateMany({
    where: { id, tenantId: session.user.tenantId },            // scope in the update
    data: parsed,
  });
  if (count === 0) throw new Error("not found");
}
```

Never trust `tenantId`, `userId` or `role` from the request body, a header, or a hidden form field — read them from the verified session. A frontend that hides a route is not authorization; the same check must exist server-side.

GraphQL: a `node(id:)` resolver and every `DataLoader` must re-apply the tenant predicate. Field-level resolvers on a nested type bypass the parent's check unless the loader is tenant-keyed.

## The safe API, per framework

| Framework | Built-in control to use |
|---|---|
| FastAPI | `Depends(require_role(...))` on `APIRouter(dependencies=[...])`; a scoped repository for all queries |
| Pydantic v2 | `ConfigDict(extra="forbid")`; distinct `XIn` / `XUpdate` / `XOut` models; `model_dump(exclude_unset=True)` |
| SQLAlchemy 2.x | Ownership as `where()` predicates; `with_loader_criteria(Doc, lambda c: c.tenant_id == tid)` for eager loads |
| Postgres | Row-level security as defence in depth (`SET LOCAL app.tenant_id`) |
| Express | Auth middleware mounted on the router; a `scoped(user)` where-builder |
| Prisma | `findFirst`/`updateMany` with tenant in `where`; Prisma client extensions for global scoping |
| Next.js | `auth()` inside every server action and route handler; never a client-passed identity |
| GraphQL | Tenant-aware DataLoaders; authz in resolvers, not only at the root query |

## Grep for

```
rg -n 'session\.get\((Doc|User|Invoice|[A-Z]\w+),'          # get() by PK: check for a tenant predicate nearby
rg -n 'select\([A-Z]\w+\)(?!.*tenant)' -P                    # select on a model with no tenant_id in the statement
rg -n '\.where\([A-Z]\w+\.id\s*==' -A2                       # id-only predicate; is tenant_id on the next line?
rg -n '@(router|app)\.(get|post|put|patch|delete)\(' -A3     # scan each route for a require_role / current_user dep
rg -n 'class \w+(In|Create|Update)\(BaseModel\)' -A3         # request models without extra="forbid"
rg -n 'setattr\(\w+,\s*k' -B3                                # loop-assign from a request body: mass assignment
rg -n '\*\*(body|payload|data)\.(model_)?dump\(\)'           # splatting a request body into an ORM constructor
rg -n 'findUnique\(\{\s*where:\s*\{\s*id'                    # Prisma lookup by id alone
rg -n 'Object\.assign\((user|doc|row|entity)\s*,\s*req\.body' # overposting in Node
rg -n 'req\.(body|query|headers)\[?[\x27"]?(tenantId|userId|role|isAdmin)' # identity taken from the request
rg -n 'is_admin|isAdmin|role\s*===?\s*[\x27"]admin'          # inline role checks; should be a shared dependency
rg -n 'extra\s*=\s*[\x27"]allow[\x27"]'                      # Pydantic explicitly accepting unknown fields
rg -n 'async def node\(|resolve_node|def resolve_\w+\(' -A3  # GraphQL resolvers that may skip tenant scoping
```

## False positives

- `session.get(Model, pk)` on a global, non-tenant table (feature flags, currency codes, country list) — nothing to scope.
- A query with no visible tenant filter when PostgreSQL RLS is active and the session variable is set in the connection hook — check the session setup before reporting.
- `select(Doc)` inside an admin/ops script or a Celery task that legitimately runs cross-tenant with no HTTP caller.
- `extra="allow"` on a model that stores an opaque, untyped `metadata` blob never mapped onto an ORM object.
- A route with no `require_role` that is mounted on a router already carrying `dependencies=[Depends(require_role(...))]`.
- Sequential integer ids on objects that are genuinely public (blog posts, published docs) where exposure is the point.

## Regression test

```python
# tests/test_idor.py
import pytest

@pytest.mark.anyio
async def test_cross_tenant_doc_is_not_readable(client, doc_of_tenant_a, token_tenant_b):
    r = await client.get(f"/docs/{doc_of_tenant_a.id}",
                         headers={"Authorization": f"Bearer {token_tenant_b}"})
    assert r.status_code == 404          # 404, not 403: no existence oracle

@pytest.mark.anyio
async def test_cross_tenant_doc_is_not_writable(client, doc_of_tenant_a, token_tenant_b, session):
    r = await client.patch(f"/docs/{doc_of_tenant_a.id}", json={"title": "pwned"},
                           headers={"Authorization": f"Bearer {token_tenant_b}"})
    assert r.status_code == 404
    await session.refresh(doc_of_tenant_a)
    assert doc_of_tenant_a.title != "pwned"   # the row really did not change

@pytest.mark.anyio
async def test_overposting_role_is_rejected(client, own_doc, token_viewer, session):
    r = await client.patch(f"/docs/{own_doc.id}",
                           json={"title": "ok", "owner_id": "00000000-0000-0000-0000-000000000001"},
                           headers={"Authorization": f"Bearer {token_viewer}"})
    assert r.status_code == 422               # extra="forbid" rejects the unknown key
    await session.refresh(own_doc)
    assert str(own_doc.owner_id) != "00000000-0000-0000-0000-000000000001"

@pytest.mark.anyio
async def test_admin_route_requires_role(client, token_viewer):
    r = await client.get("/admin/users", headers={"Authorization": f"Bearer {token_viewer}"})
    assert r.status_code == 403
```
