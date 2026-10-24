# SQL Injection

**CWE:** CWE-89 (SQL Injection), CWE-564 (SQL Injection: Hibernate/ORM), CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)

Untrusted input is concatenated into a query string, so the database parses attacker data as SQL syntax instead of as a value. Parameterization fixes values; identifiers and keywords need an allowlist.

## How it gets introduced

- f-strings, `%`, `.format()` or `+` used to build the SQL handed to `text()`, `session.execute()`, `cursor.execute()` or `conn.exec_driver_sql()`.
- Dynamic `ORDER BY`, `LIMIT`, column names, table names or `ASC/DESC` taken from query params — bind parameters cannot cover identifiers, so developers fall back to concatenation.
- `IN (...)` lists built by joining a user-supplied list with `,` instead of expanding one bind per element.
- Belief that "using the ORM" is enough: `filter(text(f"..."))`, `order_by(text(user_col))` and raw fragments inside `having`/`join` conditions are still raw SQL.
- Prisma `$queryRawUnsafe` / `$executeRawUnsafe`, Knex `knex.raw` with interpolation, Sequelize raw queries without `replacements`, `pg` with template-built strings.
- Second-order: a value is stored safely, then later read back out of the database and concatenated into another query (bulk jobs, report builders, admin tooling).

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
@app.get("/orders")
async def orders(status: str, sort: str, session: AsyncSession = Depends(get_session)):
    rows = await session.execute(
        text(f"SELECT * FROM orders WHERE status = '{status}' ORDER BY {sort}")
    )
    return rows.mappings().all()
```

```python
# fixed
from typing import Literal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

SORTABLE = {"created_at": Order.created_at, "total": Order.total}  # allowlist: identifiers cannot be bound

class OrderQuery(BaseModel):
    status: Literal["open", "paid", "cancelled"]
    sort: Literal["created_at", "total"] = "created_at"
    desc: bool = False
    ids: list[int] = Field(default_factory=list, max_length=500)

@app.get("/orders")
async def orders(q: Annotated[OrderQuery, Query()], session: AsyncSession = Depends(get_session)):
    col = SORTABLE[q.sort]
    stmt = select(Order).where(Order.status == q.status).order_by(col.desc() if q.desc else col.asc())
    if q.ids:
        stmt = stmt.where(Order.id.in_(q.ids))  # expands to one bind per element
    return (await session.scalars(stmt)).all()
```

Raw SQL when the ORM is not wanted — still bound, never formatted:

```python
# fixed
await session.execute(
    text("SELECT * FROM orders WHERE status = :status AND id = ANY(:ids)"),
    {"status": status, "ids": ids},
)
# asyncpg uses positional $1 placeholders, psycopg3 uses %s with a params tuple:
await conn.fetch("SELECT * FROM orders WHERE status = $1", status)
await acur.execute("SELECT * FROM orders WHERE status = %s", (status,))
```

Never pass user data through `psycopg.sql.SQL(...)`; for a dynamic identifier use `psycopg.sql.Identifier(name)` **after** checking `name` against an allowlist.

## JS / TS / Node / React

```ts
// vulnerable
const rows = await prisma.$queryRawUnsafe(
  `SELECT * FROM orders WHERE status = '${status}' ORDER BY ${sort}`
);
```

```ts
// fixed
const SORTABLE = { created_at: "created_at", total: "total" } as const;
const col = SORTABLE[sort as keyof typeof SORTABLE];
if (!col) throw new BadRequest("bad sort");

// tagged template: values become bind parameters, Prisma.sql/raw composes the checked identifier
const rows = await prisma.$queryRaw<Order[]>`
  SELECT * FROM orders
  WHERE status = ${status}
  ORDER BY ${Prisma.raw(col)}
`;

// node-postgres
await pool.query("SELECT * FROM orders WHERE status = $1 AND id = ANY($2)", [status, ids]);

// knex: binding, not interpolation
await knex("orders").where({ status }).whereIn("id", ids).orderBy(col, dir);
await knex.raw("SELECT * FROM orders WHERE status = ?", [status]);

// sequelize
await sequelize.query("SELECT * FROM orders WHERE status = :status", {
  replacements: { status },
  type: QueryTypes.SELECT,
});
```

`$queryRaw` is safe only as a tagged template. `prisma.$queryRaw(someString)` called as a function is equivalent to the unsafe variant.

## The safe API, per framework

| Framework | Use |
|---|---|
| SQLAlchemy 2.x ORM | `select()` / `where()` / `in_()` with Python values |
| SQLAlchemy Core raw | `text("… :name")` + params dict (second arg of `execute`) |
| Dynamic column/table | dict allowlist mapped to a mapped-column object, never a string |
| asyncpg | `$1, $2` positional args |
| psycopg3 | `%s` with a params sequence; `sql.Identifier()` for checked identifiers |
| Prisma | `$queryRaw` tagged template; `Prisma.raw()` only for allowlisted identifiers |
| Knex | query builder, or `knex.raw(sql, [bindings])` |
| Sequelize | `replacements` (or `bind`), `QueryTypes` |
| Django | ORM, or `.raw(sql, params)` / `cursor.execute(sql, params)` |

## Grep for

```
rg -n 'text\(\s*f["\']'                         # f-string straight into SQLAlchemy text() — almost always injectable
rg -n '(execute|exec_driver_sql)\([^)]*%\s*\(?[a-z_]'   # %-formatting built into the SQL argument
rg -n '\.format\([^)]*\)\s*\)' -g '*.py'        # .format() result passed as a query
rg -n 'SELECT .*\{' -g '*.py' -g '*.ts'         # interpolation inside a SQL literal
rg -n 'order_by\(text\(|filter\(text\(|having\(text\('  # raw fragments inside ORM calls
rg -n '\$query(Raw|RawUnsafe)|\$executeRawUnsafe'        # Unsafe variants are never safe; plain $queryRaw must be a tagged template
rg -n 'knex\.raw\([`"\x27][^`"\x27]*\$\{'        # template interpolation in knex.raw
rg -n 'sequelize\.query\(' -A3 | rg -v 'replacements|bind'  # raw Sequelize query with no bindings
rg -n 'cursor\.execute\([^,)]*\+\s*'            # string concatenation into DB-API execute
rg -n 'ORDER BY|LIMIT' -g '*.py' -g '*.ts' | rg '\$\{|\{[a-z_]+\}|%s%|\+ '   # dynamic ordering — needs an allowlist
```

## False positives

- `text("… WHERE id = :id")` with a params dict: `:name` is a bind parameter, not interpolation.
- An f-string that interpolates only module-level constants or a value already looked up in an allowlist dict — confirm the variable cannot come from a request.
- `.in_(list_of_values)` and `ANY(:ids)`: SQLAlchemy and the driver expand these as binds, not as text.
- Migration scripts and one-off admin scripts whose input is a literal in the file, with no request path reaching them.
- `Prisma.sql` / `$queryRaw` tagged templates: `${value}` inside a tagged template is a bind, not concatenation. Check it is a tag, not a function call.
- Table names interpolated from an enum, `__tablename__`, or an internal mapping — safe as long as the source cannot be user-controlled.

## Regression test

```python
# tests/test_orders_sqli.py
import pytest

@pytest.mark.anyio
async def test_sort_param_is_allowlisted(client, seeded_orders):
    r = await client.get("/orders", params={"status": "open", "sort": "created_at; DROP TABLE orders--"})
    assert r.status_code == 422                     # rejected before reaching the DB

@pytest.mark.anyio
async def test_status_quote_is_bound_not_parsed(client, session):
    r = await client.get("/orders", params={"status": "open' OR '1'='1"})
    assert r.status_code == 422                     # Literal[] rejects it
    assert (await session.scalar(select(func.count()).select_from(Order))) > 0  # table still there

@pytest.mark.anyio
async def test_second_order_value_is_not_executed(client, session):
    await session.execute(insert(Order).values(status="open", note="x'; DROP TABLE orders--"))
    await session.commit()
    r = await client.get("/reports/notes")          # report re-reads stored notes into a query
    assert r.status_code == 200
    assert await session.scalar(select(func.count()).select_from(Order)) == 1
```

```ts
// orders.sqli.test.ts
it("rejects an injected sort column", async () => {
  const res = await request(app).get("/orders?sort=total;DROP TABLE orders");
  expect(res.status).toBe(400);
  expect(await prisma.order.count()).toBeGreaterThan(0);
});

it("treats a quote in a value as data", async () => {
  await prisma.order.create({ data: { status: "open' OR '1'='1" } });
  const res = await request(app).get("/orders?status=open");
  expect(res.body).toHaveLength(0); // the quote matched nothing; it did not widen the query
});
```
