# Race Conditions and TOCTOU

**CWE:** CWE-362 (Concurrent Execution using Shared Resource without Proper Synchronization), CWE-367 (Time-of-Check Time-of-Use), CWE-366 (Race Condition within a Thread), CWE-837 (Improper Enforcement of a Single, Unique Action)

Two requests read the same state before either writes it, so a check that passed once is honoured twice — double spend, a coupon used N times, an oversold seat. Fix it at the layer that holds under concurrency, which is the database, not the application.

## How it gets introduced

- Check-then-act: `if balance >= amount:` ... `balance -= amount` across two statements, two round trips, or two requests.
- Read-modify-write in Python: `row.credits = row.credits - 1` issues `UPDATE ... SET credits = 9` with a value read earlier — the classic lost update.
- No idempotency key, so a double-clicked button or an HTTP timeout+retry creates two orders; uniqueness "enforced" by `SELECT ... if not exists: INSERT` with no UNIQUE constraint behind it.
- Celery `acks_late` / `autoretry_for` re-running a task whose side effect (charge, email, external POST) is not idempotent; a visibility timeout expiring mid-task redelivers the message. Webhooks have the same shape: providers retry, and a replayed body re-applies the effect.
- TOCTOU on files: `os.path.exists(p)` / `os.access(p)` then `open(p)`, or writing to a predictable temp path.
- An `asyncio.Lock` or in-process `Semaphore` treated as the guard — it disappears the moment a second uvicorn worker, pod, or Celery process exists.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
@app.post("/spend")
async def spend(uid: int, amount: int, session: AsyncSession = Depends(get_session)):
    acct = await session.get(Account, uid)
    if acct.balance < amount:                       # check
        raise HTTPException(400, "insufficient")
    acct.balance -= amount                          # act: separate statement, stale value
```

Fix in priority order: a constraint holds under any concurrency, a lock only where it is taken.

```python
# fixed — 1. constraint first — the DB refuses the bad state even if every code path is wrong
#    ALTER TABLE accounts ADD CONSTRAINT balance_non_negative CHECK (balance >= 0);
#    ALTER TABLE idempotency_keys ADD CONSTRAINT uq_key UNIQUE (tenant_id, key);

# 2. atomic UPDATE with the guard in the WHERE clause; decide on rowcount
@app.post("/spend")
async def spend(body: SpendReq, session: AsyncSession = Depends(get_session)):
    res = await session.execute(
        update(Account)
        .where(Account.id == body.uid, Account.balance >= body.amount)
        .values(balance=Account.balance - body.amount)   # column expression, not a Python value
        .returning(Account.balance))
    row = res.first()
    if row is None:                                      # zero rows == the guard failed
        await session.rollback()
        raise HTTPException(409, "insufficient funds")
    await session.commit()
    return {"balance": row.balance}

# 3. row lock, when you must read, compute, then write in one transaction
stmt = select(Account).where(Account.id == uid).with_for_update()  # skip_locked=True for queue claims
acct = (await session.scalars(stmt)).one()
await session.commit()      # lock held to commit: keep the block short, never an HTTP call inside
await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"inv:{inv_id}"})
# 4. advisory lock (above) when the thing to serialize is not a row
# 5. asyncio.Lock — single process only. Document the limit or do not use it.

# an idempotency key stops a retry doubling a side effect; the UNIQUE index picks the winner
async def claim(session: AsyncSession, tenant_id: int, key: str) -> bool:
    res = await session.execute(
        pg_insert(IdempotencyKey).values(tenant_id=tenant_id, key=key)
        .on_conflict_do_nothing(index_elements=["tenant_id", "key"]).returning(IdempotencyKey.id))
    return res.first() is not None       # False == already processed: replay the stored response

if not await claim(session, tenant.id, request.headers["Idempotency-Key"]):
    return await stored_response(session, tenant.id, key)
```

Isolation: Postgres defaults to READ COMMITTED, which does **not** prevent lost updates — each statement sees a fresh snapshot, so two concurrent read-modify-writes both succeed. SERIALIZABLE prevents the anomaly but raises SQLSTATE `40001`, so it is only correct with a retry loop. Celery tasks claim their work instead of trusting delivery once:

```python
# fixed
for attempt in range(3):
    try:
        async with session.begin():
            await session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            ...
        break
    except DBAPIError as e:                         # the retry loop is mandatory, not optional
        if getattr(e.orig, "sqlstate", None) != "40001" or attempt == 2: raise
        await anyio.sleep(0.05 * 2**attempt)

@app_celery.task(acks_late=True, max_retries=3)     # acks_late: the task WILL run twice on a worker kill
def charge(order_id: str) -> None:
    with Session() as s, s.begin():
        res = s.execute(update(Order).where(Order.id == order_id, Order.status == "pending")
                        .values(status="charging"))
        if res.rowcount == 0: return                # another delivery already claimed it
    provider.charge(order_id, idempotency_key=order_id)   # pass a key to the external API too

# files: open and handle the error instead of checking first
if not os.path.exists(p): open(p, "w").write(data)             # vulnerable: TOCTOU
os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)        # fixed: atomic create-or-fail
```

## JS / TS / Node / React

```ts
// vulnerable
const acct = await prisma.account.findUnique({ where: { id } });
if (acct.balance < amount) throw new BadRequest("insufficient");
await prisma.account.update({ where: { id }, data: { balance: acct.balance - amount } });

// fixed — conditional atomic update; count tells you whether the guard held
const { count } = await prisma.account.updateMany({
  where: { id, balance: { gte: amount } },
  data: { balance: { decrement: amount } },      // computed in the DB, not in Node
});
if (count === 0) throw new Conflict("insufficient funds");

try {                                            // idempotency: let the UNIQUE index decide
  await prisma.idempotencyKey.create({ data: { tenantId, key } });
} catch (e) {
  if ((e as Prisma.PrismaClientKnownRequestError).code !== "P2002") throw e;
  return storedResponse(tenantId, key);          // a replay: return what the first call produced
}
await prisma.$transaction(async (tx) =>          // row lock when a read must precede the write
  tx.$queryRaw<Row[]>`SELECT * FROM seats WHERE id = ${id} FOR UPDATE`);
```

Node is single-threaded but not atomic across `await`: every `await` is a yield point, so two requests interleave freely. A module-level `Map` lock dies with cluster mode and a second pod.
## The safe API, per framework

| Layer (strongest first) | Use |
|---|---|
| DB constraint | `UNIQUE (tenant_id, key)`, `CHECK (balance >= 0)`, exclusion constraints for overlapping bookings |
| Atomic UPDATE | SQLAlchemy `update().where(guard).values(col=col - x)` + `rowcount`/`returning`; Prisma `updateMany` + `count`, `{ decrement }` |
| Upsert | `postgresql.insert(...).on_conflict_do_nothing/do_update`; Prisma `upsert` |
| Row / advisory lock | `select(...).with_for_update(skip_locked=True)` in a transaction; `pg_advisory_xact_lock(key)`, released at commit |
| Isolation | SERIALIZABLE **plus** a `40001` retry loop; REPEATABLE READ for consistent reads |
| Distributed / in-process lock | Redis `SET key val NX PX ttl` with a fencing token (liveness, not correctness); `asyncio.Lock` single-worker only — never for money |
| Celery / webhooks | `acks_late` + a status-claiming conditional UPDATE; store the provider's event id under a UNIQUE constraint and pass an idempotency key to external APIs |
| Files | `os.O_CREAT | os.O_EXCL`, `tempfile.mkstemp`, and `os.replace` for an atomic swap |

## Grep for

```
rg -n -B3 'balance\s*-=|credits\s*-=|quantity\s*-=|\.count\s*-=' -g '*.py'  # read-modify-write; read the preceding check
rg -nU 'if\s+[a-z_.]*(balance|credits|quota|stock|seats)[^\n]*<[^\n]*\n[\s\S]{0,300}?(commit|update)\(' -g '*.py'  # check-then-act window
rg -n 'session\.get\(|scalars\(select' -A6 | rg 'commit\(\)'   # read then write, no lock or guard between
rg -n 'with_for_update|FOR UPDATE|pg_advisory'            # existing locking — confirm it covers every writer
rg -n 'Idempotency-Key|idempotency_key|unique\s*=\s*True|UniqueConstraint|UNIQUE \('  # keys and constraints that exist; compare to the invariants
rg -n 'acks_late|autoretry_for|max_retries'               # at-least-once delivery: the task must be idempotent
rg -n '@app\.task' -A4 | rg -v 'idempot|rowcount|on_conflict'  # side-effecting tasks with no claim step
rg -n 'asyncio\.Lock\(|threading\.Lock\(' -g '*.py'       # in-process only; worthless with >1 worker
rg -n 'os\.path\.exists\(|os\.access\(' -A3 | rg 'open\(|shutil\.'  # TOCTOU on files
rg -n 'findUnique|findFirst' -A5 -g '*.ts' | rg '\.update\('  # read-then-update in Prisma, no guard in the WHERE
rg -n 'webhook' -g '*.py' -g '*.ts' -A6 | rg -v 'event_id|dedup|signature'  # replayable webhook handler
rg -n 'ISOLATION LEVEL SERIALIZABLE' -A8 | rg -v '40001|serialization_failure'  # SERIALIZABLE with no retry loop
```

## False positives

- Read-modify-write inside a transaction that already took `with_for_update()` on that row and commits before any other work begins.
- A counter whose exact value does not matter (page views, a best-effort metric), or an `asyncio.Lock` guarding a process-local resource (an in-memory cache, a client pool) rather than a shared invariant.
- A check-then-act whose invariant is also enforced by a `CHECK`/`UNIQUE` constraint — the race becomes a 409, not a bad state. Confirm the constraint exists in a migration, not just in the model.
- `updateMany` / `update().where(...)` with the guard in the `WHERE` — that is the fix, not the bug. Likewise single-writer paths (a `beat` schedule with one owner, a job claimed by `FOR UPDATE SKIP LOCKED`) and idempotent side effects (a `PUT` of an absolute value, a call carrying a provider idempotency key).

## Regression test

Concurrency, not sequence — a sequential version of this test passes before the fix.

```python
# tests/test_spend_race.py — needs a real DB and a concurrent client, not a sqlite in-memory one
import asyncio, pytest
from sqlalchemy import func, select

@pytest.mark.anyio
async def test_concurrent_spends_cannot_overdraw(client, session, account_factory):
    acct = await account_factory(balance=100)
    rs = await asyncio.gather(
        *[client.post("/spend", json={"uid": acct.id, "amount": 100}) for _ in range(20)],
        return_exceptions=True)
    assert len([r for r in rs if getattr(r, "status_code", None) == 200]) == 1   # exactly one winner
    await session.refresh(acct)
    assert acct.balance == 0                              # never negative, never a lost update

@pytest.mark.anyio
async def test_same_idempotency_key_creates_one_order(client, session):
    h = {"Idempotency-Key": "k-123"}
    rs = await asyncio.gather(*[client.post("/orders", json={"sku": "a"}, headers=h) for _ in range(10)])
    assert len({r.json()["id"] for r in rs}) == 1         # one order id, returned every time
    assert await session.scalar(select(func.count()).select_from(Order)) == 1

@pytest.mark.anyio
async def test_webhook_replay_applies_once(client, session, signed_event):   # provider retries
    await asyncio.gather(*[client.post("/webhooks/stripe", **signed_event) for _ in range(5)])
    assert await session.scalar(select(func.count()).select_from(Payment)) == 1
```

```ts
// spend.race.test.ts
it("only one of twenty concurrent spends succeeds", async () => {
  await prisma.account.update({ where: { id }, data: { balance: 100 } });
  const rs = await Promise.all(Array.from({ length: 20 }, () =>
    request(app).post("/spend").send({ id, amount: 100 })));
  expect(rs.filter((r) => r.status === 200)).toHaveLength(1);
  expect((await prisma.account.findUniqueOrThrow({ where: { id } })).balance).toBe(0);
});
```
