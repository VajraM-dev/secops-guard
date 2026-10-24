# Business Logic Flaws

**CWE:** CWE-840 (Business Logic Errors), CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-682 (Incorrect Calculation), CWE-190 (Integer Overflow or Wraparound), CWE-770 (Allocation of Resources Without Limits or Throttling)

The code does exactly what it was written to do, and that is the bug: it trusts a price, a quantity, a state or a timestamp the client chose. No scanner finds these — the review pass is the only control.

## How it gets introduced

- Price, total, discount, tax, currency or credits arrive in the request body and are charged or persisted as-is instead of recomputed from server-side catalogue data; money is `float` rather than `Decimal` or integer minor units, so rounding and repeated partial refunds drift.
- Quantity, refund and transfer amounts are validated as "a number" — not `> 0`, not upper-bounded, not checked against what was actually paid, so negatives credit the account and huge values overflow.
- `status` is a free string written straight from the request, so a client PATCHes `shipped` or `approved` and skips payment, review or fulfilment; approval asks "is the caller an approver?" and never "is the caller the requester?" (self-approval of your own expense or refund).
- Coupon, trial and referral redemption is checked per request, with no per-account redemption row and no unique index.
- Quotas and rate limits are keyed on the request (IP, API key, device) instead of the account, so N keys multiply the free tier; the entitlement check often lives only in the React component that hides the button.
- A webhook is signature-verified but its event id is never stored, so a replayed signed body credits twice; expiry is compared against a client-supplied timestamp; a share/invite flow lets the inviter pick the grantee's role.

Concurrency variants — double-spend, a coupon redeemed twice in parallel, check-then-debit — are in `race-conditions.md`; those fixes (row locks, atomic `UPDATE … WHERE`, unique constraints) are needed *in addition* to these.

## Python / FastAPI / SQLAlchemy / Pydantic

```python
# vulnerable
@router.post("/orders")
async def create_order(body: dict, s: AsyncSession = Depends(db), u: User = Depends(current_user)):
    total = body["price"] * body["qty"] - body.get("discount", 0)   # all client-supplied
    order = Order(user_id=u.id, total=total, status=body.get("status", "pending"))
    s.add(order); await s.commit()
    return order
```

```python
# fixed
class OrderLineIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sku: str
    qty: int = Field(gt=0, le=100)                       # never 0, never negative, bounded

class OrderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")            # price/total/currency/status: server-owned
    lines: list[OrderLineIn] = Field(min_length=1, max_length=50)
    coupon: str | None = None

# money as integer minor units (or Numeric(12, 2) + Decimal); never float
async def price_order(s: AsyncSession, body: OrderIn, u: User) -> tuple[int, str]:
    skus = {l.sku: l.qty for l in body.lines}
    rows = (await s.scalars(select(Product).where(Product.sku.in_(skus)))).all()
    currencies = {p.currency for p in rows}
    if len(rows) != len(skus) or len(currencies) != 1:   # unknown sku, or mixed-currency math
        raise HTTPException(422, "invalid cart")
    subtotal = sum(p.price_cents * skus[p.sku] for p in rows)        # server price, server math
    discount = await redeem_coupon(s, body.coupon, u, subtotal) if body.coupon else 0
    return max(subtotal - discount, 0), currencies.pop()

ALLOWED: dict[str, set[str]] = {                         # the state machine is data, not scattered ifs
    "pending": {"paid", "cancelled"}, "paid": {"packed", "refunded"}, "packed": {"shipped"},
    "shipped": {"delivered"}, "delivered": {"refunded"}, "refunded": set(), "cancelled": set()}

def transition(order: Order, new: str) -> None:
    if new not in ALLOWED[order.status]:
        raise HTTPException(409, f"{order.status} -> {new} not allowed")
    order.status = new

def approve(req: ApprovalRequest, u: User) -> None:
    if req.requested_by == u.id:
        raise HTTPException(403, "self-approval")        # separation of duties
    transition(req, "approved")

def refund(order: Order, cents: int) -> None:
    if not 0 < cents <= order.paid_cents - order.refunded_cents:   # partials cannot over-sum
        raise HTTPException(422, "refund exceeds remaining")
    order.refunded_cents += cents
```

Back every invariant with a DB constraint — the app is not the only writer (Celery tasks, admin scripts, migrations):

```python
# fixed — alembic
op.create_check_constraint("ck_qty_pos", "order_lines", "qty > 0")
op.create_check_constraint("ck_refund", "orders", "refunded_cents between 0 and paid_cents")
op.create_unique_constraint("uq_coupon_per_user", "coupon_redemptions", ["coupon_id", "user_id"])
op.create_unique_constraint("uq_webhook_event", "webhook_events", ["provider", "event_id"])
```

Idempotency: add a unique index on `(user_id, idempotency_key)`, read the `Idempotency-Key` header, insert it with the result row in the same transaction, return the stored response on a duplicate. A replayed signed webhook is the same fix — insert `event_id` first and, on `IntegrityError`, return 200 and do nothing. Time: compare against `datetime.now(UTC)` server-side; a client timestamp is display data, never the value compared to `expires_at`.

## JS / TS / Node / React

```ts
// vulnerable
app.post("/api/checkout", requireAuth, async (req, res) => {
  const { items, total, plan } = req.body;          // total and plan chosen by the client
  await stripe.paymentIntents.create({ amount: Math.round(total * 100), currency: "usd" });
  await db.subscription.update({ where: { userId: req.user.id }, data: { plan } }); // free upgrade
  res.json({ ok: true });
});
```

```ts
// fixed — no total, no price, no plan in the schema
const Checkout = z.object({
  items: z.array(z.object({ sku: z.string(), qty: z.number().int().positive().max(100) })).min(1).max(50),
  idempotencyKey: z.string().uuid(),
}).strict();

app.post("/api/checkout", requireAuth, async (req, res) => {
  const body = Checkout.parse(req.body);
  const products = await db.product.findMany({ where: { sku: { in: body.items.map(i => i.sku) } } });
  if (products.length !== body.items.length) return res.status(422).json({ error: "unknown sku" });
  // integer minor units: no float money anywhere on this path
  const amount = body.items.reduce((s, i) => s + products.find(p => p.sku === i.sku)!.priceCents * i.qty, 0);
  if (!Number.isSafeInteger(amount) || amount <= 0) return res.status(422).json({ error: "bad amount" });
  const used = await db.usage.count({ where: { accountId: req.user.accountId, month: thisMonth() } });
  if (used >= planLimit(req.user.plan)) return res.status(429).json({ error: "quota" }); // per account, not per key
  await stripe.paymentIntents.create({ amount, currency: products[0].currency },
                                     { idempotencyKey: body.idempotencyKey });
  res.json({ ok: true });                  // the plan changes from the webhook, after payment
});
```

Enforce entitlements in the route handler or a server middleware, never only in the component that renders the upgrade banner. An invite endpoint derives the grantable role from the inviter's own role (`min(inviterRole, requested)`, never `owner`) instead of reading it from the form.

## The safe API, per framework

| Framework / tool | Control to use |
|---|---|
| Pydantic v2 | `Field(gt=0, le=…)`, `condecimal(...)`, `ConfigDict(extra="forbid")`, separate `In`/`Out` models; money as `int` minor units or `Decimal` + `ROUND_HALF_EVEN`, never `float` |
| SQLAlchemy / Postgres | `Numeric(12, 2)` not `Float`; `Enum` status columns; `CHECK` on amounts and quantities; unique index on (coupon, user), (provider, event_id), (user, idempotency_key) |
| FastAPI / Celery | `Depends` for entitlement and quota checks; `Idempotency-Key` honoured in the route; tasks keyed by business id so retries do not double-apply |
| Stripe / PSP | `idempotencyKey` on every create; amount from your catalogue, never from the client |
| Zod / Node | `.strict()`, `.int().positive()`, `.max()`; integer cents or `bigint` with a `Number.isSafeInteger` guard |
| Next.js | Entitlement check inside the server action or route handler, not the client component |

## Grep for

```
rg -n 'body\.(price|total|amount|cost|discount|currency|credits)'   # money read from the request
rg -n 'Column\(Float|mapped_column\(Float|:\s*float'                # float money column or annotation
rg -n 'status\s*=\s*(body|payload|req\.body|data)\[?[\x27"]?status' # client-chosen workflow state
rg -n -P 'Field\((?![^)]*\b(gt|ge|lt|le|max_length|max_digits)\s*=)' -g '*.py'   # Pydantic field with no bounds
rg -n -P 'z\.number\(\)(?!\s*\.\s*(int|positive|nonnegative|min|max|step))' -g '*.ts'  # unbounded zod number
rg -n '(coupon|promo|referral|trial)' -A4 | rg 'select|findFirst'   # redemption: per-user unique row?
rg -n 'Idempotency-Key|idempotency_key|idempotencyKey'              # absence on payment/webhook routes is the finding
rg -n '(expires_at|valid_until|not_after)\s*[<>]=?\s*(body|req|payload)\.'  # expiry vs a client clock
rg -n 'role\s*[:=]\s*(body|req\.body|form)\.(role|invite_role)'     # grantee role taken from the request
rg -n 'approve\(' -A5 | rg -v 'requested_by|created_by'             # approval with no self-approval guard
```

## False positives

- A client-sent `price` used only for display and compared against the server total before charging — the server value wins; that comparison is the control. Likewise `float` on a non-money metric (latency, score, ratio) — no rounding exposure.
- A status string assigned from a server-side constant or state function, or a quantity with no Pydantic bound where a DB `CHECK` and a stock check both apply downstream — confirm before reporting.
- IP-keyed rate limiting that sits *in addition to* an account-level quota enforced elsewhere, or a webhook handler with no event-id row when the action is genuinely idempotent (`SET status='paid'` behind a transition guard).

## Regression test

```python
# tests/test_business_logic.py
@pytest.mark.anyio
async def test_client_price_and_status_are_ignored(client, token, product_1000_cents):
    r = await client.post("/orders", headers={"Authorization": f"Bearer {token}"},
                          json={"lines": [{"sku": product_1000_cents.sku, "qty": 2}],
                                "price": 1, "total": 1, "status": "paid"})
    assert r.status_code == 422                  # extra="forbid" rejects server-owned fields
    ok = await client.post("/orders", headers={"Authorization": f"Bearer {token}"},
                           json={"lines": [{"sku": product_1000_cents.sku, "qty": 2}]})
    assert ok.json()["total_cents"] == 2000 and ok.json()["status"] == "pending"  # server math

@pytest.mark.anyio
@pytest.mark.parametrize("qty", [0, -5, 10**9])
async def test_bad_quantity_rejected(client, token, product_1000_cents, qty):
    r = await client.post("/orders", headers={"Authorization": f"Bearer {token}"},
                          json={"lines": [{"sku": product_1000_cents.sku, "qty": qty}]})
    assert r.status_code == 422

@pytest.mark.anyio
async def test_workflow_cannot_skip_to_shipped(client, admin_token, pending_order, session):
    r = await client.patch(f"/orders/{pending_order.id}/status", json={"status": "shipped"},
                           headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 409
    await session.refresh(pending_order)
    assert pending_order.status == "pending"     # the row really did not move

@pytest.mark.anyio
async def test_partial_refunds_cannot_exceed_paid(client, admin_token, order_paid_1000, session):
    h, body = {"Authorization": f"Bearer {admin_token}"}, {"amount_cents": 600}
    first = await client.post(f"/orders/{order_paid_1000.id}/refund", json=body, headers=h)
    second = await client.post(f"/orders/{order_paid_1000.id}/refund", json=body, headers=h)
    assert (first.status_code, second.status_code) == (200, 422)
    await session.refresh(order_paid_1000)
    assert order_paid_1000.refunded_cents == 600
```

```ts
// checkout.logic.test.ts — the quota is per account, not per API key
it("rejects a second key on an account already at its plan limit", async () => {
  await seedUsage({ accountId: "acct_1", count: planLimit("free") });
  const res = await request(app).post("/api/checkout").set(authForSecondKeyOf("acct_1"))
    .send({ items: [{ sku: "A", qty: 1 }], idempotencyKey: crypto.randomUUID() });
  expect(res.status).toBe(429);   // not 200
});
```
