# VibeNest Project Payments disposable E2E

Timestamped QA repository for the Phase 1 simulator and exact-SHA deployment test. It
contains no provider credentials and is deleted after the run. The original health root
and `/api/me` behavior remain intact.

## Declared product

`.vibenest/payments.yaml` declares two provider-neutral simulator QA offers: Pro at USD
15.00/month and Lifetime at USD 15.00 one time. Both use authenticated `user_id` buyers and
grant `team_exports` from the runtime-issued catalog mapping only. Pro access follows the
signed authoritative billing period; Lifetime is an independently tracked one-time source.
Authorization reads a derived subject/grant aggregate that is recomputed by summing every
available paid-source contribution in the same transaction as each webhook effect.
The customer portal is enabled, scheduled cancellation preserves access through the signed
period end, and a refund revokes only the exact trusted transaction source. A recurring refund
copies its transaction-to-subscription binding into a durable projection and fences the whole
linked subscription against resurrection. `immediate-refund` evidence appears only when the
approved refund and terminal subscription cancellation have both persisted, in either order.
The refund window is 14 days.

Economic estimate: VibeNest's planned fee is 1% of Eligible Sales. Paddle's public standard
fee is separately estimated at 5% + USD 0.50 per checkout transaction. The simulator
charges nothing; partner pricing and VibeNest's fee mechanism remain subject to Paddle
confirmation. Prices below USD 10 are especially affected by the fixed fee.

## Disposable authentication boundary

`X-QA-User-Id` is the repository's pre-existing server-side QA buyer middleware. Checkout,
portal, entitlement reads, and `/api/team-exports` use only the resulting
`request.buyerId`; request JSON and query parameters cannot select another buyer. This
header is a disposable simulator ingress shim, not a production authentication design.

## Routes to exercise

- `GET /api/project-payments/prices` with `X-QA-User-Id` records price-preview evidence.
- `POST /api/project-payments/checkout` with `X-QA-User-Id` and JSON
  `{ "priceKey": "monthly" }` creates a buyer-bound simulator checkout.
- The same checkout route accepts `{ "priceKey": "once" }` for the declared Lifetime
  simulator-only one-time lifecycle scenario.
- `POST /api/project-payments/portal` with `X-QA-User-Id` and JSON `{}` creates only that
  buyer's portal and records customer-portal evidence.
- `POST /webhooks/project-payments` takes the untouched simulator scenario `rawBody` as
  `application/json` and its signature in `Paddle-Signature`. The route verifies HMAC over
  the exact bytes before parsing, validates the environment and strict event shape, then
  acknowledges only after a durable insert.
- `GET /api/project-payments/entitlements/team_exports` with `X-QA-User-Id` reads only the
  authenticated buyer's cached authorization state.
- `GET /api/team-exports` with `X-QA-User-Id` is the server-enforced protected operation.
- `GET /terms`, `GET /privacy`, and `GET /refund-policy` are seller-owned
  `preview-2026-08-06` Draft/noindex pages. Seller identity/contact remain explicitly
  pending project-owner legal review rather than being invented.

The simulator-only evidence harness is
`POST /.well-known/vibenest/project-payments/harness`. It exists only in the enabled
simulator verifier runtime, accepts at most 1 KiB of strict JSON, and accepts exactly
`{ "action": "restart-replay" }`. Every call requires the runtime-only simulator secret
plus exact `SOURCE_COMMIT` and installed-manifest-digest challenges. The route stages one
durable inert probe for the SHA-256 scope of environment, manifest, and build. It returns
exactly `202 { "action": "restart-replay", "state": "staged" }`, or idempotently `200`
with `state: "already-passed"` after valid evidence already exists.

The process that receives the POST cannot claim its own probe. Creating another store
object inside that process does not help because every store shares the process boot ID.
Only a different Node process sharing the SQLite inbox can process the no-op row and record
`restart-replay` evidence once. VibeNest owns the real Coolify restart; neither this route
nor the coding agent receives restart authority. Secret scanning remains repository/CI
evidence and is never asserted by a runtime HTTP action.

After all lifecycle scenarios pass, VibeNest calls only:

`GET /.well-known/vibenest/project-payments/verifier`

with `X-VibeNest-Simulator-Secret`, `X-VibeNest-Expected-Commit`, and
`X-VibeNest-Expected-Manifest-Digest`. The running commit comes from Coolify's
`SOURCE_COMMIT` (with a legacy build-variable fallback only when `SOURCE_COMMIT` is absent).
The verifier accepts GET only and returns 404 until every required evidence item, the
durable inbox, restart/replay, commit, manifest, and secret checks independently pass.

## Runtime modes and persistence

The provider abstraction has `simulator`, future `paddle`, and `disabled` modes. Paddle is
an intentionally unavailable placeholder and has no IDs or credentials. When
`VIBENEST_PROJECT_PAYMENTS_ENABLED` is not `true`, the provider fails closed and the
webhook, harness, and verifier routes are absent. Production-code deployment must set:

```text
VIBENEST_PROJECT_PAYMENTS_ENABLED=false
VIBENEST_PROJECT_PAYMENTS_PROVIDER=disabled
VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED=false
```

Production must omit `VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET`,
`VIBENEST_PROJECT_PAYMENTS_CATALOG_B64`, the simulator environment/manifest variables,
and every verifier secret; those values belong only to the isolated preview runtime.

The disposable preview requires Node 22.13 or newer and uses built-in `node:sqlite` with a
real database under `.data/`. Webhook rows have a unique destination/event key, due and
lease columns, conditional claims, expired-lease recovery, and transactional effect/cache
updates. Paid access is stored as immutable `transaction:{id}` one-time and
`subscription:{id}` recurring source rows plus a separately persisted derived aggregate used
for every protected authorization check. A recurring source advances its latest-transaction
pointer without rewriting the independently immutable transaction projections. Trusted
transaction, subscription, and refund
projections preserve the refund binding; exact-transaction and subscription-wide terminal
fences reject any later reactivation while treating events at or before approval as stale.
The internal restart probe persists both receiving and processing process IDs, is
ineligible to its receiving boot, and has no buyer, entitlement, transaction, or revenue
effect. Signed billing-period bounds and event occurrence time are both persisted and fenced;
renewal must advance exactly one trusted interval. The runtime-issued camelCase catalog is
read only from `VIBENEST_PROJECT_PAYMENTS_CATALOG_B64` and is rejected unless its provider,
environment, manifest digest, unique IDs, prices, and grants exactly match the manifest.
The webhook also has a bounded application-level rate limiter. `migrations/001_project_payments.sql`
is the equivalent PostgreSQL schema for a future multi-instance persistent application.
