import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { computeManifestDigest, requiredLifecycleEvidence, signEvent } from "../src/project-payments.mjs";
import { createApp } from "../src/server.mjs";

const secret = `qa-runtime-${"r".repeat(40)}`;
const environmentId = `sim_env_${"1".repeat(24)}`;
const productId = `sim_prod_${"2".repeat(24)}`;
const priceId = `sim_price_${"3".repeat(24)}`;
const oneTimeProductId = `sim_prod_${"4".repeat(24)}`;
const oneTimePriceId = `sim_price_${"5".repeat(24)}`;
const buyer = "qa-buyer-01";
const commitSha = "a".repeat(40);

test("checkout, price preview, and portal are authenticated and buyer-isolated", async context => {
  const fixture = await simulatorServer(context);
  assert.equal((await fetch(`${fixture.url}/api/project-payments/prices`)).status, 401);

  const priceResponse = await fetch(`${fixture.url}/api/project-payments/prices`, { headers: buyerHeaders(buyer) });
  assert.equal(priceResponse.status, 200);
  assert.deepEqual(await priceResponse.json(), {
    prices: [
      { priceKey: "monthly", unitAmount: 1500, currency: "USD", formatted: "USD 15.00" },
      { priceKey: "once", unitAmount: 1500, currency: "USD", formatted: "USD 15.00" }
    ]
  });

  const firstCheckout = await postJson(`${fixture.url}/api/project-payments/checkout`, { priceKey: "monthly" }, buyerHeaders(buyer));
  const secondCheckout = await postJson(`${fixture.url}/api/project-payments/checkout`, { priceKey: "monthly" }, buyerHeaders("qa-buyer-02"));
  assert.equal(firstCheckout.status, 201);
  assert.equal(secondCheckout.status, 201);
  const firstCheckoutBody = await firstCheckout.json();
  const secondCheckoutBody = await secondCheckout.json();
  assert.notEqual(firstCheckoutBody.id, secondCheckoutBody.id);
  assert.match(firstCheckoutBody.checkoutUrl, /^\/billing\/simulator\/session_[0-9a-f]{24}$/);
  assert.equal((await fetch(`${fixture.url}${firstCheckoutBody.checkoutUrl}`)).status, 401);
  assert.equal((await fetch(`${fixture.url}${firstCheckoutBody.checkoutUrl}`, { headers: buyerHeaders("qa-buyer-02") })).status, 404);
  const ownCheckout = await fetch(`${fixture.url}${firstCheckoutBody.checkoutUrl}`, { headers: buyerHeaders(buyer) });
  assert.equal(ownCheckout.status, 200);
  assert.match(await ownCheckout.text(), /id="retry-checkout"/);

  const oneTimeCheckout = await postJson(`${fixture.url}/api/project-payments/checkout`, { priceKey: "once" }, buyerHeaders(buyer));
  assert.equal(oneTimeCheckout.status, 201);

  const forgedBuyer = await postJson(
    `${fixture.url}/api/project-payments/checkout`,
    { priceKey: "monthly", buyerId: "qa-buyer-02" },
    buyerHeaders(buyer)
  );
  assert.equal(forgedBuyer.status, 400);

  const firstPortal = await postJson(`${fixture.url}/api/project-payments/portal`, {}, buyerHeaders(buyer));
  const secondPortal = await postJson(`${fixture.url}/api/project-payments/portal`, {}, buyerHeaders("qa-buyer-02"));
  assert.notEqual((await firstPortal.json()).url, (await secondPortal.json()).url);
});

test("disabled production mode fails closed and exposes no webhook, harness, or verifier", async context => {
  const fixture = await simulatorServer(context, {
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "false",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "disabled",
    VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "false"
  });
  const checkout = await postJson(`${fixture.url}/api/project-payments/checkout`, { priceKey: "monthly" }, buyerHeaders(buyer));
  assert.equal(checkout.status, 503);
  assert.deepEqual(await checkout.json(), { code: "PAYMENTS_DISABLED" });
  assert.equal((await fetch(`${fixture.url}/webhooks/project-payments`, { method: "POST" })).status, 404);
  assert.equal((await fetch(`${fixture.url}/.well-known/vibenest/project-payments/harness`)).status, 404);
  assert.equal((await fetch(`${fixture.url}/.well-known/vibenest/project-payments/verifier`)).status, 404);
  const pricing = await (await fetch(`${fixture.url}/pricing`)).text();
  assert.match(pricing, /currently unavailable/);
  assert.doesNotMatch(pricing, /<button|checkoutUrl/);
});

test("signed subscription state enforces team_exports through scheduled and immediate cancellation", async context => {
  const fixture = await simulatorServer(context);
  const base = Date.now() - 20_000;
  const initialPeriodStart = at(base, 0);
  const initialPeriodEnd = periodEnd(initialPeriodStart);
  const created = subscriptionEvent(50, 1, "subscription.created", at(base, 0), null, buyer, initialPeriodStart);
  assert.equal((await postWebhook(fixture.url, created)).status, 202);
  await processHarness(fixture.url);
  assert.equal((await fetch(`${fixture.url}/api/team-exports`, { headers: buyerHeaders(buyer) })).status, 200);
  assert.equal((await fetch(`${fixture.url}/api/team-exports`, { headers: buyerHeaders("qa-buyer-02") })).status, 403);

  const scheduled = subscriptionEvent(51, 1, "subscription.updated", at(base, 2), initialPeriodEnd, buyer, initialPeriodStart);
  await postWebhook(fixture.url, scheduled);
  await processHarness(fixture.url);
  const scheduledState = await fetch(`${fixture.url}/api/project-payments/entitlements/team_exports`, { headers: buyerHeaders(buyer) });
  assert.deepEqual(await scheduledState.json(), {
    entitlement: "team_exports",
    active: true,
    status: "scheduled_cancel",
    effectiveUntil: initialPeriodEnd
  });

  const canceled = subscriptionEvent(52, 1, "subscription.canceled", at(base, 4), null, buyer, initialPeriodStart);
  await postWebhook(fixture.url, canceled);
  await processHarness(fixture.url);
  assert.equal((await fetch(`${fixture.url}/api/team-exports`, { headers: buyerHeaders(buyer) })).status, 403);
});

test("webhook rejects tampering, strict-shape violations, and oversized bodies", async context => {
  const fixture = await simulatorServer(context);
  const payload = transactionEvent(60, 10, new Date().toISOString());
  const raw = rawEvent(payload);
  const badSignature = signEvent(raw, `${secret}x`, Math.floor(Date.parse(payload.occurred_at) / 1000));
  assert.equal((await fetch(`${fixture.url}/webhooks/project-payments`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Paddle-Signature": badSignature },
    body: raw
  })).status, 401);

  const extraField = { ...payload, status: "active" };
  assert.equal((await postWebhook(fixture.url, extraField)).status, 400);

  const oversized = Buffer.alloc(129 * 1024, 0x61);
  assert.equal((await fetch(`${fixture.url}/webhooks/project-payments`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Paddle-Signature": signEvent(oversized, secret, Math.floor(Date.now() / 1000)) },
    body: oversized
  })).status, 413);

  const compressed = gzipSync(raw);
  assert.equal((await fetch(`${fixture.url}/webhooks/project-payments`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Encoding": "gzip",
      "Paddle-Signature": signEvent(compressed, secret, Math.floor(Date.parse(payload.occurred_at) / 1000))
    },
    body: compressed
  })).status, 415);
});

test("webhook rate limiter is bounded and returns 429 without parsing excess payloads", async context => {
  const fixture = await simulatorServer(context, { PROJECT_PAYMENT_WEBHOOK_RATE_LIMIT: "1" });
  const first = transactionEvent(70, 70, new Date().toISOString());
  const second = transactionEvent(71, 71, new Date(Date.now() + 1_000).toISOString());
  assert.equal((await postWebhook(fixture.url, first)).status, 202);
  assert.equal((await postWebhook(fixture.url, second)).status, 429);
});

test("present but blank SOURCE_COMMIT never falls back to the legacy build value", async context => {
  const fixture = await simulatorServer(context, {
    SOURCE_COMMIT: "",
    VIBENEST_BUILD_COMMIT_SHA: commitSha
  });
  await postWebhook(fixture.url, transactionEvent(80, 80, new Date().toISOString()));
  await processHarness(fixture.url);
  for (const name of requiredLifecycleEvidence) {
    await fixture.app.locals.projectPayments.store.recordEvidence(name);
  }
  const verifier = await fetch(`${fixture.url}/.well-known/vibenest/project-payments/verifier`, {
    headers: verifierHeaders()
  });
  assert.equal(verifier.status, 404);
});

test("simulator harness derives the complete lifecycle and GET-only verifier returns the exact contract", async context => {
  const fixture = await simulatorServer(context);
  const base = Date.now() - 90_000;
  const subscriptionId = providerId("sim_sub", 20);
  const subscriptionTransactionId = providerId("sim_txn", 21);
  const outOfOrderSubscriptionId = providerId("sim_sub", 22);
  const initialPeriodStart = at(base, 5);
  const renewalPeriodStart = periodEnd(initialPeriodStart);
  const renewalPeriodEnd = periodEnd(renewalPeriodStart);
  const outOfOrderPeriodStart = at(base, 20);

  assert.equal((await fetch(`${fixture.url}/api/project-payments/prices`, { headers: buyerHeaders(buyer) })).status, 200);
  assert.equal((await postJson(`${fixture.url}/api/project-payments/portal`, {}, buyerHeaders(buyer))).status, 201);

  const oneTime = transactionEvent(100, 20, at(base, 0), "transaction.completed", null, "qa-one-time-buyer");
  const lifecycle = [
    oneTime,
    subscriptionEvent(101, 20, "subscription.created", at(base, 5), null, buyer, initialPeriodStart),
    transactionEvent(102, 21, at(base, 6), "transaction.completed", subscriptionId, buyer, initialPeriodStart),
    transactionEvent(103, 23, at(base, 10), "transaction.payment_failed"),
    transactionEvent(104, 24, at(base, 22), "transaction.completed", outOfOrderSubscriptionId, "qa-buyer-02", outOfOrderPeriodStart),
    subscriptionEvent(105, 22, "subscription.created", at(base, 20), null, "qa-buyer-02", outOfOrderPeriodStart),
    subscriptionEvent(106, 20, "subscription.updated", at(base, 30), null, buyer, renewalPeriodStart),
    subscriptionEvent(107, 20, "subscription.updated", at(base, 40), renewalPeriodEnd, buyer, renewalPeriodStart),
    adjustmentEvent(108, 1, subscriptionTransactionId, "adjustment.created", at(base, 50)),
    adjustmentEvent(109, 1, subscriptionTransactionId, "adjustment.updated", at(base, 51)),
    subscriptionEvent(110, 20, "subscription.canceled", at(base, 52), null, buyer, renewalPeriodStart),
    portalEvent(111, 1, at(base, 55))
  ];
  for (const event of lifecycle) assert.equal((await postWebhook(fixture.url, event)).status, 202);
  assert.equal((await postWebhook(fixture.url, oneTime)).status, 202);

  const processed = await processHarness(fixture.url);
  assert.equal(processed.status, 200);
  const processResult = await processed.json();
  assert.equal(processResult.failed, 0);
  assert.equal(processResult.pendingEvents, 0);
  assert.equal(processResult.deadLetteredEvents, 0);

  const replay = await postHarness(fixture.url, "restart-replay");
  assert.deepEqual(await replay.json(), { action: "restart-replay", passed: true });
  const scan = await postHarness(fixture.url, "secret-scan");
  assert.equal(scan.status, 200);
  assert.equal((await scan.json()).passed, true);

  assert.equal((await fetch(`${fixture.url}/.well-known/vibenest/project-payments/harness`)).status, 404);
  const statusResponse = await fetch(`${fixture.url}/.well-known/vibenest/project-payments/harness`, {
    headers: simulatorHeaders()
  });
  const status = await statusResponse.json();
  assert.deepEqual(status.evidence, [...requiredLifecycleEvidence].sort());
  assert.equal(status.lifecyclePassed, true);
  assert.equal(status.durableInbox, true);
  assert.equal(status.restartReplayPassed, true);

  const verifierUrl = `${fixture.url}/.well-known/vibenest/project-payments/verifier`;
  assert.equal((await fetch(verifierUrl)).status, 404);
  assert.equal((await fetch(`${verifierUrl}?unexpected=1`, { headers: verifierHeaders() })).status, 404);
  assert.equal((await fetch(verifierUrl, { method: "HEAD", headers: verifierHeaders() })).status, 405);
  assert.equal((await fetch(verifierUrl, { method: "POST", headers: verifierHeaders() })).status, 405);
  assert.equal((await fetch(verifierUrl, { headers: { ...verifierHeaders(), "X-VibeNest-Simulator-Secret": "short" } })).status, 404);
  const verified = await fetch(verifierUrl, { headers: verifierHeaders() });
  assert.equal(verified.status, 200);
  assert.deepEqual(await verified.json(), {
    provider: "simulator",
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha,
    manifestDigest: computeManifestDigest(),
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  });
});

test("seller-owned legal routes use the versioned Draft/noindex templates", async context => {
  const fixture = await simulatorServer(context);
  for (const route of ["/terms", "/privacy", "/refund-policy"]) {
    const response = await fetch(`${fixture.url}${route}`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow");
    const html = await response.text();
    assert.match(html, /preview-2026-08-06/);
    assert.match(html, /Preview\/Draft/);
    assert.match(html, /Pending project-owner/);
    assert.match(html, /Lifetime/);
    assert.doesNotMatch(html, /\{[A-Z_]+\}/);
  }
});

async function simulatorServer(context, overrides = {}) {
  const directory = await mkdtemp(join(tmpdir(), "vn-pp-http-"));
  const configuration = {
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "simulator",
    VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: secret,
    VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID: environmentId,
    VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST: computeManifestDigest(),
    VIBENEST_PROJECT_PAYMENTS_CATALOG_B64: runtimeCatalogB64(),
    SOURCE_COMMIT: commitSha,
    VIBENEST_NOINDEX: "true",
    PROJECT_PAYMENT_STORE_PATH: join(directory, "store.sqlite"),
    ...overrides
  };
  const app = createApp(configuration, { projectRoot: process.cwd(), startWorker: false });
  const server = app.listen(0);
  await new Promise(resolve => server.once("listening", resolve));
  const address = server.address();
  context.after(async () => {
    app.locals.projectPayments.stopWorker();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  });
  return { app, configuration, url: `http://127.0.0.1:${address.port}` };
}

async function postWebhook(baseUrl, payload) {
  const raw = rawEvent(payload);
  const timestamp = Math.floor(Date.parse(payload.occurred_at) / 1000);
  return fetch(`${baseUrl}/webhooks/project-payments`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Paddle-Signature": signEvent(raw, secret, timestamp)
    },
    body: raw
  });
}

function processHarness(baseUrl) {
  return postHarness(baseUrl, "process");
}

function postHarness(baseUrl, action) {
  return postJson(`${baseUrl}/.well-known/vibenest/project-payments/harness`, { action }, simulatorHeaders());
}

function postJson(url, body, headers = {}) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body)
  });
}

function buyerHeaders(subjectKey) {
  return { "X-QA-User-Id": subjectKey };
}

function simulatorHeaders() {
  return { "X-VibeNest-Simulator-Secret": secret };
}

function verifierHeaders() {
  return {
    ...simulatorHeaders(),
    "X-VibeNest-Expected-Commit": commitSha,
    "X-VibeNest-Expected-Manifest-Digest": computeManifestDigest()
  };
}

function transactionEvent(number, transactionNumber, occurredAt, eventType = "transaction.completed", subscriptionId = null, subjectKey = buyer, periodStartsAt = occurredAt) {
  const oneTime = eventType === "transaction.completed" && subscriptionId === null;
  return envelope(number, eventType, occurredAt, {
    id: providerId("sim_txn", transactionNumber),
    status: eventType === "transaction.completed" ? "completed" : "declined",
    customer_id: subjectKey,
    subscription_id: subscriptionId,
    items: [{
      price_id: oneTime ? oneTimePriceId : priceId,
      product_id: oneTime ? oneTimeProductId : productId,
      quantity: 1,
      billing_period: oneTime ? null : billingPeriod(periodStartsAt)
    }],
    details: { totals: { total: "1500", currency_code: "USD" } },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function subscriptionEvent(number, subscriptionNumber, eventType, occurredAt, scheduledCancelAt = null, subjectKey = buyer, periodStartsAt = occurredAt) {
  return envelope(number, eventType, occurredAt, {
    id: providerId("sim_sub", subscriptionNumber),
    status: eventType === "subscription.canceled" ? "canceled" : "active",
    customer_id: subjectKey,
    items: [{ price_id: priceId, product_id: productId, quantity: 1 }],
    current_billing_period: billingPeriod(periodStartsAt),
    scheduled_change: scheduledCancelAt === null ? null : { action: "cancel", effective_at: scheduledCancelAt },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function adjustmentEvent(number, adjustmentNumber, transactionId, eventType, occurredAt) {
  return envelope(number, eventType, occurredAt, {
    id: providerId("sim_adj", adjustmentNumber),
    action: "refund",
    status: eventType === "adjustment.created" ? "pending_approval" : "approved",
    transaction_id: transactionId,
    totals: { total: "1500", currency_code: "USD" },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function portalEvent(number, portalNumber, occurredAt, subjectKey = buyer) {
  return envelope(number, "customer.portal_session.created", occurredAt, {
    id: providerId("sim_portal", portalNumber),
    customer_id: subjectKey,
    url: `https://simulator.invalid/portal/${environmentId}/${subjectKey}`,
    expires_at: new Date(Date.parse(occurredAt) + 30 * 60_000).toISOString(),
    custom_data: { vibenest_environment_id: environmentId }
  });
}

function envelope(number, eventType, occurredAt, data) {
  return {
    event_id: providerId("sim_evt", number),
    event_type: eventType,
    occurred_at: occurredAt,
    notification_id: providerId("sim_ntf", number),
    data
  };
}

function providerId(prefix, number) {
  return `${prefix}_${number.toString(16).padStart(24, "0")}`;
}

function rawEvent(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8");
}

function at(base, seconds) {
  return new Date(base + seconds * 1_000).toISOString();
}

function billingPeriod(startsAt) {
  return { starts_at: startsAt, ends_at: periodEnd(startsAt) };
}

function periodEnd(startsAt) {
  const value = new Date(startsAt);
  const day = value.getUTCDate();
  value.setUTCDate(1);
  value.setUTCMonth(value.getUTCMonth() + 1);
  const lastDay = new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth() + 1, 0)).getUTCDate();
  value.setUTCDate(Math.min(day, lastDay));
  return value.toISOString();
}

function runtimeCatalogB64() {
  return Buffer.from(JSON.stringify({
    provider: "simulator",
    sellerExternalId: `sim_seller_${"6".repeat(24)}`,
    environmentExternalId: environmentId,
    manifestDigest: computeManifestDigest(),
    products: [
      {
        manifestKey: "lifetime",
        externalId: oneTimeProductId,
        prices: [{ manifestKey: "once", externalId: oneTimePriceId, currency: "USD", unitAmount: 1500, type: "one_time", interval: null }],
        grants: [{ entitlement: "team_exports", quantity: 1 }]
      },
      {
        manifestKey: "pro",
        externalId: productId,
        prices: [{ manifestKey: "monthly", externalId: priceId, currency: "USD", unitAmount: 1500, type: "recurring", interval: "month" }],
        grants: [{ entitlement: "team_exports", quantity: 1 }]
      }
    ]
  }), "utf8").toString("base64");
}
