import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { gzipSync } from "node:zlib";
import {
  computeManifestDigest,
  DurableProjectPaymentStore,
  signEvent
} from "../src/project-payments.mjs";
import { createApp, resolveEvidenceScopedStorePath } from "../src/server.mjs";

const execFileAsync = promisify(execFile);
const restartReplayChild = fileURLToPath(new URL("../scripts/restart-replay-child.mjs", import.meta.url));

const secret = `qa-runtime-${"r".repeat(40)}`;
const environmentId = `sim_env_${"1".repeat(24)}`;
const productId = `sim_prod_${"2".repeat(24)}`;
const priceId = `sim_price_${"3".repeat(24)}`;
const oneTimeProductId = `sim_prod_${"4".repeat(24)}`;
const oneTimePriceId = `sim_price_${"5".repeat(24)}`;
const buyer = "qa-buyer-01";
const commitSha = "a".repeat(40);

test("durable verifier evidence is partitioned by environment, manifest, and exact SOURCE_COMMIT", () => {
  const basePath = join(tmpdir(), "project-payments.sqlite");
  const identity = {
    environmentId,
    manifestDigest: computeManifestDigest(),
    builtCommit: commitSha
  };
  const current = resolveEvidenceScopedStorePath(basePath, identity);
  assert.equal(resolveEvidenceScopedStorePath(basePath, identity), current);
  assert.notEqual(resolveEvidenceScopedStorePath(basePath, { ...identity, builtCommit: "b".repeat(40) }), current);
  assert.notEqual(resolveEvidenceScopedStorePath(basePath, { ...identity, manifestDigest: "c".repeat(64) }), current);
  assert.notEqual(resolveEvidenceScopedStorePath(basePath, { ...identity, environmentId: `sim_env_${"d".repeat(24)}` }), current);
  assert.equal(resolveEvidenceScopedStorePath(basePath, null), basePath);
});

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
  await processInbox(fixture);
  assert.equal((await fetch(`${fixture.url}/api/team-exports`, { headers: buyerHeaders(buyer) })).status, 200);
  assert.equal((await fetch(`${fixture.url}/api/team-exports`, { headers: buyerHeaders("qa-buyer-02") })).status, 403);

  const scheduled = subscriptionEvent(51, 1, "subscription.updated", at(base, 2), initialPeriodEnd, buyer, initialPeriodStart);
  await postWebhook(fixture.url, scheduled);
  await processInbox(fixture);
  const scheduledState = await fetch(`${fixture.url}/api/project-payments/entitlements/team_exports`, { headers: buyerHeaders(buyer) });
  assert.deepEqual(await scheduledState.json(), {
    entitlement: "team_exports",
    active: true,
    status: "scheduled_cancel",
    effectiveUntil: initialPeriodEnd
  });

  const canceled = subscriptionEvent(52, 1, "subscription.canceled", at(base, 4), null, buyer, initialPeriodStart);
  await postWebhook(fixture.url, canceled);
  await processInbox(fixture);
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

test("present but blank SOURCE_COMMIT never falls back to the legacy build value", () => {
  assert.throws(
    () => createApp(simulatorConfiguration({
      SOURCE_COMMIT: "",
      VIBENEST_BUILD_COMMIT_SHA: commitSha
    }), { projectRoot: process.cwd(), startWorker: false }),
    error => error?.code === "SIMULATOR_CONFIG_INVALID"
  );
});

test("protected restart harness is strict, process-bound, durable, and idempotent", async context => {
  const fixture = await simulatorServer(context);
  const endpoint = `${fixture.url}/.well-known/vibenest/project-payments/harness`;
  const postRaw = (body, headers = verifierHeaders()) => fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body
  });

  assert.equal((await postRaw('{"action":"restart-replay"}', {
    ...verifierHeaders(),
    "X-VibeNest-Simulator-Secret": "x".repeat(40)
  })).status, 404);
  assert.equal((await postRaw('{"action":"restart-replay"}', {
    ...verifierHeaders(),
    "X-VibeNest-Expected-Commit": "b".repeat(40)
  })).status, 404);
  assert.equal((await postRaw('{"action":"restart-replay"}', {
    ...verifierHeaders(),
    "X-VibeNest-Expected-Manifest-Digest": "c".repeat(64)
  })).status, 404);
  assert.equal((await postRaw("{}")).status, 400);
  assert.equal((await postRaw('{"action":"unsupported"}')).status, 400);
  assert.equal((await postRaw('{"action":"restart-replay","extra":true}')).status, 400);
  assert.equal((await postRaw('{"action":')).status, 400);
  assert.equal((await postRaw(JSON.stringify({
    action: "restart-replay",
    padding: "x".repeat(1_100)
  }))).status, 413);
  assert.equal((await fetch(endpoint, {
    method: "POST",
    headers: { ...verifierHeaders(), "Content-Type": "text/plain" },
    body: '{"action":"restart-replay"}'
  })).status, 415);
  assert.equal((await fetch(endpoint, {
    method: "POST",
    headers: {
      ...verifierHeaders(),
      "Content-Type": "application/json",
      "Content-Encoding": "gzip"
    },
    body: gzipSync(Buffer.from('{"action":"restart-replay"}', "utf8"))
  })).status, 415);
  assert.equal((await fetch(endpoint, { headers: verifierHeaders() })).status, 405);
  assert.equal((await fetch(`${endpoint}?unexpected=1`, {
    method: "POST",
    headers: { ...verifierHeaders(), "Content-Type": "application/json" },
    body: '{"action":"restart-replay"}'
  })).status, 404);

  const staged = await postRaw('{"action":"restart-replay"}');
  assert.equal(staged.status, 202);
  assert.equal(staged.headers.get("content-type"), "application/json; charset=utf-8");
  assert.deepEqual(await staged.json(), { action: "restart-replay", state: "staged" });
  const stagedRetry = await postRaw('{"action":"restart-replay"}');
  assert.equal(stagedRetry.status, 202);
  assert.deepEqual(await stagedRetry.json(), { action: "restart-replay", state: "staged" });

  const sameBootStore = new DurableProjectPaymentStore(
    fixture.app.locals.projectPayments.storePath,
    { evidenceScope: fixture.app.locals.projectPayments.evidenceScope }
  );
  assert.deepEqual(await sameBootStore.processDue(), { applied: 0, ignored: 0, failed: 0 });
  const pendingProbe = (await sameBootStore.snapshot()).events.find(
    event => event.eventType === "internal.restart_replay_probe"
  );
  assert.ok(pendingProbe);
  assert.equal(pendingProbe.processedAt, null);

  const firstChild = await runRestartReplayChild(fixture);
  assert.deepEqual(firstChild.result, { applied: 1, ignored: 0, failed: 0 });
  assert.equal(firstChild.status.restartReplayPassed, true);
  const secondChild = await runRestartReplayChild(fixture);
  assert.deepEqual(secondChild.result, { applied: 0, ignored: 0, failed: 0 });

  const snapshot = await sameBootStore.snapshot();
  const processedProbe = snapshot.events.find(event => event.eventType === "internal.restart_replay_probe");
  assert.ok(processedProbe.processedAt);
  assert.notEqual(processedProbe.processedInstanceId, processedProbe.receivedInstanceId);
  assert.equal(snapshot.evidence.filter(name => name === "restart-replay").length, 1);
  assert.deepEqual(snapshot.entitlements, {});
  assert.deepEqual(snapshot.transactions, {});
  assert.deepEqual(snapshot.subscriptions, {});
  assert.deepEqual(snapshot.refundedTransactions, {});

  const completedRetry = await postRaw('{"action":"restart-replay"}');
  assert.equal(completedRetry.status, 200);
  assert.deepEqual(await completedRetry.json(), { action: "restart-replay", state: "already-passed" });
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

  const processResult = await processInbox(fixture);
  assert.equal(processResult.failed, 0);
  const beforeRestart = await fixture.app.locals.projectPayments.store.verificationStatus();
  assert.equal(beforeRestart.pendingEvents, 0);
  assert.equal(beforeRestart.deadLetteredEvents, 0);

  const staged = await postRestartHarness(fixture.url);
  assert.equal(staged.status, 202);
  assert.deepEqual(await staged.json(), { action: "restart-replay", state: "staged" });
  assert.deepEqual(await fixture.app.locals.projectPayments.store.processDue(), {
    applied: 0, ignored: 0, failed: 0
  });
  const child = await runRestartReplayChild(fixture);
  assert.deepEqual(child.result, { applied: 1, ignored: 0, failed: 0 });
  assert.equal(child.status.restartReplayPassed, true);

  const alreadyPassed = await postRestartHarness(fixture.url);
  assert.equal(alreadyPassed.status, 200);
  assert.deepEqual(await alreadyPassed.json(), { action: "restart-replay", state: "already-passed" });

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
  const configuration = simulatorConfiguration({
    PROJECT_PAYMENT_STORE_PATH: join(directory, "store.sqlite"),
    ...overrides
  });
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

function simulatorConfiguration(overrides = {}) {
  return {
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "simulator",
    VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: secret,
    VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID: environmentId,
    VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST: computeManifestDigest(),
    VIBENEST_PROJECT_PAYMENTS_CATALOG_B64: runtimeCatalogB64(),
    SOURCE_COMMIT: commitSha,
    VIBENEST_NOINDEX: "true",
    ...overrides
  };
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

function processInbox(fixture) {
  return fixture.app.locals.projectPayments.store.processDue();
}

function postRestartHarness(baseUrl) {
  return postJson(
    `${baseUrl}/.well-known/vibenest/project-payments/harness`,
    { action: "restart-replay" },
    verifierHeaders()
  );
}

async function runRestartReplayChild(fixture) {
  const { stdout } = await execFileAsync(process.execPath, [
    restartReplayChild,
    fixture.app.locals.projectPayments.storePath,
    fixture.app.locals.projectPayments.evidenceScope
  ], {
    encoding: "utf8",
    timeout: 10_000,
    windowsHide: true
  });
  return JSON.parse(stdout);
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
