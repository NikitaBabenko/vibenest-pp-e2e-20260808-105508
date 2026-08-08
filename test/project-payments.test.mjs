import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  acceptSignedEvent,
  buildVerifierPayload,
  canonicalManifest,
  computeManifestDigest,
  computeRuntimeEvidenceScope,
  createProjectPaymentProvider,
  DurableProjectPaymentStore,
  oneTimeCatalog,
  parseRuntimeCatalog,
  PaddleProjectPaymentProvider,
  providerModes,
  requiredLifecycleEvidence,
  signEvent,
  trustedCatalog,
  validateSimulatorConfiguration,
  verifyEventSignature,
  verifySimulatorSecret
} from "../src/project-payments.mjs";
import { scanProjectTree } from "../src/secret-scan.mjs";

const simulatorSecret = `qa-simulator-${"s".repeat(40)}`;
const execFileAsync = promisify(execFile);
const restartReplayChild = fileURLToPath(new URL("../scripts/restart-replay-child.mjs", import.meta.url));
const environmentId = `sim_env_${"e".repeat(24)}`;
const productId = `sim_prod_${"d".repeat(24)}`;
const priceId = `sim_price_${"c".repeat(24)}`;
const oneTimeProductId = `sim_prod_${"b".repeat(24)}`;
const oneTimePriceId = `sim_price_${"a".repeat(24)}`;
const buyer = "qa-buyer-01";
const commitSha = "a".repeat(40);
const evidenceScope = computeRuntimeEvidenceScope(environmentId, computeManifestDigest(), commitSha);
const runtimeCatalog = parseRuntimeCatalog(runtimeCatalogB64(), environmentId, computeManifestDigest());

test("manifest projection is provider-neutral and matches the recurring and one-time catalog", async () => {
  const yaml = await readFile(new URL("../.vibenest/payments.yaml", import.meta.url), "utf8");
  assert.match(yaml, /project:\s+key: project-532/);
  assert.match(yaml, /unitAmount: 1500/);
  assert.match(yaml, /interval: month/);
  assert.match(yaml, /entitlement: team_exports/);
  assert.match(yaml, /key: lifetime/);
  assert.match(yaml, /key: once/);
  assert.match(yaml, /type: one_time/);
  assert.doesNotMatch(yaml, /providerId|priceId|productId|webhookSecret/i);
  assert.equal(canonicalManifest().products.length, 2);
  assert.ok(canonicalManifest().products.every(product => product.prices.length === 1));
  assert.match(computeManifestDigest(), /^[0-9a-f]{64}$/);
});

test("signature verification uses untouched bytes and rejects tampering or short secrets", () => {
  const rawBody = Buffer.from('{"spacing":  "is-significant"}\n', "utf8");
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signEvent(rawBody, simulatorSecret, timestamp);
  assert.equal(verifyEventSignature(rawBody, signature, simulatorSecret, timestamp), true);
  assert.equal(verifyEventSignature(Buffer.from(rawBody.toString("utf8").trim()), signature, simulatorSecret, timestamp), false);
  assert.equal(verifyEventSignature(rawBody, signature, "short", timestamp), false);
  const nonNumericTimestamp = signEvent(rawBody, simulatorSecret, 123).replace("ts=123", "ts=123junk");
  assert.equal(verifyEventSignature(rawBody, nonNumericTimestamp, simulatorSecret, 123), false);
  assert.equal(verifySimulatorSecret(undefined, undefined), false);
  assert.equal(verifySimulatorSecret("short", "short"), false);
  assert.equal(verifySimulatorSecret(simulatorSecret, simulatorSecret), true);
});

test("runtime catalog and signed billing-period shapes fail closed", async context => {
  const validConfiguration = {
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "true",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "simulator",
    VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: simulatorSecret,
    VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID: environmentId,
    VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST: computeManifestDigest(),
    VIBENEST_PROJECT_PAYMENTS_CATALOG_B64: runtimeCatalogB64()
  };
  assert.ok(validateSimulatorConfiguration(validConfiguration));
  assert.throws(
    () => validateSimulatorConfiguration({ ...validConfiguration, VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET: "short" }),
    error => error.code === "SIMULATOR_CONFIG_INVALID"
  );
  const wrongGrant = runtimeCatalogDocument();
  wrongGrant.products[1].grants[0].quantity = 2;
  assert.throws(
    () => parseRuntimeCatalog(encodeCatalog(wrongGrant), environmentId, computeManifestDigest()),
    error => error.code === "SIMULATOR_CONFIG_INVALID"
  );
  const duplicatePrice = runtimeCatalogDocument();
  duplicatePrice.products[1].prices[0].externalId = duplicatePrice.products[0].prices[0].externalId;
  assert.throws(
    () => parseRuntimeCatalog(encodeCatalog(duplicatePrice), environmentId, computeManifestDigest()),
    error => error.code === "SIMULATOR_CONFIG_INVALID"
  );
  const wrongAuthority = runtimeCatalogDocument();
  wrongAuthority.environmentExternalId = `sim_env_${"f".repeat(24)}`;
  assert.throws(
    () => parseRuntimeCatalog(encodeCatalog(wrongAuthority), environmentId, computeManifestDigest()),
    error => error.code === "SIMULATOR_CONFIG_INVALID"
  );

  const fixture = await temporaryStore(context);
  const occurredAt = new Date().toISOString();
  const recurringWithoutSubscription = transactionEvent({ eventNumber: 4, transactionNumber: 4, occurredAt });
  recurringWithoutSubscription.data.items[0].price_id = priceId;
  recurringWithoutSubscription.data.items[0].product_id = productId;
  recurringWithoutSubscription.data.items[0].billing_period = billingPeriod(occurredAt);
  await assert.rejects(deliver(fixture.store, recurringWithoutSubscription), error => error.code === "WEBHOOK_CATALOG_MISMATCH");

  const oneTimeWithSubscription = transactionEvent({
    eventNumber: 5,
    transactionNumber: 5,
    occurredAt,
    subscriptionId: providerId("sim_sub", 5)
  });
  oneTimeWithSubscription.data.items[0].price_id = oneTimePriceId;
  oneTimeWithSubscription.data.items[0].product_id = oneTimeProductId;
  oneTimeWithSubscription.data.items[0].billing_period = null;
  await assert.rejects(deliver(fixture.store, oneTimeWithSubscription), error => error.code === "WEBHOOK_CATALOG_MISMATCH");

  const oneTimeSubscription = subscriptionEvent({
    eventNumber: 6,
    subscriptionNumber: 6,
    eventType: "subscription.created",
    occurredAt
  });
  oneTimeSubscription.data.items[0].price_id = oneTimePriceId;
  oneTimeSubscription.data.items[0].product_id = oneTimeProductId;
  await assert.rejects(deliver(fixture.store, oneTimeSubscription), error => error.code === "WEBHOOK_CATALOG_MISMATCH");

  const wrongPeriod = subscriptionEvent({
    eventNumber: 7,
    subscriptionNumber: 7,
    eventType: "subscription.created",
    occurredAt
  });
  wrongPeriod.data.current_billing_period.ends_at = new Date(Date.parse(occurredAt) + 2 * 86_400_000).toISOString();
  await assert.rejects(deliver(fixture.store, wrongPeriod), error => error.code === "WEBHOOK_CATALOG_MISMATCH");
});

test("signed webhook parsing is strict and pins grants to the trusted catalog", async context => {
  const fixture = await temporaryStore(context);
  const occurredAt = new Date().toISOString();
  const valid = transactionEvent({ eventNumber: 1, transactionNumber: 1, occurredAt });
  assert.equal((await deliver(fixture.store, valid)).inserted, true);
  await fixture.store.processDue();
  const state = await fixture.store.snapshot();
  assert.equal(state.catalogMappings[oneTimePriceId].productKey, oneTimeCatalog.productKey);
  assert.equal(state.catalogMappings[oneTimePriceId].priceKey, oneTimeCatalog.priceKey);
  assert.deepEqual(state.catalogMappings[oneTimePriceId].grants, [{ entitlement: "team_exports", quantity: 1 }]);
  assert.equal((await fixture.store.getEntitlement(buyer)).active, true);

  const injected = { ...valid, grant_key: "administrator" };
  await assert.rejects(deliver(fixture.store, injected), error => error.code === "WEBHOOK_PAYLOAD_INVALID");

  const wrongEnvironment = transactionEvent({ eventNumber: 2, transactionNumber: 2, occurredAt });
  wrongEnvironment.data.custom_data.vibenest_environment_id = `sim_env_${"f".repeat(24)}`;
  await assert.rejects(deliver(fixture.store, wrongEnvironment), error => error.code === "WEBHOOK_ENVIRONMENT_MISMATCH");

  const wrongDestination = transactionEvent({ eventNumber: 4, transactionNumber: 4, occurredAt });
  const wrongDestinationRaw = rawEvent(wrongDestination);
  const wrongDestinationTimestamp = Math.floor(Date.parse(occurredAt) / 1000);
  await assert.rejects(acceptSignedEvent({
    rawBody: wrongDestinationRaw,
    signature: signEvent(wrongDestinationRaw, simulatorSecret, wrongDestinationTimestamp),
    secret: simulatorSecret,
    nowSeconds: wrongDestinationTimestamp,
    destinationKey: `sim_env_${"f".repeat(24)}`,
    environmentId,
    runtimeCatalog,
    store: fixture.store
  }), error => error.code === "WEBHOOK_DESTINATION_INVALID");

  const wrongCatalog = transactionEvent({ eventNumber: 3, transactionNumber: 3, occurredAt });
  wrongCatalog.data.items[0].price_id = `sim_price_${"9".repeat(24)}`;
  wrongCatalog.data.items[0].product_id = `sim_prod_${"8".repeat(24)}`;
  await assert.rejects(deliver(fixture.store, wrongCatalog), error => error.code === "WEBHOOK_CATALOG_MISMATCH");
});

test("durable inbox deduplicates, fences stale state, and recovers expired leases", async context => {
  const directory = await mkdtemp(join(tmpdir(), "vn-pp-store-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, "store.json");
  const base = Date.now() - 5_000;
  const store = new DurableProjectPaymentStore(file, { leaseMilliseconds: 10, clock: () => new Date(base) });
  const periodStart = new Date(base).toISOString();
  const active = subscriptionEvent({ eventNumber: 10, subscriptionNumber: 1, eventType: "subscription.created", occurredAt: periodStart, periodStartsAt: periodStart });
  await deliver(store, active);
  await deliver(store, active);
  const claimed = await store.claimNextDue(new Date(base + 1_000));
  assert.ok(claimed?.leaseId);

  const restarted = new DurableProjectPaymentStore(file, { leaseMilliseconds: 10 });
  assert.deepEqual(await restarted.processDue(new Date(base + 1_020)), { applied: 1, ignored: 0, failed: 0 });
  let state = await restarted.snapshot();
  assert.ok(state.evidence.includes("duplicate-delivery"));
  assert.equal(state.evidence.includes("restart-replay"), false);
  assert.equal((await restarted.getEntitlement(buyer, trustedCatalog.entitlement, new Date(base + 2_000))).active, true);

  const newerCancel = subscriptionEvent({ eventNumber: 12, subscriptionNumber: 1, eventType: "subscription.canceled", occurredAt: new Date(base + 4_000).toISOString(), periodStartsAt: periodStart });
  const olderActive = subscriptionEvent({ eventNumber: 11, subscriptionNumber: 1, eventType: "subscription.created", occurredAt: new Date(base + 3_000).toISOString(), periodStartsAt: periodStart });
  const olderOccurrenceWithLaterPeriod = subscriptionEvent({
    eventNumber: 13,
    subscriptionNumber: 1,
    eventType: "subscription.created",
    occurredAt: new Date(base + 2_000).toISOString(),
    periodStartsAt: periodEnd(periodStart)
  });
  await deliver(restarted, newerCancel);
  await deliver(restarted, olderActive);
  await deliver(restarted, olderOccurrenceWithLaterPeriod);
  await restarted.processDue(new Date(Date.now() + 1_000));
  state = await restarted.snapshot();
  const entitlement = Object.values(state.entitlements).find(row => row.subjectKey === buyer && row.grantKey === "team_exports");
  assert.equal(entitlement.status, "revoked");
  assert.equal(state.events.find(event => event.providerEventId === eventId(11)).ignoredAsStale, true);
  assert.equal(state.events.find(event => event.providerEventId === eventId(13)).ignoredAsStale, true);
  assert.ok(state.evidence.includes("out-of-order-delivery"));

  const header = await readFile(file);
  assert.equal(header.subarray(0, 16).toString("utf8"), "SQLite format 3\u0000");
  const database = new DatabaseSync(file);
  try {
    const tables = database.prepare(`
      SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'project_payment_%'
    `).all().map(row => row.name).sort();
    assert.ok(tables.includes("project_payment_webhook_event"));
    assert.ok(tables.includes("project_payment_entitlement_source"));
    assert.ok(tables.includes("project_payment_entitlement"));
  } finally {
    database.close();
  }
});

test("renewal advances the signed period exactly once and matching transaction does not extend it", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 10_000;
  const initialStart = at(base, 0);
  const renewedStart = periodEnd(initialStart);
  const renewedEnd = periodEnd(renewedStart);
  const subscriptionId = providerId("sim_sub", 30);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 30,
    subscriptionNumber: 30,
    eventType: "subscription.created",
    occurredAt: at(base, 0),
    periodStartsAt: initialStart
  }));
  await fixture.store.processDue();
  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 31,
    subscriptionNumber: 30,
    eventType: "subscription.updated",
    occurredAt: at(base, 1),
    periodStartsAt: renewedStart
  }));
  await fixture.store.processDue();
  await deliver(fixture.store, transactionEvent({
    eventNumber: 32,
    transactionNumber: 32,
    occurredAt: at(base, 2),
    subscriptionId,
    periodStartsAt: renewedStart
  }));
  await fixture.store.processDue();
  let row = Object.values((await fixture.store.snapshot()).entitlements).find(item => item.sourceKey === `subscription:${subscriptionId}`);
  assert.equal(row.periodStartsAt, renewedStart);
  assert.equal(row.periodEndsAt, renewedEnd);
  assert.equal(row.effectiveUntil, renewedEnd);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 33,
    subscriptionNumber: 30,
    eventType: "subscription.updated",
    occurredAt: at(base, 3),
    periodStartsAt: renewedStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 0, ignored: 0, failed: 1 });
  row = Object.values((await fixture.store.snapshot()).entitlements).find(item => item.sourceKey === `subscription:${subscriptionId}`);
  assert.equal(row.periodEndsAt, renewedEnd);
});

test("two paid sources are summed and a recurring refund plus cancellation preserves the independent source", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 20_000;
  const subjectKey = "qa-selective-refund";
  const periodStart = at(base, 1);
  const subscriptionId = providerId("sim_sub", 41);
  const oneTimeTransaction = providerId("sim_txn", 40);
  const recurringTransaction = providerId("sim_txn", 42);

  const events = [
    transactionEvent({ eventNumber: 40, transactionNumber: 40, occurredAt: at(base, 0), subjectKey }),
    subscriptionEvent({ eventNumber: 41, subscriptionNumber: 41, eventType: "subscription.created", occurredAt: at(base, 1), subjectKey, periodStartsAt: periodStart }),
    transactionEvent({ eventNumber: 42, transactionNumber: 42, occurredAt: at(base, 2), subscriptionId, subjectKey, periodStartsAt: periodStart })
  ];
  for (const event of events) await deliver(fixture.store, event);
  assert.equal((await fixture.store.processDue()).failed, 0);
  let snapshot = await fixture.store.snapshot();
  let sources = Object.values(snapshot.entitlements).filter(row =>
    row.subjectKey === subjectKey && row.grantKey === "team_exports");
  let aggregate = snapshot.entitlementAggregates[`${subjectKey}:team_exports`];
  assert.equal(sources.length, 2);
  assert.equal(sources.find(row => row.sourceKey === `transaction:${oneTimeTransaction}`).status, "active");
  assert.equal(sources.find(row => row.sourceKey === `subscription:${subscriptionId}`).status, "active");
  assert.equal(sources.find(row => row.sourceKey === `subscription:${subscriptionId}`).latestTransactionId, recurringTransaction);
  assert.equal(aggregate.quantity, 2);
  assert.equal(aggregate.status, "active");
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, true);

  await deliver(fixture.store, adjustmentEvent({
    eventNumber: 43,
    adjustmentNumber: 43,
    transactionId: recurringTransaction,
    eventType: "adjustment.updated",
    occurredAt: at(base, 3)
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  sources = Object.values(snapshot.entitlements).filter(row =>
    row.subjectKey === subjectKey && row.grantKey === "team_exports");
  aggregate = snapshot.entitlementAggregates[`${subjectKey}:team_exports`];
  assert.equal(snapshot.refundedTransactions[recurringTransaction].subscriptionId, subscriptionId);
  assert.equal(snapshot.refundedTransactions[recurringTransaction].environmentId, environmentId);
  assert.equal(snapshot.refundedTransactions[recurringTransaction].subjectKey, subjectKey);
  assert.equal(snapshot.refundedTransactions[recurringTransaction].sourceKey, `subscription:${subscriptionId}`);
  assert.equal(sources.find(row => row.sourceKey === `transaction:${oneTimeTransaction}`).status, "active");
  assert.equal(sources.find(row => row.sourceKey === `subscription:${subscriptionId}`).status, "revoked");
  assert.equal(aggregate.quantity, 1);
  assert.equal(aggregate.status, "active");
  assert.equal(snapshot.evidence.includes("immediate-refund"), false);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, true);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 44,
    subscriptionNumber: 41,
    eventType: "subscription.canceled",
    occurredAt: at(base, 4),
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  aggregate = snapshot.entitlementAggregates[`${subjectKey}:team_exports`];
  assert.equal(snapshot.subscriptions[subscriptionId].status, "revoked");
  assert.equal(snapshot.evidence.includes("immediate-refund"), true);
  assert.equal(aggregate.quantity, 1);
  assert.equal(aggregate.status, "active");
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, true);
});

test("cancellation then an older approved refund converges terminal state and evidence", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 20_000;
  const subjectKey = "qa-cancel-then-refund";
  const periodStart = at(base, 0);
  const subscriptionId = providerId("sim_sub", 71);
  const transactionId = providerId("sim_txn", 72);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 70,
    subscriptionNumber: 71,
    eventType: "subscription.created",
    occurredAt: at(base, 0),
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, transactionEvent({
    eventNumber: 71,
    transactionNumber: 72,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 72,
    subscriptionNumber: 71,
    eventType: "subscription.canceled",
    occurredAt: at(base, 3),
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.equal((await fixture.store.processDue()).failed, 0);
  let snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.subscriptions[subscriptionId].status, "revoked");
  assert.equal(snapshot.evidence.includes("immediate-refund"), false);

  await deliver(fixture.store, adjustmentEvent({
    eventNumber: 73,
    adjustmentNumber: 73,
    transactionId,
    eventType: "adjustment.updated",
    occurredAt: at(base, 2)
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  const source = snapshot.entitlements[`${subjectKey}:team_exports:subscription:${subscriptionId}`];
  const aggregate = snapshot.entitlementAggregates[`${subjectKey}:team_exports`];
  assert.equal(snapshot.refundedTransactions[transactionId].subscriptionId, subscriptionId);
  assert.equal(snapshot.refundedTransactions[transactionId].approvedAt, at(base, 2));
  assert.equal(source.status, "revoked");
  assert.equal(source.lastOccurredAt, at(base, 3));
  assert.equal(aggregate.status, "revoked");
  assert.equal(aggregate.quantity, 0);
  assert.equal(snapshot.evidence.includes("immediate-refund"), true);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, false);
});

test("approved refunds fence the exact transaction and the whole linked subscription", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 20_000;
  const subjectKey = "qa-refund-fence";
  const periodStart = at(base, 0);
  const subscriptionId = providerId("sim_sub", 81);
  const refundedTransactionId = providerId("sim_txn", 82);
  const secondTransactionId = providerId("sim_txn", 83);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 80,
    subscriptionNumber: 81,
    eventType: "subscription.created",
    occurredAt: at(base, 0),
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, transactionEvent({
    eventNumber: 81,
    transactionNumber: 82,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, adjustmentEvent({
    eventNumber: 82,
    adjustmentNumber: 82,
    transactionId: refundedTransactionId,
    eventType: "adjustment.updated",
    occurredAt: at(base, 2)
  }));
  assert.equal((await fixture.store.processDue()).failed, 0);

  await deliver(fixture.store, transactionEvent({
    eventNumber: 83,
    transactionNumber: 82,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, transactionEvent({
    eventNumber: 84,
    transactionNumber: 83,
    occurredAt: at(base, 2),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 0, ignored: 2, failed: 0 });

  await deliver(fixture.store, transactionEvent({
    eventNumber: 85,
    transactionNumber: 82,
    occurredAt: at(base, 3),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, transactionEvent({
    eventNumber: 86,
    transactionNumber: 83,
    occurredAt: at(base, 3),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 87,
    subscriptionNumber: 81,
    eventType: "subscription.created",
    occurredAt: at(base, 3),
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 0, ignored: 0, failed: 3 });
  const snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.transactions[secondTransactionId], undefined);
  assert.equal(snapshot.entitlements[`${subjectKey}:team_exports:subscription:${subscriptionId}`].status, "revoked");
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].status, "revoked");
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].quantity, 0);
  assert.equal(snapshot.evidence.includes("immediate-refund"), false);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, false);
  assert.equal(snapshot.events.find(event => event.providerEventId === eventId(85)).lastErrorCode, "TRANSACTION_ID_COLLISION");
  for (const number of [86, 87]) assert.equal(
    snapshot.events.find(event => event.providerEventId === eventId(number)).lastErrorCode,
    "TERMINAL_REFUND_FENCE"
  );
});

test("a stale recurring transaction keeps its immutable projection so a later refund resolves", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 20_000;
  const subjectKey = "qa-stale-transaction-projection";
  const periodStart = at(base, 0);
  const subscriptionId = providerId("sim_sub", 91);
  const transactionId = providerId("sim_txn", 92);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 90,
    subscriptionNumber: 91,
    eventType: "subscription.created",
    occurredAt: at(base, 2),
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.equal((await fixture.store.processDue()).failed, 0);
  await deliver(fixture.store, transactionEvent({
    eventNumber: 91,
    transactionNumber: 92,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 0, ignored: 1, failed: 0 });
  let snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.transactions[transactionId].subscriptionId, subscriptionId);
  assert.equal(snapshot.transactions[transactionId].occurredAt, at(base, 1));
  assert.equal(snapshot.entitlements[`${subjectKey}:team_exports:subscription:${subscriptionId}`].latestTransactionId, transactionId);

  await deliver(fixture.store, adjustmentEvent({
    eventNumber: 92,
    adjustmentNumber: 92,
    transactionId,
    eventType: "adjustment.updated",
    occurredAt: at(base, 3)
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.refundedTransactions[transactionId].subscriptionId, subscriptionId);
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].status, "revoked");
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].quantity, 0);
});

test("a delayed refund and cancellation dominate an already-applied post-approval T2", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 20_000;
  const subjectKey = "qa-delayed-terminal-convergence";
  const periodStart = at(base, 0);
  const subscriptionId = providerId("sim_sub", 101);
  const firstTransactionId = providerId("sim_txn", 102);
  const secondTransactionId = providerId("sim_txn", 103);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 100,
    subscriptionNumber: 101,
    eventType: "subscription.created",
    occurredAt: at(base, 0),
    subjectKey,
    periodStartsAt: periodStart
  }));
  await deliver(fixture.store, transactionEvent({
    eventNumber: 101,
    transactionNumber: 102,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.equal((await fixture.store.processDue()).failed, 0);

  await deliver(fixture.store, transactionEvent({
    eventNumber: 102,
    transactionNumber: 103,
    occurredAt: at(base, 3),
    subscriptionId,
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  let snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.transactions[secondTransactionId].subscriptionId, subscriptionId);
  assert.equal(snapshot.entitlements[`${subjectKey}:team_exports:subscription:${subscriptionId}`].latestTransactionId, secondTransactionId);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, true);

  await deliver(fixture.store, adjustmentEvent({
    eventNumber: 103,
    adjustmentNumber: 103,
    transactionId: firstTransactionId,
    eventType: "adjustment.updated",
    occurredAt: at(base, 2)
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.entitlements[`${subjectKey}:team_exports:subscription:${subscriptionId}`].status, "revoked");
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].quantity, 0);
  assert.equal(snapshot.evidence.includes("immediate-refund"), false);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, false);

  await deliver(fixture.store, subscriptionEvent({
    eventNumber: 104,
    subscriptionNumber: 101,
    eventType: "subscription.canceled",
    occurredAt: new Date(base + 2_500).toISOString(),
    subjectKey,
    periodStartsAt: periodStart
  }));
  assert.deepEqual(await fixture.store.processDue(), { applied: 1, ignored: 0, failed: 0 });
  snapshot = await fixture.store.snapshot();
  assert.equal(snapshot.subscriptions[subscriptionId].status, "revoked");
  assert.equal(snapshot.evidence.includes("immediate-refund"), true);
  assert.equal(snapshot.entitlementAggregates[`${subjectKey}:team_exports`].quantity, 0);
  assert.equal((await fixture.store.getEntitlement(subjectKey)).active, false);
});

test("subscription identity is symmetric and a terminal source cannot be reactivated", async context => {
  const base = Date.now() - 20_000;
  const periodStart = at(base, 0);
  const subscriptionId = providerId("sim_sub", 61);

  const transactionFirst = await temporaryStore(context);
  await deliver(transactionFirst.store, transactionEvent({
    eventNumber: 61,
    transactionNumber: 61,
    occurredAt: at(base, 1),
    subscriptionId,
    subjectKey: "qa-identity-a",
    periodStartsAt: periodStart
  }));
  assert.equal((await transactionFirst.store.processDue()).failed, 0);
  await deliver(transactionFirst.store, subscriptionEvent({
    eventNumber: 62,
    subscriptionNumber: 61,
    eventType: "subscription.created",
    occurredAt: at(base, 2),
    subjectKey: "qa-identity-b",
    periodStartsAt: periodStart
  }));
  assert.equal((await transactionFirst.store.processDue()).failed, 1);
  assert.equal((await transactionFirst.store.getEntitlement("qa-identity-b")).active, false);

  const terminal = await temporaryStore(context);
  await deliver(terminal.store, subscriptionEvent({
    eventNumber: 63,
    subscriptionNumber: 61,
    eventType: "subscription.created",
    occurredAt: at(base, 3),
    subjectKey: "qa-terminal",
    periodStartsAt: periodStart
  }));
  await deliver(terminal.store, subscriptionEvent({
    eventNumber: 64,
    subscriptionNumber: 61,
    eventType: "subscription.canceled",
    occurredAt: at(base, 4),
    subjectKey: "qa-terminal",
    periodStartsAt: periodStart
  }));
  assert.equal((await terminal.store.processDue()).failed, 0);
  await deliver(terminal.store, transactionEvent({
    eventNumber: 65,
    transactionNumber: 65,
    occurredAt: at(base, 5),
    subscriptionId,
    subjectKey: "qa-terminal",
    periodStartsAt: periodStart
  }));
  assert.equal((await terminal.store.processDue()).failed, 1);
  assert.equal((await terminal.store.getEntitlement("qa-terminal")).active, false);
});

test("recognized lifecycle events produce bounded evidence and terminal cancellation revokes access", async context => {
  const fixture = await temporaryStore(context);
  const base = Date.now() - 30_000;
  const subscriptionId = providerId("sim_sub", 3);
  const subscriptionTransactionId = providerId("sim_txn", 4);
  const initialPeriodStart = at(base, 1);
  const renewalPeriodStart = periodEnd(initialPeriodStart);
  const renewalPeriodEnd = periodEnd(renewalPeriodStart);

  const events = [
    transactionEvent({ eventNumber: 20, transactionNumber: 2, occurredAt: at(base, 0), subjectKey: "qa-one-time-buyer" }),
    subscriptionEvent({ eventNumber: 21, subscriptionNumber: 3, eventType: "subscription.created", occurredAt: at(base, 1), periodStartsAt: initialPeriodStart }),
    transactionEvent({ eventNumber: 22, transactionNumber: 4, subscriptionId, occurredAt: at(base, 2), periodStartsAt: initialPeriodStart }),
    transactionEvent({ eventNumber: 23, transactionNumber: 5, eventType: "transaction.payment_failed", occurredAt: at(base, 3), subjectKey: "qa-declined-only" }),
    subscriptionEvent({ eventNumber: 24, subscriptionNumber: 3, eventType: "subscription.updated", occurredAt: at(base, 4), periodStartsAt: renewalPeriodStart }),
    subscriptionEvent({ eventNumber: 25, subscriptionNumber: 3, eventType: "subscription.updated", occurredAt: at(base, 5), periodStartsAt: renewalPeriodStart, scheduledCancelAt: renewalPeriodEnd }),
    adjustmentEvent({ eventNumber: 26, adjustmentNumber: 1, transactionId: subscriptionTransactionId, eventType: "adjustment.created", occurredAt: at(base, 6) }),
    adjustmentEvent({ eventNumber: 27, adjustmentNumber: 1, transactionId: subscriptionTransactionId, eventType: "adjustment.updated", occurredAt: at(base, 7) }),
    subscriptionEvent({ eventNumber: 28, subscriptionNumber: 3, eventType: "subscription.canceled", occurredAt: at(base, 8), periodStartsAt: renewalPeriodStart }),
    portalEvent({ eventNumber: 29, portalNumber: 1, occurredAt: at(base, 9) })
  ];
  for (const payload of events) await deliver(fixture.store, payload);
  await fixture.store.processDue();
  const evidence = (await fixture.store.snapshot()).evidence;
  for (const expected of [
    "one-time-purchase", "subscription-purchase", "declined-checkout", "renewal",
    "scheduled-cancellation", "immediate-refund", "customer-portal"
  ]) assert.ok(evidence.includes(expected), expected);
  assert.equal((await fixture.store.getEntitlement("qa-declined-only")).active, false);
  assert.equal((await fixture.store.getEntitlement(buyer)).active, false);
});

test("verifier is secret-, challenge-, lifecycle-, and durable-inbox-gated", async context => {
  const fixture = await temporaryStore(context);
  await deliver(fixture.store, transactionEvent({ eventNumber: 40, transactionNumber: 8, occurredAt: new Date().toISOString() }));
  await fixture.store.processDue();
  for (const name of requiredLifecycleEvidence) await fixture.store.recordEvidence(name);
  assert.deepEqual(
    await fixture.store.stageRestartReplayProbe(environmentId),
    { action: "restart-replay", state: "staged" }
  );
  assert.deepEqual(await fixture.store.processDue(), { applied: 0, ignored: 0, failed: 0 });
  const child = await runRestartReplayChild(fixture.file);
  assert.deepEqual(child.result, { applied: 1, ignored: 0, failed: 0 });
  const manifestDigest = computeManifestDigest();
  const input = {
    provider: providerModes.simulator,
    paymentsEnabled: true,
    verifierEnabled: true,
    suppliedSecret: simulatorSecret,
    configuredSecret: simulatorSecret,
    expectedCommit: commitSha,
    builtCommit: commitSha,
    expectedManifestDigest: manifestDigest,
    installedManifestDigest: manifestDigest,
    environmentId,
    store: fixture.store
  };
  assert.deepEqual(await buildVerifierPayload(input), {
    provider: "simulator",
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha,
    manifestDigest,
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  });
  assert.equal(await buildVerifierPayload({ ...input, suppliedSecret: undefined }), null);
  assert.equal(await buildVerifierPayload({ ...input, configuredSecret: "short", suppliedSecret: "short" }), null);
  assert.equal(await buildVerifierPayload({ ...input, expectedCommit: "b".repeat(40) }), null);
  assert.equal(await buildVerifierPayload({ ...input, provider: providerModes.disabled }), null);
});

test("provider factory fails closed and future Paddle mode performs no live operation", async () => {
  const disabled = createProjectPaymentProvider({
    VIBENEST_PROJECT_PAYMENTS_ENABLED: "false",
    VIBENEST_PROJECT_PAYMENTS_PROVIDER: "simulator"
  });
  await assert.rejects(disabled.createCheckout({}), error => error.code === "PAYMENTS_DISABLED");
  const paddle = new PaddleProjectPaymentProvider();
  await assert.rejects(paddle.createPortal(buyer), error => error.code === "PADDLE_NOT_CONFIGURED");
});

test("credential scanner reports only paths and classifications", async context => {
  const directory = await mkdtemp(join(tmpdir(), "vn-pp-scan-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "safe.txt"), "configuration names only\n", "utf8");
  assert.deepEqual(await scanProjectTree(directory), { clean: true, scannedFiles: 1, findings: [] });
  const synthetic = ["vnp", "i_", "A".repeat(24)].join("");
  await writeFile(join(directory, "unsafe.txt"), synthetic, "utf8");
  const result = await scanProjectTree(directory);
  assert.equal(result.clean, false);
  assert.deepEqual(result.findings, [{ file: "unsafe.txt", kind: "VibeNest install code" }]);
  assert.equal(JSON.stringify(result).includes(synthetic), false);
});

export function transactionEvent({
  eventNumber,
  transactionNumber,
  occurredAt,
  eventType = "transaction.completed",
  subscriptionId = null,
  subjectKey = buyer,
  periodStartsAt = occurredAt
}) {
  const oneTime = eventType === "transaction.completed" && subscriptionId === null;
  return envelope(eventNumber, eventType, occurredAt, {
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

export function subscriptionEvent({
  eventNumber,
  subscriptionNumber,
  eventType,
  occurredAt,
  scheduledCancelAt = null,
  subjectKey = buyer,
  periodStartsAt = occurredAt
}) {
  return envelope(eventNumber, eventType, occurredAt, {
    id: providerId("sim_sub", subscriptionNumber),
    status: eventType === "subscription.canceled" ? "canceled" : "active",
    customer_id: subjectKey,
    items: [{ price_id: priceId, product_id: productId, quantity: 1 }],
    current_billing_period: billingPeriod(periodStartsAt),
    scheduled_change: scheduledCancelAt === null ? null : { action: "cancel", effective_at: scheduledCancelAt },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

export function adjustmentEvent({ eventNumber, adjustmentNumber, transactionId, eventType, occurredAt }) {
  return envelope(eventNumber, eventType, occurredAt, {
    id: providerId("sim_adj", adjustmentNumber),
    action: "refund",
    status: eventType === "adjustment.created" ? "pending_approval" : "approved",
    transaction_id: transactionId,
    totals: { total: "1500", currency_code: "USD" },
    custom_data: { vibenest_environment_id: environmentId }
  });
}

export function portalEvent({ eventNumber, portalNumber, occurredAt, subjectKey = buyer }) {
  return envelope(eventNumber, "customer.portal_session.created", occurredAt, {
    id: providerId("sim_portal", portalNumber),
    customer_id: subjectKey,
    url: `https://simulator.invalid/portal/${environmentId}/${subjectKey}`,
    expires_at: new Date(Date.parse(occurredAt) + 30 * 60_000).toISOString(),
    custom_data: { vibenest_environment_id: environmentId }
  });
}

export function rawEvent(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8");
}

export function signatureFor(payload) {
  const timestamp = Math.floor(Date.parse(payload.occurred_at) / 1000);
  return signEvent(rawEvent(payload), simulatorSecret, timestamp);
}

export const testRuntime = Object.freeze({ simulatorSecret, environmentId, buyer, productId, priceId });

function envelope(number, eventType, occurredAt, data) {
  return {
    event_id: eventId(number),
    event_type: eventType,
    occurred_at: occurredAt,
    notification_id: providerId("sim_ntf", number),
    data
  };
}

function eventId(number) {
  return providerId("sim_evt", number);
}

function providerId(prefix, number) {
  return `${prefix}_${number.toString(16).padStart(24, "0")}`;
}

async function deliver(store, payload) {
  const rawBody = rawEvent(payload);
  const timestamp = Math.floor(Date.parse(payload.occurred_at) / 1000);
  return acceptSignedEvent({
    rawBody,
    signature: signEvent(rawBody, simulatorSecret, timestamp),
    secret: simulatorSecret,
    nowSeconds: timestamp,
    destinationKey: environmentId,
    environmentId,
    runtimeCatalog,
    store
  });
}

async function temporaryStore(context) {
  const directory = await mkdtemp(join(tmpdir(), "vn-pp-test-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, "store.sqlite");
  return {
    directory,
    file,
    store: new DurableProjectPaymentStore(file, { evidenceScope })
  };
}

async function runRestartReplayChild(storePath) {
  const { stdout } = await execFileAsync(process.execPath, [
    restartReplayChild,
    storePath,
    evidenceScope
  ], {
    encoding: "utf8",
    timeout: 10_000,
    windowsHide: true
  });
  return JSON.parse(stdout);
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
  return encodeCatalog(runtimeCatalogDocument());
}

function encodeCatalog(document) {
  return Buffer.from(JSON.stringify(document), "utf8").toString("base64");
}

function runtimeCatalogDocument() {
  return {
    provider: "simulator",
    sellerExternalId: `sim_seller_${"9".repeat(24)}`,
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
  };
}
