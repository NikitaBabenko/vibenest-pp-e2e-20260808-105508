import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { TextDecoder } from "node:util";

const processBootInstanceId = randomUUID();
const restartReplayProbeEventType = "internal.restart_replay_probe";
const verifierCommitPattern = /^[0-9a-f]{40}$/;
const verifierDigestPattern = /^[0-9a-f]{64}$/;

export const providerModes = Object.freeze({
  simulator: "simulator",
  paddle: "paddle",
  disabled: "disabled"
});

export const requiredLifecycleEvidence = Object.freeze([
  "price-preview",
  "one-time-purchase",
  "subscription-purchase",
  "declined-checkout",
  "duplicate-delivery",
  "out-of-order-delivery",
  "renewal",
  "scheduled-cancellation",
  "immediate-refund",
  "customer-portal"
]);

export function computeRuntimeEvidenceScope(environmentId, manifestDigest, builtCommit) {
  if (!idPatterns.environment.test(environmentId ?? "")) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator evidence environment is invalid.");
  }
  if (!verifierDigestPattern.test(manifestDigest ?? "")) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator evidence manifest digest is invalid.");
  }
  if (!verifierCommitPattern.test(builtCommit ?? "")) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator evidence build commit is invalid.");
  }
  return createHash("sha256")
    .update("vibenest-project-payments-evidence-v1\0", "utf8")
    .update(environmentId, "utf8")
    .update("\0", "utf8")
    .update(manifestDigest, "ascii")
    .update("\0", "utf8")
    .update(builtCommit, "ascii")
    .digest("hex");
}

export const trustedCatalog = Object.freeze({
  projectKey: "project-532",
  productKey: "pro",
  productName: "Pro",
  description: "Team export access for active subscribers",
  priceKey: "monthly",
  currency: "USD",
  unitAmount: 1500,
  type: "recurring",
  interval: "month",
  entitlement: "team_exports",
  quantity: 1,
  successPath: "/billing/success",
  cancelPath: "/pricing",
  refundWindowDays: 14
});

export const oneTimeCatalog = Object.freeze({
  productKey: "lifetime",
  productName: "Lifetime",
  description: "Simulator-only one-time team export access",
  priceKey: "once",
  currency: "USD",
  unitAmount: 1500,
  type: "one_time",
  interval: null,
  entitlement: "team_exports",
  quantity: 1
});

const declaredCatalogs = Object.freeze([oneTimeCatalog, trustedCatalog]);

const recognizedEventTypes = new Set([
  "transaction.completed",
  "transaction.payment_failed",
  "subscription.created",
  "subscription.updated",
  "subscription.canceled",
  "adjustment.created",
  "adjustment.updated",
  "customer.portal_session.created"
]);
const idPatterns = Object.freeze({
  event: /^sim_evt_[0-9a-f]{24}$/,
  notification: /^sim_ntf_[0-9a-f]{24}$/,
  transaction: /^sim_txn_[0-9a-f]{24}$/,
  subscription: /^sim_sub_[0-9a-f]{24}$/,
  adjustment: /^sim_adj_[0-9a-f]{24}$/,
  portal: /^sim_portal_[0-9a-f]{24}$/,
  seller: /^sim_seller_[0-9a-f]{24}$/,
  product: /^sim_prod_[0-9a-f]{24}$/,
  price: /^sim_price_[0-9a-f]{24}$/,
  environment: /^sim_env_[0-9a-f]{24}$/,
  buyer: /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/
});

export class ProjectPaymentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProjectPaymentError";
    this.code = code;
  }
}

export class DisabledProjectPaymentProvider {
  mode = providerModes.disabled;

  async previewPrices() { throw new ProjectPaymentError("PAYMENTS_DISABLED", "Project payments are disabled."); }
  async createCheckout() { throw new ProjectPaymentError("PAYMENTS_DISABLED", "Project payments are disabled."); }
  async createPortal() { throw new ProjectPaymentError("PAYMENTS_DISABLED", "Project payments are disabled."); }
}

export class PaddleProjectPaymentProvider {
  mode = providerModes.paddle;

  async previewPrices() { throw unavailablePaddle(); }
  async createCheckout() { throw unavailablePaddle(); }
  async createPortal() { throw unavailablePaddle(); }
}

export class SimulatorProjectPaymentProvider {
  mode = providerModes.simulator;

  async previewPrices(priceKeys) {
    return priceKeys.map(priceKey => {
      const catalog = assertTrustedPriceKey(priceKey);
      return Object.freeze({
        priceKey,
        unitAmount: catalog.unitAmount,
        currency: catalog.currency,
        formatted: `${catalog.currency} ${(catalog.unitAmount / 100).toFixed(2)}`
      });
    });
  }

  async createCheckout({ buyerKey, priceKey, successUrl }) {
    assertBuyerKey(buyerKey);
    assertTrustedPriceKey(priceKey);
    if (successUrl !== trustedCatalog.successPath) {
      throw new ProjectPaymentError("CHECKOUT_PATH_INVALID", "The checkout success path is not trusted.");
    }
    return Object.freeze({
      id: stableId("sim_checkout", buyerKey, priceKey),
      checkoutUrl: `/billing/simulator/${simulatorSessionId(buyerKey, priceKey)}`,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString()
    });
  }

  async createPortal(buyerKey) {
    assertBuyerKey(buyerKey);
    return Object.freeze({
      url: `https://simulator.invalid/portal/${encodeURIComponent(buyerKey)}`,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString()
    });
  }
}

export function createProjectPaymentProvider(configuration) {
  if (configuration.VIBENEST_PROJECT_PAYMENTS_ENABLED !== "true") {
    return new DisabledProjectPaymentProvider();
  }
  switch (configuration.VIBENEST_PROJECT_PAYMENTS_PROVIDER) {
    case providerModes.simulator:
      return new SimulatorProjectPaymentProvider();
    case providerModes.paddle:
      return new PaddleProjectPaymentProvider();
    default:
      return new DisabledProjectPaymentProvider();
  }
}

export function isSimulatorRuntime(configuration) {
  return configuration.VIBENEST_PROJECT_PAYMENTS_ENABLED === "true"
    && configuration.VIBENEST_PROJECT_PAYMENTS_PROVIDER === providerModes.simulator;
}

export function validateSimulatorConfiguration(configuration) {
  if (!isSimulatorRuntime(configuration)) return null;
  const secret = configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET;
  const environmentId = configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID;
  const manifestDigest = configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST;
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator webhook credential is missing or too short.");
  }
  if (!idPatterns.environment.test(environmentId ?? "")) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator environment identifier is invalid.");
  }
  if (manifestDigest !== computeManifestDigest()) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The simulator manifest digest does not match the installed catalog.");
  }
  return parseRuntimeCatalog(
    configuration.VIBENEST_PROJECT_PAYMENTS_CATALOG_B64,
    environmentId,
    manifestDigest
  );
}

export function parseRuntimeCatalog(encoded, expectedEnvironmentId, expectedManifestDigest) {
  if (typeof encoded !== "string" || encoded.length < 16 || encoded.length > 128 * 1024
      || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The trusted simulator catalog is missing or invalid.");
  }
  let bytes;
  let document;
  try {
    bytes = Buffer.from(encoded, "base64");
    if (bytes.toString("base64") !== encoded) throw new Error("non-canonical base64");
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The trusted simulator catalog is not canonical UTF-8 JSON.");
  }
  assertPlainObject(document, "runtime catalog");
  assertExactKeys(document, ["provider", "sellerExternalId", "environmentExternalId", "manifestDigest", "products"], "runtime catalog");
  if (document.provider !== providerModes.simulator
      || !idPatterns.seller.test(document.sellerExternalId ?? "")
      || document.environmentExternalId !== expectedEnvironmentId
      || document.manifestDigest !== expectedManifestDigest) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime catalog authority does not match this simulator deployment.");
  }

  const manifest = canonicalManifest();
  if (!Array.isArray(document.products) || document.products.length !== manifest.products.length) {
    throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime product mapping does not match the manifest.");
  }
  const expectedProducts = new Map(manifest.products.map(product => [product.key, product]));
  const seenManifestProducts = new Set();
  const seenProductIds = new Set();
  const seenPriceIds = new Set();
  const pricesByExternalId = Object.create(null);

  for (const product of document.products) {
    assertPlainObject(product, "runtime product");
    assertExactKeys(product, ["manifestKey", "externalId", "prices", "grants"], "runtime product");
    const expectedProduct = expectedProducts.get(product.manifestKey);
    if (!expectedProduct || !markUnique(seenManifestProducts, product.manifestKey)
        || !idPatterns.product.test(product.externalId ?? "") || !markUnique(seenProductIds, product.externalId)) {
      throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime product mapping is invalid or duplicated.");
    }
    const expectedGrants = [...expectedProduct.grants]
      .sort((left, right) => left.entitlement.localeCompare(right.entitlement));
    if (!Array.isArray(product.grants) || product.grants.length !== expectedGrants.length) {
      throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime grant mapping does not match the manifest.");
    }
    const grants = product.grants
      .map(grant => {
        assertPlainObject(grant, "runtime grant");
        assertExactKeys(grant, ["entitlement", "quantity"], "runtime grant");
        if (typeof grant.entitlement !== "string" || !Number.isSafeInteger(grant.quantity) || grant.quantity < 1) {
          throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime grant mapping is invalid.");
        }
        return { entitlement: grant.entitlement, quantity: grant.quantity };
      })
      .sort((left, right) => left.entitlement.localeCompare(right.entitlement));
    if (grants.some((grant, index) => grant.entitlement !== expectedGrants[index].entitlement
        || grant.quantity !== expectedGrants[index].quantity)) {
      throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime grant mapping does not match the manifest.");
    }
    if (!Array.isArray(product.prices) || product.prices.length !== expectedProduct.prices.length) {
      throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime price mapping does not match the manifest.");
    }
    const expectedPrices = new Map(expectedProduct.prices.map(price => [price.key, price]));
    const seenManifestPrices = new Set();
    for (const price of product.prices) {
      assertPlainObject(price, "runtime price");
      assertExactKeys(price, ["manifestKey", "externalId", "currency", "unitAmount", "type", "interval"], "runtime price");
      const expectedPrice = expectedPrices.get(price.manifestKey);
      if (!expectedPrice || !markUnique(seenManifestPrices, price.manifestKey)
          || !idPatterns.price.test(price.externalId ?? "") || !markUnique(seenPriceIds, price.externalId)
          || price.currency !== expectedPrice.currency || price.unitAmount !== expectedPrice.unitAmount
          || price.type !== expectedPrice.type || price.interval !== expectedPrice.interval) {
        throw new ProjectPaymentError("SIMULATOR_CONFIG_INVALID", "The runtime price mapping is invalid, duplicated, or differs from the manifest.");
      }
      pricesByExternalId[price.externalId] = Object.freeze({
        productKey: product.manifestKey,
        priceKey: price.manifestKey,
        providerProductId: product.externalId,
        providerPriceId: price.externalId,
        currency: price.currency,
        unitAmount: price.unitAmount,
        type: price.type,
        interval: price.interval,
        grants: Object.freeze(grants.map(grant => Object.freeze({ ...grant })))
      });
    }
  }
  return Object.freeze({
    provider: document.provider,
    environmentExternalId: document.environmentExternalId,
    manifestDigest: document.manifestDigest,
    pricesByExternalId: Object.freeze(pricesByExternalId)
  });
}

export function canonicalManifest() {
  return {
    apiVersion: "vibenest.net/project-payments/v1alpha1",
    kind: "ProjectPayments",
    project: { key: trustedCatalog.projectKey },
    products: declaredCatalogs.map(catalog => ({
      key: catalog.productKey,
      name: catalog.productName,
      description: catalog.description,
      prices: [{
        key: catalog.priceKey,
        currency: catalog.currency,
        unitAmount: catalog.unitAmount,
        type: catalog.type,
        interval: catalog.interval
      }],
      grants: [{ entitlement: catalog.entitlement, quantity: catalog.quantity }]
    })),
    buyer: { identity: "user_id" },
    checkout: { successPath: trustedCatalog.successPath, cancelPath: trustedCatalog.cancelPath },
    portal: { enabled: true },
    refunds: { windowDays: trustedCatalog.refundWindowDays }
  };
}

export function computeManifestDigest() {
  return createHash("sha256").update(JSON.stringify(canonicalManifest()), "utf8").digest("hex");
}

export function signEvent(rawBody, secret, timestamp) {
  const bytes = asRawBuffer(rawBody);
  const digest = createHmac("sha256", secret)
    .update(String(timestamp), "utf8")
    .update(":", "utf8")
    .update(bytes)
    .digest("hex");
  return `ts=${timestamp};h1=${digest}`;
}

export function verifyEventSignature(rawBody, signature, secret, nowSeconds, toleranceSeconds = 300) {
  if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || rawBody.length > 128 * 1024) return false;
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) return false;
  if (typeof signature !== "string" || signature.length < 70 || signature.length > 1024) return false;
  const parts = signature.split(";").map(part => part.trim()).filter(Boolean);
  const timestamps = parts.filter(part => part.startsWith("ts="));
  const signatures = parts.filter(part => part.startsWith("h1="));
  if (timestamps.length !== 1 || signatures.length === 0) return false;
  const timestampText = timestamps[0].slice(3);
  if (!/^[0-9]+$/.test(timestampText)) return false;
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || Math.abs(nowSeconds - timestamp) > toleranceSeconds) return false;
  const expected = Buffer.from(signEvent(rawBody, secret, timestamp).split("h1=")[1], "hex");
  return signatures.some(part => {
    const supplied = part.slice(3);
    if (!/^[0-9a-f]{64}$/i.test(supplied)) return false;
    return timingSafeEqual(Buffer.from(supplied, "hex"), expected);
  });
}

export async function acceptSignedEvent({
  rawBody,
  signature,
  secret,
  nowSeconds,
  destinationKey,
  environmentId,
  runtimeCatalog,
  store
}) {
  if (destinationKey !== environmentId) {
    throw new ProjectPaymentError("WEBHOOK_DESTINATION_INVALID", "The webhook destination does not match the simulator environment.");
  }
  if (!verifyEventSignature(rawBody, signature, secret, nowSeconds)) {
    throw new ProjectPaymentError("WEBHOOK_SIGNATURE_INVALID", "The simulator signature is invalid.");
  }
  const normalized = normalizeSimulatorEvent(rawBody, environmentId, runtimeCatalog);
  const bodySha256 = createHash("sha256").update(rawBody).digest("hex");
  return store.insertVerifiedEvent({ destinationKey, bodySha256, normalized });
}

export function normalizeSimulatorEvent(rawBody, environmentId, runtimeCatalog) {
  if (!Buffer.isBuffer(rawBody)) {
    throw new ProjectPaymentError("WEBHOOK_BODY_INVALID", "The webhook body must be the untouched byte buffer.");
  }
  if (!idPatterns.environment.test(environmentId ?? "")) {
    throw new ProjectPaymentError("WEBHOOK_ENVIRONMENT_INVALID", "The expected simulator environment is invalid.");
  }
  if (runtimeCatalog?.provider !== providerModes.simulator
      || runtimeCatalog.environmentExternalId !== environmentId
      || runtimeCatalog.manifestDigest !== computeManifestDigest()) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The trusted simulator catalog mapping is unavailable.");
  }

  let root;
  try {
    root = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new ProjectPaymentError("WEBHOOK_JSON_INVALID", "The verified webhook body is not valid JSON.");
  }
  assertPlainObject(root, "event");
  assertExactKeys(root, ["event_id", "event_type", "occurred_at", "notification_id", "data"], "event");
  assertIdentifier(root.event_id, idPatterns.event, "event_id");
  assertIdentifier(root.notification_id, idPatterns.notification, "notification_id");
  if (!recognizedEventTypes.has(root.event_type)) {
    throw new ProjectPaymentError("WEBHOOK_EVENT_UNRECOGNIZED", "The simulator event type is not recognized.");
  }
  const occurredAt = parseDate(root.occurred_at, "occurred_at");
  assertPlainObject(root.data, "data");

  const common = {
    eventId: root.event_id,
    eventType: root.event_type,
    occurredAt,
    notificationId: root.notification_id
  };
  if (root.event_type.startsWith("transaction.")) {
    return Object.freeze({ ...common, ...normalizeTransaction(root.event_type, root.data, environmentId, runtimeCatalog) });
  }
  if (root.event_type.startsWith("subscription.")) {
    return Object.freeze({ ...common, ...normalizeSubscription(root.event_type, root.data, environmentId, runtimeCatalog, occurredAt) });
  }
  if (root.event_type.startsWith("adjustment.")) {
    return Object.freeze({ ...common, ...normalizeAdjustment(root.event_type, root.data, environmentId) });
  }
  return Object.freeze({ ...common, ...normalizePortal(root.data, environmentId, occurredAt) });
}

function normalizeTransaction(eventType, data, environmentId, runtimeCatalog) {
  assertExactKeys(data, ["id", "status", "customer_id", "subscription_id", "items", "details", "custom_data"], "transaction data");
  assertIdentifier(data.id, idPatterns.transaction, "transaction id");
  assertBuyerKey(data.customer_id);
  if (data.subscription_id !== null) assertIdentifier(data.subscription_id, idPatterns.subscription, "subscription id");
  const expectedStatus = eventType === "transaction.completed" ? "completed" : "declined";
  if (data.status !== expectedStatus) throw invalidPayload("The transaction status does not match its event type.");
  const mapping = normalizeItems(data.items, runtimeCatalog, true);
  if (eventType === "transaction.completed"
      && ((mapping.type === "recurring" && data.subscription_id === null)
        || (mapping.type === "one_time" && data.subscription_id !== null))) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The completed transaction does not match the trusted price type.");
  }
  assertEnvironment(data.custom_data, environmentId);
  assertPlainObject(data.details, "transaction details");
  assertExactKeys(data.details, ["totals"], "transaction details");
  assertTrustedTotals(data.details.totals, mapping);
  return {
    kind: eventType === "transaction.completed" ? "transaction_completed" : "transaction_declined",
    environmentId,
    subjectKey: data.customer_id,
    transactionId: data.id,
    subscriptionId: data.subscription_id,
    ...mapping,
    orderingKey: `${data.customer_id}:${mapping.providerPriceId}`
  };
}

function normalizeSubscription(eventType, data, environmentId, runtimeCatalog, occurredAt) {
  assertExactKeys(data, ["id", "status", "customer_id", "items", "current_billing_period", "scheduled_change", "custom_data"], "subscription data");
  assertIdentifier(data.id, idPatterns.subscription, "subscription id");
  assertBuyerKey(data.customer_id);
  assertEnvironment(data.custom_data, environmentId);
  const mapping = normalizeItems(data.items, runtimeCatalog, false);
  if (mapping.type !== "recurring") {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "Subscription events require a trusted recurring price.");
  }
  const billingPeriod = normalizeBillingPeriod(data.current_billing_period, mapping, "current_billing_period");
  let scheduledCancelAt = null;
  if (data.scheduled_change !== null) {
    assertPlainObject(data.scheduled_change, "scheduled change");
    assertExactKeys(data.scheduled_change, ["action", "effective_at"], "scheduled change");
    if (data.scheduled_change.action !== "cancel") throw invalidPayload("Only a scheduled cancellation is recognized.");
    scheduledCancelAt = parseDate(data.scheduled_change.effective_at, "scheduled change effective_at");
    if (Date.parse(scheduledCancelAt) !== Date.parse(billingPeriod.periodEndsAt)
        || Date.parse(scheduledCancelAt) <= Date.parse(occurredAt)) {
      throw invalidPayload("The scheduled cancellation must equal the signed current billing-period end.");
    }
  }
  if (eventType === "subscription.canceled") {
    if (data.status !== "canceled" || scheduledCancelAt !== null) throw invalidPayload("The canceled subscription payload is invalid.");
  } else if (data.status !== "active") {
    throw invalidPayload("Only active subscription create/update events are recognized.");
  }
  return {
    kind: eventType === "subscription.created"
      ? "subscription_created"
      : eventType === "subscription.canceled"
        ? "subscription_canceled"
        : scheduledCancelAt === null
          ? "subscription_renewed"
          : "subscription_scheduled_cancel",
    environmentId,
    subjectKey: data.customer_id,
    subscriptionId: data.id,
    scheduledCancelAt,
    ...billingPeriod,
    ...mapping,
    orderingKey: `${data.customer_id}:${mapping.providerPriceId}`
  };
}

function normalizeAdjustment(eventType, data, environmentId) {
  assertExactKeys(data, ["id", "action", "status", "transaction_id", "totals", "custom_data"], "adjustment data");
  assertIdentifier(data.id, idPatterns.adjustment, "adjustment id");
  assertIdentifier(data.transaction_id, idPatterns.transaction, "transaction id");
  assertEnvironment(data.custom_data, environmentId);
  const totals = readTotals(data.totals);
  if (data.action !== "refund") throw invalidPayload("Only refund adjustments are recognized.");
  const expectedStatus = eventType === "adjustment.created" ? "pending_approval" : "approved";
  if (data.status !== expectedStatus) throw invalidPayload("The adjustment status does not match its event type.");
  return {
    kind: eventType === "adjustment.created" ? "refund_pending" : "refund_approved",
    environmentId,
    adjustmentId: data.id,
    transactionId: data.transaction_id,
    unitAmount: totals.unitAmount,
    currency: totals.currency,
    orderingKey: `transaction:${data.transaction_id}`
  };
}

function normalizePortal(data, environmentId, occurredAt) {
  assertExactKeys(data, ["id", "customer_id", "url", "expires_at", "custom_data"], "portal data");
  assertIdentifier(data.id, idPatterns.portal, "portal session id");
  assertBuyerKey(data.customer_id);
  assertEnvironment(data.custom_data, environmentId);
  const expiresAt = parseDate(data.expires_at, "portal expires_at");
  if (Date.parse(expiresAt) <= Date.parse(occurredAt)) throw invalidPayload("The portal session is already expired.");
  let url;
  try { url = new URL(data.url); }
  catch { throw invalidPayload("The portal URL is invalid."); }
  const expectedPrefix = `/portal/${encodeURIComponent(environmentId)}/${encodeURIComponent(data.customer_id)}`;
  if (url.protocol !== "https:" || url.hostname !== "simulator.invalid" || url.pathname !== expectedPrefix || url.search || url.hash) {
    throw invalidPayload("The portal URL does not belong to the trusted simulator environment and buyer.");
  }
  return {
    kind: "portal_created",
    environmentId,
    subjectKey: data.customer_id,
    portalSessionId: data.id,
    orderingKey: `portal:${data.customer_id}`
  };
}

function normalizeItems(items, runtimeCatalog, transactionItem) {
  if (!Array.isArray(items) || items.length !== 1) throw invalidPayload("Exactly one trusted catalog item is required.");
  const item = items[0];
  assertPlainObject(item, "catalog item");
  assertExactKeys(
    item,
    transactionItem
      ? ["price_id", "product_id", "quantity", "billing_period"]
      : ["price_id", "product_id", "quantity"],
    "catalog item"
  );
  assertIdentifier(item.price_id, idPatterns.price, "provider price id");
  assertIdentifier(item.product_id, idPatterns.product, "provider product id");
  const mapping = runtimeCatalog.pricesByExternalId[item.price_id];
  if (!mapping || item.product_id !== mapping.providerProductId) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The event item is outside the trusted runtime-issued catalog mapping.");
  }
  if (item.quantity !== 1) throw invalidPayload("The catalog item quantity is invalid.");
  if (!transactionItem) return mapping;
  return { ...mapping, ...normalizeBillingPeriod(item.billing_period, mapping, "billing_period") };
}

function normalizeBillingPeriod(value, mapping, label) {
  if (mapping.type === "one_time") {
    if (value !== null) throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "A one-time price cannot carry a billing period.");
    return { periodStartsAt: null, periodEndsAt: null };
  }
  assertPlainObject(value, label);
  assertExactKeys(value, ["starts_at", "ends_at"], label);
  const periodStartsAt = parseDate(value.starts_at, `${label} starts_at`);
  const periodEndsAt = parseDate(value.ends_at, `${label} ends_at`);
  if (Date.parse(periodEndsAt) !== Date.parse(addBillingInterval(periodStartsAt, mapping.interval))) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The billing period does not match the trusted recurring interval.");
  }
  return { periodStartsAt, periodEndsAt };
}

function assertEnvironment(customData, environmentId) {
  assertPlainObject(customData, "custom_data");
  assertExactKeys(customData, ["vibenest_environment_id"], "custom_data");
  if (customData.vibenest_environment_id !== environmentId) {
    throw new ProjectPaymentError("WEBHOOK_ENVIRONMENT_MISMATCH", "The event belongs to another simulator environment.");
  }
}

function assertTrustedTotals(totals, mapping) {
  const parsed = readTotals(totals);
  if (parsed.unitAmount !== mapping.unitAmount || parsed.currency !== mapping.currency) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The event amount or currency is outside the trusted catalog.");
  }
}

function readTotals(totals) {
  assertPlainObject(totals, "totals");
  assertExactKeys(totals, ["total", "currency_code"], "totals");
  if (typeof totals.total !== "string" || !/^[1-9][0-9]{0,11}$/.test(totals.total)
      || !Number.isSafeInteger(Number(totals.total)) || !/^[A-Z]{3}$/.test(totals.currency_code ?? "")) {
    throw invalidPayload("The event totals are invalid.");
  }
  return { unitAmount: Number(totals.total), currency: totals.currency_code };
}

export class DurableProjectPaymentStore {
  constructor(filePath, options = {}) {
    this.filePath = resolve(filePath);
    this.instanceId = processBootInstanceId;
    this.evidenceScope = options.evidenceScope ?? null;
    if (this.evidenceScope !== null && !verifierDigestPattern.test(this.evidenceScope)) {
      throw new TypeError("The lifecycle evidence scope must be a SHA-256 digest.");
    }
    this.clock = options.clock ?? (() => new Date());
    this.leaseMilliseconds = options.leaseMilliseconds ?? 30_000;
    this.maximumAttempts = options.maximumAttempts ?? 5;
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const database = this.#open();
    try {
      database.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        CREATE TABLE IF NOT EXISTS project_payment_webhook_event (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          destination_key TEXT NOT NULL,
          provider_event_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          occurred_at TEXT NOT NULL,
          received_at TEXT NOT NULL,
          received_instance_id TEXT NOT NULL,
          body_sha256 TEXT NOT NULL,
          normalized_payload TEXT NOT NULL,
          attempt_count INTEGER NOT NULL DEFAULT 0,
          next_attempt_at TEXT NOT NULL,
          last_attempt_at TEXT NULL,
          lease_id TEXT NULL,
          lease_expires_at TEXT NULL,
          processed_at TEXT NULL,
          processed_instance_id TEXT NULL,
          dead_lettered_at TEXT NULL,
          last_error_code TEXT NULL,
          ignored_as_stale INTEGER NOT NULL DEFAULT 0,
          arrived_out_of_order INTEGER NOT NULL DEFAULT 0,
          UNIQUE (destination_key, provider_event_id)
        );
        CREATE INDEX IF NOT EXISTS ix_project_payment_webhook_event_due
          ON project_payment_webhook_event (next_attempt_at, sequence)
          WHERE processed_at IS NULL AND dead_lettered_at IS NULL;
        CREATE TABLE IF NOT EXISTS project_payment_entitlement_source (
          subject_key TEXT NOT NULL,
          grant_key TEXT NOT NULL,
          source_key TEXT NOT NULL,
          quantity INTEGER NOT NULL CHECK (quantity > 0),
          status TEXT NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
          effective_from TEXT NOT NULL,
          effective_until TEXT NULL,
          period_starts_at TEXT NULL,
          period_ends_at TEXT NULL,
          source_price_key TEXT NOT NULL,
          source_event_id TEXT NOT NULL,
          last_occurred_at TEXT NOT NULL,
          latest_transaction_id TEXT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (subject_key, grant_key, source_key),
          UNIQUE (grant_key, source_key)
        );
        CREATE INDEX IF NOT EXISTS ix_project_payment_entitlement_source_active
          ON project_payment_entitlement_source (subject_key, grant_key, effective_until)
          WHERE status IN ('active', 'scheduled_cancel');
        CREATE TABLE IF NOT EXISTS project_payment_entitlement (
          subject_key TEXT NOT NULL,
          grant_key TEXT NOT NULL,
          quantity INTEGER NOT NULL CHECK (quantity >= 0),
          status TEXT NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
          effective_from TEXT NOT NULL,
          effective_until TEXT NULL,
          period_starts_at TEXT NULL,
          period_ends_at TEXT NULL,
          source_price_key TEXT NOT NULL,
          source_event_id TEXT NOT NULL,
          last_occurred_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (subject_key, grant_key)
        );
        CREATE TABLE IF NOT EXISTS project_payment_evidence (
          name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS project_payment_ordering_clock (
          ordering_key TEXT PRIMARY KEY,
          occurred_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_payment_projection (
          namespace TEXT NOT NULL,
          projection_key TEXT NOT NULL,
          value_json TEXT NOT NULL,
          PRIMARY KEY (namespace, projection_key)
        );
      `);
      const inboxColumns = new Set(
        database.prepare("PRAGMA table_info(project_payment_webhook_event)").all().map(column => column.name)
      );
      if (!inboxColumns.has("processed_instance_id")) {
        database.exec("ALTER TABLE project_payment_webhook_event ADD COLUMN processed_instance_id TEXT NULL;");
      }
      const sourceColumns = new Set(
        database.prepare("PRAGMA table_info(project_payment_entitlement_source)").all().map(column => column.name)
      );
      if (!sourceColumns.has("latest_transaction_id")) {
        database.exec("ALTER TABLE project_payment_entitlement_source ADD COLUMN latest_transaction_id TEXT NULL;");
      }
      const legacySourceTable = database.prepare(`
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'project_payment_entitlement_cache'
      `).get();
      if (legacySourceTable) {
        database.exec(`
          INSERT OR IGNORE INTO project_payment_entitlement_source (
            subject_key, grant_key, source_key, quantity, status, effective_from,
            effective_until, period_starts_at, period_ends_at, source_price_key,
            source_event_id, last_occurred_at, latest_transaction_id, updated_at
          )
          SELECT subject_key, grant_key, source_key, quantity, status, effective_from,
            effective_until, period_starts_at, period_ends_at, source_price_key,
            source_event_id, last_occurred_at,
            CASE WHEN source_key LIKE 'transaction:%' THEN substr(source_key, 13) ELSE NULL END,
            updated_at
          FROM project_payment_entitlement_cache;
        `);
      }
    } finally {
      database.close();
    }
    chmodSync(this.filePath, 0o600);
  }

  async insertVerifiedEvent({ destinationKey, bodySha256, normalized }) {
    if (typeof destinationKey !== "string" || !idPatterns.environment.test(destinationKey)) {
      throw new ProjectPaymentError("WEBHOOK_DESTINATION_INVALID", "The webhook destination is invalid.");
    }
    if (!/^[0-9a-f]{64}$/.test(bodySha256)) throw invalidPayload("The body digest is invalid.");
    return this.#transaction(database => {
      const key = `${destinationKey}:${normalized.eventId}`;
      const existing = database.prepare(`
        SELECT body_sha256 FROM project_payment_webhook_event
        WHERE destination_key = ? AND provider_event_id = ?
      `).get(destinationKey, normalized.eventId);
      if (existing) {
        if (existing.body_sha256 !== bodySha256) {
          throw new ProjectPaymentError("WEBHOOK_EVENT_COLLISION", "The provider event identifier was reused with different content.");
        }
        insertEvidence(database, "duplicate-delivery");
        return { inserted: false, key };
      }
      const receivedAt = this.clock().toISOString();
      const previousClock = database.prepare(`
        SELECT occurred_at FROM project_payment_ordering_clock WHERE ordering_key = ?
      `).get(normalized.orderingKey)?.occurred_at;
      const arrivedOutOfOrder = previousClock !== undefined
        && Date.parse(normalized.occurredAt) < Date.parse(previousClock);
      if (previousClock === undefined || Date.parse(normalized.occurredAt) > Date.parse(previousClock)) {
        database.prepare(`
          INSERT INTO project_payment_ordering_clock (ordering_key, occurred_at) VALUES (?, ?)
          ON CONFLICT(ordering_key) DO UPDATE SET occurred_at = excluded.occurred_at
        `).run(normalized.orderingKey, normalized.occurredAt);
      }
      database.prepare(`
        INSERT INTO project_payment_webhook_event (
          destination_key, provider_event_id, event_type, occurred_at, received_at,
          received_instance_id, body_sha256, normalized_payload, next_attempt_at,
          arrived_out_of_order
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        destinationKey,
        normalized.eventId,
        normalized.eventType,
        normalized.occurredAt,
        receivedAt,
        this.instanceId,
        bodySha256,
        JSON.stringify(normalized),
        receivedAt,
        arrivedOutOfOrder ? 1 : 0
      );
      return { inserted: true, key };
    });
  }

  async recordEvidence(name) {
    if (!requiredLifecycleEvidence.includes(name)) {
      throw new ProjectPaymentError("EVIDENCE_INVALID", "The lifecycle evidence name is not recognized.");
    }
    return this.#transaction(database => insertEvidence(database, name));
  }

  async stageRestartReplayProbe(destinationKey, now = this.clock()) {
    if (!idPatterns.environment.test(destinationKey ?? "")) {
      throw new ProjectPaymentError("RESTART_REPLAY_INVALID", "The restart replay destination is invalid.");
    }
    if (!verifierDigestPattern.test(this.evidenceScope ?? "")) {
      throw new ProjectPaymentError("RESTART_REPLAY_INVALID", "Restart replay requires an exact runtime evidence scope.");
    }
    const stagedAt = toIso(now);
    return this.#transaction(database => {
      const alreadyPassed = database.prepare(`
        SELECT 1 FROM project_payment_evidence WHERE name = 'restart-replay'
      `).get();
      if (alreadyPassed) return { action: "restart-replay", state: "already-passed" };

      const probeId = stableId("vn_restart_probe", destinationKey, this.evidenceScope);
      const normalized = {
        kind: "restart_replay_probe",
        probeId,
        environmentId: destinationKey,
        evidenceScope: this.evidenceScope,
        orderingKey: `probe:${this.evidenceScope}`
      };
      database.prepare(`
        INSERT OR IGNORE INTO project_payment_webhook_event (
          destination_key, provider_event_id, event_type, occurred_at, received_at,
          received_instance_id, body_sha256, normalized_payload, next_attempt_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        destinationKey,
        probeId,
        restartReplayProbeEventType,
        stagedAt,
        stagedAt,
        this.instanceId,
        createHash("sha256")
          .update(`restart-replay\0${destinationKey}\0${this.evidenceScope}`, "utf8")
          .digest("hex"),
        JSON.stringify(normalized),
        stagedAt
      );
      return { action: "restart-replay", state: "staged" };
    });
  }

  async claimNextDue(now = this.clock()) {
    const nowIso = toIso(now);
    return this.#transaction(database => {
      const due = database.prepare(`
        SELECT sequence FROM project_payment_webhook_event
        WHERE processed_at IS NULL
          AND dead_lettered_at IS NULL
          AND next_attempt_at <= ?
          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
          AND (event_type <> ? OR received_instance_id <> ?)
        ORDER BY sequence
        LIMIT 1
      `).get(nowIso, nowIso, restartReplayProbeEventType, this.instanceId);
      if (!due) return null;
      const leaseId = randomUUID();
      const leaseExpiresAt = new Date(Date.parse(nowIso) + this.leaseMilliseconds).toISOString();
      const result = database.prepare(`
        UPDATE project_payment_webhook_event
        SET attempt_count = attempt_count + 1,
            last_attempt_at = ?, lease_id = ?, lease_expires_at = ?
        WHERE sequence = ?
          AND processed_at IS NULL
          AND dead_lettered_at IS NULL
          AND next_attempt_at <= ?
          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
          AND (event_type <> ? OR received_instance_id <> ?)
      `).run(
        nowIso,
        leaseId,
        leaseExpiresAt,
        due.sequence,
        nowIso,
        nowIso,
        restartReplayProbeEventType,
        this.instanceId
      );
      if (Number(result.changes) !== 1) return null;
      return eventFromRow(database.prepare(`
        SELECT * FROM project_payment_webhook_event WHERE sequence = ?
      `).get(due.sequence));
    });
  }

  async processDue(now = this.clock()) {
    const summary = { applied: 0, ignored: 0, failed: 0 };
    while (true) {
      const claimed = await this.claimNextDue(now);
      if (!claimed) return summary;
      try {
        const result = await this.#applyClaimed(claimed, now);
        if (result.ignored) summary.ignored++;
        else summary.applied++;
      } catch (error) {
        summary.failed++;
        await this.#failClaimed(claimed, error, now);
      }
    }
  }

  async getEntitlement(subjectKey, grantKey = trustedCatalog.entitlement, now = this.clock()) {
    assertBuyerKey(subjectKey);
    const state = await this.snapshot();
    const aggregate = state.entitlementAggregates[`${subjectKey}:${grantKey}`];
    if (!aggregate) return { active: false, status: null, effectiveUntil: null };
    const active = (aggregate.status === "active" || aggregate.status === "scheduled_cancel")
      && aggregate.quantity > 0
      && Date.parse(aggregate.effectiveFrom) <= toDate(now).getTime()
      && (aggregate.effectiveUntil === null || Date.parse(aggregate.effectiveUntil) > toDate(now).getTime());
    return {
      active,
      status: aggregate.status,
      effectiveUntil: aggregate.effectiveUntil
    };
  }

  async verificationStatus() {
    const state = await this.snapshot();
    const externalEvents = state.events.filter(event => event.destinationKey !== "internal");
    return Object.freeze({
      lifecyclePassed: requiredLifecycleEvidence.every(name => state.evidence.includes(name)),
      durableInbox: externalEvents.length > 0
        && externalEvents.every(event => event.processedAt !== null && event.deadLetteredAt === null),
      restartReplayPassed: state.evidence.includes("restart-replay"),
      evidence: [...state.evidence].sort(),
      pendingEvents: externalEvents.filter(event => event.processedAt === null && event.deadLetteredAt === null).length,
      deadLetteredEvents: externalEvents.filter(event => event.deadLetteredAt !== null).length
    });
  }

  async snapshot() {
    const database = this.#open();
    try {
      return readSnapshot(database);
    } finally {
      database.close();
    }
  }

  async #applyClaimed(claimed, now) {
    return this.#transaction(database => {
      const row = database.prepare(`
        SELECT * FROM project_payment_webhook_event WHERE sequence = ?
      `).get(claimed.sequence);
      const event = row ? eventFromRow(row) : null;
      if (!event || event.processedAt !== null || event.leaseId !== claimed.leaseId) {
        throw new ProjectPaymentError("INBOX_LEASE_LOST", "The inbox event lease is no longer owned.");
      }
      const restartReplayProbe = event.eventType === restartReplayProbeEventType;
      if (restartReplayProbe && (
        event.receivedInstanceId === this.instanceId
        || event.normalized?.kind !== "restart_replay_probe"
        || event.normalized?.environmentId !== event.destinationKey
        || !safeEqualFixedText(event.normalized?.evidenceScope, this.evidenceScope, verifierDigestPattern)
      )) {
        throw new ProjectPaymentError("RESTART_REPLAY_INVALID", "The restart replay probe is not bound to a different process and exact runtime scope.");
      }
      const state = readProjectionState(database);
      const result = applyNormalizedEvent(state, event);
      if (restartReplayProbe) addEvidence(state, "restart-replay");
      writeProjectionState(database, state);
      const update = database.prepare(`
        UPDATE project_payment_webhook_event
        SET ignored_as_stale = ?, processed_at = ?, processed_instance_id = ?, lease_id = NULL,
            lease_expires_at = NULL, last_error_code = NULL
        WHERE sequence = ? AND lease_id = ? AND processed_at IS NULL
      `).run(result.ignored ? 1 : 0, toIso(now), this.instanceId, event.sequence, claimed.leaseId);
      if (Number(update.changes) !== 1) {
        throw new ProjectPaymentError("INBOX_LEASE_LOST", "The inbox event lease changed before commit.");
      }
      return result;
    });
  }

  async #failClaimed(claimed, error, now) {
    return this.#transaction(database => {
      const row = database.prepare(`
        SELECT * FROM project_payment_webhook_event WHERE sequence = ?
      `).get(claimed.sequence);
      const event = row ? eventFromRow(row) : null;
      if (!event || event.processedAt !== null || event.leaseId !== claimed.leaseId) return false;
      const lastErrorCode = error instanceof ProjectPaymentError ? error.code : "PROCESSING_FAILED";
      const deadLetteredAt = event.attemptCount >= this.maximumAttempts ? toIso(now) : null;
      const delay = Math.min(60_000, 250 * 2 ** Math.max(0, event.attemptCount - 1));
      const nextAttemptAt = deadLetteredAt === null
        ? new Date(toDate(now).getTime() + delay).toISOString()
        : event.nextAttemptAt;
      database.prepare(`
        UPDATE project_payment_webhook_event
        SET lease_id = NULL, lease_expires_at = NULL, last_error_code = ?,
            dead_lettered_at = ?, next_attempt_at = ?
        WHERE sequence = ? AND lease_id = ? AND processed_at IS NULL
      `).run(lastErrorCode, deadLetteredAt, nextAttemptAt, event.sequence, claimed.leaseId);
      return true;
    });
  }

  #open() {
    const database = new DatabaseSync(this.filePath);
    database.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
    return database;
  }

  #transaction(work) {
    const database = this.#open();
    database.exec("BEGIN IMMEDIATE");
    try {
      const result = work(database);
      database.exec("COMMIT");
      return result;
    } catch (error) {
      try { database.exec("ROLLBACK"); } catch { /* Preserve the original transaction failure. */ }
      throw error;
    } finally {
      database.close();
    }
  }
}

function eventFromRow(row) {
  return {
    key: `${row.destination_key}:${row.provider_event_id}`,
    destinationKey: row.destination_key,
    providerEventId: row.provider_event_id,
    eventType: row.event_type,
    occurredAt: row.occurred_at,
    receivedAt: row.received_at,
    receivedInstanceId: row.received_instance_id,
    sequence: Number(row.sequence),
    bodySha256: row.body_sha256,
    normalized: JSON.parse(row.normalized_payload),
    attemptCount: Number(row.attempt_count),
    nextAttemptAt: row.next_attempt_at,
    lastAttemptAt: row.last_attempt_at,
    leaseId: row.lease_id,
    leaseExpiresAt: row.lease_expires_at,
    processedAt: row.processed_at,
    processedInstanceId: row.processed_instance_id,
    deadLetteredAt: row.dead_lettered_at,
    lastErrorCode: row.last_error_code,
    ignoredAsStale: row.ignored_as_stale === 1,
    arrivedOutOfOrder: row.arrived_out_of_order === 1
  };
}

function readSnapshot(database) {
  const state = readProjectionState(database);
  state.events = database.prepare(`
    SELECT * FROM project_payment_webhook_event ORDER BY sequence
  `).all().map(eventFromRow);
  state.nextSequence = (state.events.at(-1)?.sequence ?? 0) + 1;
  return state;
}

function readProjectionState(database) {
  const state = normalizeState({});
  for (const row of database.prepare(`SELECT * FROM project_payment_entitlement_source`).all()) {
    const key = `${row.subject_key}:${row.grant_key}:${row.source_key}`;
    state.entitlements[key] = {
      subjectKey: row.subject_key,
      grantKey: row.grant_key,
      sourceKey: row.source_key,
      quantity: Number(row.quantity),
      status: row.status,
      effectiveFrom: row.effective_from,
      effectiveUntil: row.effective_until,
      periodStartsAt: row.period_starts_at,
      periodEndsAt: row.period_ends_at,
      sourcePriceKey: row.source_price_key,
      sourceEventId: row.source_event_id,
      lastOccurredAt: row.last_occurred_at,
      latestTransactionId: row.latest_transaction_id,
      updatedAt: row.updated_at
    };
  }
  for (const row of database.prepare(`SELECT * FROM project_payment_entitlement`).all()) {
    const key = `${row.subject_key}:${row.grant_key}`;
    state.entitlementAggregates[key] = {
      subjectKey: row.subject_key,
      grantKey: row.grant_key,
      quantity: Number(row.quantity),
      status: row.status,
      effectiveFrom: row.effective_from,
      effectiveUntil: row.effective_until,
      periodStartsAt: row.period_starts_at,
      periodEndsAt: row.period_ends_at,
      sourcePriceKey: row.source_price_key,
      sourceEventId: row.source_event_id,
      lastOccurredAt: row.last_occurred_at,
      updatedAt: row.updated_at
    };
  }
  if (Object.keys(state.entitlementAggregates).length === 0 && Object.keys(state.entitlements).length > 0) {
    const aggregateKeys = new Set(
      Object.values(state.entitlements).map(row => `${row.subjectKey}\0${row.grantKey}`)
    );
    for (const composite of aggregateKeys) {
      const [subjectKey, grantKey] = composite.split("\0");
      rebuildEntitlementAggregate(state, subjectKey, grantKey);
    }
  }
  state.evidence = database.prepare(`SELECT name FROM project_payment_evidence ORDER BY name`).all().map(row => row.name);
  for (const row of database.prepare(`SELECT ordering_key, occurred_at FROM project_payment_ordering_clock`).all()) {
    state.observedClocks[row.ordering_key] = row.occurred_at;
  }
  const namespaces = {
    catalogMappings: state.catalogMappings,
    transactions: state.transactions,
    declinedTransactions: state.declinedTransactions,
    subscriptions: state.subscriptions,
    refundedTransactions: state.refundedTransactions
  };
  for (const row of database.prepare(`SELECT namespace, projection_key, value_json FROM project_payment_projection`).all()) {
    if (namespaces[row.namespace]) namespaces[row.namespace][row.projection_key] = JSON.parse(row.value_json);
  }
  return state;
}

function writeProjectionState(database, state) {
  database.exec("DELETE FROM project_payment_entitlement_source; DELETE FROM project_payment_entitlement; DELETE FROM project_payment_evidence; DELETE FROM project_payment_projection;");
  const entitlementStatement = database.prepare(`
    INSERT INTO project_payment_entitlement_source (
      subject_key, grant_key, source_key, quantity, status, effective_from,
      effective_until, period_starts_at, period_ends_at, source_price_key,
      source_event_id, last_occurred_at, latest_transaction_id, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const entitlement of Object.values(state.entitlements)) {
    entitlementStatement.run(
      entitlement.subjectKey,
      entitlement.grantKey,
      entitlement.sourceKey,
      entitlement.quantity,
      entitlement.status,
      entitlement.effectiveFrom,
      entitlement.effectiveUntil,
      entitlement.periodStartsAt,
      entitlement.periodEndsAt,
      entitlement.sourcePriceKey,
      entitlement.sourceEventId,
      entitlement.lastOccurredAt,
      entitlement.latestTransactionId,
      entitlement.updatedAt
    );
  }
  const aggregateStatement = database.prepare(`
    INSERT INTO project_payment_entitlement (
      subject_key, grant_key, quantity, status, effective_from, effective_until,
      period_starts_at, period_ends_at, source_price_key, source_event_id,
      last_occurred_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const aggregate of Object.values(state.entitlementAggregates)) {
    aggregateStatement.run(
      aggregate.subjectKey,
      aggregate.grantKey,
      aggregate.quantity,
      aggregate.status,
      aggregate.effectiveFrom,
      aggregate.effectiveUntil,
      aggregate.periodStartsAt,
      aggregate.periodEndsAt,
      aggregate.sourcePriceKey,
      aggregate.sourceEventId,
      aggregate.lastOccurredAt,
      aggregate.updatedAt
    );
  }
  for (const name of state.evidence) insertEvidence(database, name);
  const projectionStatement = database.prepare(`
    INSERT INTO project_payment_projection (namespace, projection_key, value_json) VALUES (?, ?, ?)
  `);
  for (const namespace of ["catalogMappings", "transactions", "declinedTransactions", "subscriptions", "refundedTransactions"]) {
    for (const [key, value] of Object.entries(state[namespace])) {
      projectionStatement.run(namespace, key, JSON.stringify(value));
    }
  }
}

function insertEvidence(database, name) {
  database.prepare(`INSERT OR IGNORE INTO project_payment_evidence (name) VALUES (?)`).run(name);
  return true;
}

export async function buildVerifierPayload({
  provider,
  paymentsEnabled,
  verifierEnabled,
  suppliedSecret,
  configuredSecret,
  expectedCommit,
  builtCommit,
  expectedManifestDigest,
  installedManifestDigest,
  environmentId,
  store
}) {
  if (provider !== providerModes.simulator || paymentsEnabled !== true || verifierEnabled !== true) return null;
  if (!safeEqualSecret(suppliedSecret, configuredSecret)) return null;
  if (!safeEqualFixedText(expectedCommit, builtCommit, verifierCommitPattern)) return null;
  if (!safeEqualFixedText(expectedManifestDigest, installedManifestDigest, verifierDigestPattern)) return null;
  let expectedScope;
  try {
    expectedScope = computeRuntimeEvidenceScope(environmentId, installedManifestDigest, builtCommit);
  } catch {
    return null;
  }
  if (!safeEqualFixedText(store?.evidenceScope, expectedScope, verifierDigestPattern)) return null;
  const status = await store.verificationStatus();
  if (!status.lifecyclePassed || !status.durableInbox || !status.restartReplayPassed) return null;
  return Object.freeze({
    provider: providerModes.simulator,
    paymentsEnabled: true,
    verifierEnabled: true,
    commitSha: builtCommit,
    manifestDigest: installedManifestDigest,
    lifecyclePassed: true,
    durableInbox: true,
    restartReplayPassed: true
  });
}

export function isSimulatorHarnessAuthorized({
  provider,
  paymentsEnabled,
  verifierEnabled,
  suppliedSecret,
  configuredSecret,
  expectedCommit,
  builtCommit,
  expectedManifestDigest,
  installedManifestDigest
}) {
  return provider === providerModes.simulator
    && paymentsEnabled === true
    && verifierEnabled === true
    && safeEqualSecret(suppliedSecret, configuredSecret)
    && safeEqualFixedText(expectedCommit, builtCommit, verifierCommitPattern)
    && safeEqualFixedText(expectedManifestDigest, installedManifestDigest, verifierDigestPattern);
}

export function verifySimulatorSecret(suppliedSecret, configuredSecret) {
  return safeEqualSecret(suppliedSecret, configuredSecret);
}

export function simulatorSessionId(buyerKey, priceKey) {
  assertBuyerKey(buyerKey);
  assertTrustedPriceKey(priceKey);
  return stableId("session", buyerKey, priceKey);
}

export function startInboxWorker(store, options = {}) {
  const intervalMilliseconds = options.intervalMilliseconds ?? 500;
  let stopped = false;
  let running = false;
  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try { await store.processDue(); }
    catch { /* The durable row remains due or leased for retry; never log payloads. */ }
    finally { running = false; }
  };
  const timer = setInterval(tick, intervalMilliseconds);
  timer.unref();
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

function applyNormalizedEvent(state, event) {
  const normalized = event.normalized;
  if (normalized.kind === "restart_replay_probe") return { ignored: false };
  if (normalized.providerPriceId) persistCatalogMapping(state, normalized);
  if (normalized.subscriptionId) validateSubscriptionIdentity(state, normalized);
  if (normalized.kind === "transaction_completed") validateTransactionIdentity(state, normalized);
  const terminalRefundFence = validateTerminalRefundFence(state, event);
  if (terminalRefundFence === "stale") {
    addEvidence(state, "out-of-order-delivery");
    return { ignored: true };
  }

  switch (normalized.kind) {
    case "transaction_completed":
      {
        const existingTransaction = state.transactions[normalized.transactionId];
        if (existingTransaction) return { ignored: true };
        validateRecurringTransactionPeriod(state, normalized);
        state.transactions[normalized.transactionId] = {
          transactionId: normalized.transactionId,
          environmentId: normalized.environmentId,
          subjectKey: normalized.subjectKey,
          subscriptionId: normalized.subscriptionId,
          providerProductId: normalized.providerProductId,
          providerPriceId: normalized.providerPriceId,
          productKey: normalized.productKey,
          priceKey: normalized.priceKey,
          priceType: normalized.type,
          unitAmount: normalized.unitAmount,
          currency: normalized.currency,
          grants: normalized.grants,
          sourceKey: sourceKeyFor(normalized),
          periodStartsAt: normalized.periodStartsAt,
          periodEndsAt: normalized.periodEndsAt,
          occurredAt: event.occurredAt,
          sourceEventId: event.providerEventId
        };
        const result = upsertEntitlement(
          state,
          event,
          "active",
          normalized.periodEndsAt
        );
        linkTransactionToSource(state, normalized);
        if (!result.ignored && normalized.subscriptionId !== null) persistSubscription(state, event, "active");
        addEvidence(state, normalized.type === "one_time" ? "one-time-purchase" : "subscription-purchase");
        return result;
      }
    case "transaction_declined":
      state.declinedTransactions[normalized.transactionId] = {
        subjectKey: normalized.subjectKey,
        retryPath: trustedCatalog.cancelPath,
        occurredAt: event.occurredAt
      };
      addEvidence(state, "declined-checkout");
      return { ignored: false };
    case "subscription_created":
      {
        const result = upsertEntitlement(state, event, "active", normalized.periodEndsAt);
        if (!result.ignored) {
          persistSubscription(state, event, "active");
          addEvidence(state, "subscription-purchase");
        }
        return result;
      }
    case "subscription_renewed":
      {
        validateRenewalAdvance(state, event);
        const result = upsertEntitlement(state, event, "active", normalized.periodEndsAt);
        if (!result.ignored) {
          persistSubscription(state, event, "active");
          addEvidence(state, "renewal");
        }
        return result;
      }
    case "subscription_scheduled_cancel":
      {
        requireSourceEntitlements(state, event.normalized);
        const result = upsertEntitlement(state, event, "scheduled_cancel", normalized.periodEndsAt);
        if (!result.ignored) {
          persistSubscription(state, event, "scheduled_cancel");
          addEvidence(state, "scheduled-cancellation");
        }
        return result;
      }
    case "subscription_canceled":
      {
        requireSourceEntitlements(state, event.normalized);
        const cancellation = validateCancellationProjection(state, event);
        if (cancellation.ignored) {
          addEvidence(state, "out-of-order-delivery");
          recordImmediateRefundIfComplete(state, normalized.subscriptionId);
          return { ignored: true };
        }
        const result = upsertEntitlementForSubject(
          state,
          normalized.subjectKey,
          event,
          "revoked",
          event.occurredAt,
          normalized.grants,
          normalized.priceKey,
          sourceKeyFor(normalized),
          cancellation.periodStartsAt,
          cancellation.periodEndsAt,
          { terminal: true, forceTerminal: true }
        );
        const linkedRefund = findSubscriptionRefund(state, normalized.subscriptionId);
        if (!result.ignored || linkedRefund) {
          persistSubscription(
            state,
            event,
            "revoked",
            cancellation.periodStartsAt,
            cancellation.periodEndsAt
          );
          recordImmediateRefundIfComplete(state, normalized.subscriptionId);
          return { ignored: false };
        }
        return result;
      }
    case "refund_pending":
      validateRefundTransaction(state, normalized);
      return { ignored: false };
    case "refund_approved":
      {
        const transaction = validateRefundTransaction(state, normalized);
        if (Date.parse(event.occurredAt) < Date.parse(transaction.occurredAt)) {
          throw new ProjectPaymentError("REFUND_PRECEDES_TRANSACTION", "The refund predates its trusted transaction projection.");
        }
        const existingRefund = state.refundedTransactions[normalized.transactionId];
        if (existingRefund) {
          validateRefundProjectionIdentity(existingRefund, transaction);
          if (Date.parse(event.occurredAt) <= Date.parse(existingRefund.approvedAt)) {
            addEvidence(state, "out-of-order-delivery");
          }
          return { ignored: true };
        }
        const refundProjection = {
          transactionId: normalized.transactionId,
          subscriptionId: transaction.subscriptionId,
          environmentId: transaction.environmentId,
          subjectKey: transaction.subjectKey,
          providerProductId: transaction.providerProductId,
          providerPriceId: transaction.providerPriceId,
          productKey: transaction.productKey,
          priceKey: transaction.priceKey,
          priceType: transaction.priceType,
          unitAmount: transaction.unitAmount,
          currency: transaction.currency,
          grants: transaction.grants,
          sourceKey: transaction.sourceKey,
          approvedAt: event.occurredAt,
          sourceEventId: event.providerEventId
        };
        state.refundedTransactions[normalized.transactionId] = refundProjection;
        upsertEntitlementForSubject(
          state,
          transaction.subjectKey,
          event,
          "revoked",
          event.occurredAt,
          transaction.grants,
          transaction.priceKey,
          transaction.sourceKey,
          transaction.periodStartsAt,
          transaction.periodEndsAt,
          { terminal: true, forceTerminal: true }
        );
        recordImmediateRefundIfComplete(state, transaction.subscriptionId);
        return { ignored: false };
      }
    case "portal_created":
      addEvidence(state, "customer-portal");
      return { ignored: false };
    default:
      throw new ProjectPaymentError("EVENT_EFFECT_UNRECOGNIZED", "The normalized event effect is not recognized.");
  }
}

function upsertEntitlement(state, event, status, effectiveUntil, options = {}) {
  return upsertEntitlementForSubject(
    state,
    event.normalized.subjectKey,
    event,
    status,
    effectiveUntil,
    event.normalized.grants,
    event.normalized.priceKey,
    sourceKeyFor(event.normalized),
    event.normalized.periodStartsAt,
    event.normalized.periodEndsAt,
    options
  );
}

function upsertEntitlementForSubject(
  state,
  subjectKey,
  event,
  status,
  effectiveUntil,
  grants,
  sourcePriceKey,
  sourceKey,
  periodStartsAt,
  periodEndsAt,
  options = {}
) {
  if (!Array.isArray(grants) || grants.length === 0) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The trusted event has no entitlement grants.");
  }
  if (typeof sourceKey !== "string" || sourceKey.length > 200) {
    throw new ProjectPaymentError("WEBHOOK_PAYLOAD_INVALID", "The entitlement source is invalid.");
  }
  const currentRows = grants.map(grant => state.entitlements[`${subjectKey}:${grant.entitlement}:${sourceKey}`]).filter(Boolean);
  if (options.forceTerminal === true && currentRows.length === grants.length
      && currentRows.every(current => current.status === "revoked")) {
    return { ignored: true };
  }
  const stale = currentRows.some(current => eventIsOlder(current, event, periodStartsAt, periodEndsAt, options));
  if (stale) {
    addEvidence(state, "out-of-order-delivery");
    return { ignored: true };
  }
  if (currentRows.some(current => current.status === "revoked" && status !== "revoked")) {
    throw new ProjectPaymentError("TERMINAL_STATE_REGRESSION", "A terminal entitlement source cannot be reactivated.");
  }
  for (const grant of grants) {
    const key = `${subjectKey}:${grant.entitlement}:${sourceKey}`;
    const current = state.entitlements[key];
    state.entitlements[key] = {
      subjectKey,
      grantKey: grant.entitlement,
      sourceKey,
      quantity: grant.quantity,
      status,
      effectiveFrom: current?.effectiveFrom ?? periodStartsAt ?? event.occurredAt,
      effectiveUntil,
      periodStartsAt,
      periodEndsAt,
      sourcePriceKey,
      sourceEventId: event.providerEventId,
      lastOccurredAt: event.occurredAt,
      latestTransactionId: event.normalized.kind === "transaction_completed"
        ? event.normalized.transactionId
        : current?.latestTransactionId ?? null,
      updatedAt: new Date().toISOString()
    };
    rebuildEntitlementAggregate(state, subjectKey, grant.entitlement);
  }
  return { ignored: false };
}

function linkTransactionToSource(state, normalized) {
  if (normalized.kind !== "transaction_completed") return false;
  let changed = false;
  for (const grant of normalized.grants) {
    const key = `${normalized.subjectKey}:${grant.entitlement}:${sourceKeyFor(normalized)}`;
    const source = state.entitlements[key];
    if (!source || source.periodStartsAt !== normalized.periodStartsAt
        || source.periodEndsAt !== normalized.periodEndsAt) continue;
    const previous = source.latestTransactionId
      ? state.transactions[source.latestTransactionId]
      : null;
    if (previous && (Date.parse(previous.periodEndsAt ?? previous.occurredAt) > Date.parse(normalized.periodEndsAt ?? normalized.occurredAt)
        || (previous.periodEndsAt === normalized.periodEndsAt
          && Date.parse(previous.occurredAt) > Date.parse(normalized.occurredAt)))) continue;
    source.latestTransactionId = normalized.transactionId;
    source.updatedAt = new Date().toISOString();
    rebuildEntitlementAggregate(state, normalized.subjectKey, grant.entitlement);
    changed = true;
  }
  return changed;
}

function rebuildEntitlementAggregate(state, subjectKey, grantKey) {
  const sources = Object.values(state.entitlements)
    .filter(row => row.subjectKey === subjectKey && row.grantKey === grantKey);
  if (sources.length === 0) {
    delete state.entitlementAggregates[`${subjectKey}:${grantKey}`];
    return null;
  }
  const available = sources.filter(row => row.status === "active" || row.status === "scheduled_cancel");
  const latest = [...sources].sort((left, right) =>
    Date.parse(right.lastOccurredAt) - Date.parse(left.lastOccurredAt)
    || right.sourceEventId.localeCompare(left.sourceEventId, "en"))[0];
  const status = available.some(row => row.status === "active")
    ? "active"
    : available.length > 0
      ? "scheduled_cancel"
      : "revoked";
  const activeQuantity = available.reduce((total, row) => total + row.quantity, 0);
  const effectiveFrom = available.length > 0
    ? new Date(Math.min(...available.map(row => Date.parse(row.effectiveFrom)))).toISOString()
    : latest.effectiveFrom;
  const effectiveUntil = available.length === 0
    ? latest.effectiveUntil
    : available.some(row => row.effectiveUntil === null)
      ? null
      : new Date(Math.max(...available.map(row => Date.parse(row.effectiveUntil)))).toISOString();
  const periodSource = [...(available.length > 0 ? available : sources)]
    .filter(row => row.periodEndsAt !== null)
    .sort((left, right) => Date.parse(right.periodEndsAt) - Date.parse(left.periodEndsAt))[0] ?? latest;
  const aggregate = {
    subjectKey,
    grantKey,
    quantity: activeQuantity,
    status,
    effectiveFrom,
    effectiveUntil,
    periodStartsAt: periodSource.periodStartsAt,
    periodEndsAt: periodSource.periodEndsAt,
    sourcePriceKey: latest.sourcePriceKey,
    sourceEventId: latest.sourceEventId,
    lastOccurredAt: latest.lastOccurredAt,
    updatedAt: latest.updatedAt
  };
  state.entitlementAggregates[`${subjectKey}:${grantKey}`] = aggregate;
  return aggregate;
}

function eventIsOlder(current, event, periodStartsAt, periodEndsAt, options) {
  if (options.forceTerminal === true) return false;
  const occurrenceIsOlder = Date.parse(event.occurredAt) < Date.parse(current.lastOccurredAt);
  if (occurrenceIsOlder) return true;
  if (options.terminal === true) return false;
  if (current.periodEndsAt !== null && periodEndsAt !== null) {
    const periodComparison = Date.parse(periodEndsAt) - Date.parse(current.periodEndsAt);
    if (periodComparison < 0) return true;
    if (periodComparison > 0) return false;
    const startComparison = Date.parse(periodStartsAt) - Date.parse(current.periodStartsAt);
    if (startComparison < 0) return true;
    if (startComparison > 0) return false;
  }
  return occurrenceIsOlder;
}

function persistCatalogMapping(state, normalized) {
  const incoming = {
    providerProductId: normalized.providerProductId,
    providerPriceId: normalized.providerPriceId,
    productKey: normalized.productKey,
    priceKey: normalized.priceKey,
    grants: normalized.grants
  };
  const existing = state.catalogMappings[normalized.providerPriceId];
  if (!existing) {
    state.catalogMappings[normalized.providerPriceId] = incoming;
    return;
  }
  if (JSON.stringify(existing) !== JSON.stringify(incoming)) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The signed event does not match the pinned simulator catalog mapping.");
  }
}

function validateRefundTransaction(state, normalized) {
  const transaction = state.transactions[normalized.transactionId];
  if (!transaction) {
    throw new ProjectPaymentError("REFUND_TRANSACTION_UNKNOWN", "The refund references an unknown transaction.");
  }
  if (transaction.environmentId !== normalized.environmentId
      || transaction.unitAmount !== normalized.unitAmount
      || transaction.currency !== normalized.currency) {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The refund totals do not match the trusted transaction.");
  }
  return transaction;
}

function validateRefundProjectionIdentity(refund, transaction) {
  if (refund.transactionId !== transaction.transactionId
      || refund.subscriptionId !== transaction.subscriptionId
      || refund.environmentId !== transaction.environmentId
      || refund.subjectKey !== transaction.subjectKey
      || refund.providerProductId !== transaction.providerProductId
      || refund.providerPriceId !== transaction.providerPriceId
      || refund.productKey !== transaction.productKey
      || refund.priceKey !== transaction.priceKey
      || refund.priceType !== transaction.priceType
      || refund.unitAmount !== transaction.unitAmount
      || refund.currency !== transaction.currency
      || refund.sourceKey !== transaction.sourceKey
      || JSON.stringify(refund.grants) !== JSON.stringify(transaction.grants)) {
    throw new ProjectPaymentError("REFUND_BINDING_COLLISION", "The refund binding differs from its trusted transaction projection.");
  }
}

function validateTerminalRefundFence(state, event) {
  const normalized = event.normalized;
  let refunds = [];
  if (normalized.kind === "transaction_completed") {
    const exact = state.refundedTransactions[normalized.transactionId];
    if (exact) refunds.push(exact);
    if (normalized.subscriptionId) {
      refunds = refunds.concat(findSubscriptionRefunds(state, normalized.subscriptionId));
    }
  } else if ([
    "subscription_created",
    "subscription_renewed",
    "subscription_scheduled_cancel"
  ].includes(normalized.kind)) {
    refunds = findSubscriptionRefunds(state, normalized.subscriptionId);
  } else {
    return null;
  }
  if (refunds.length === 0) return null;
  const approvedAt = refunds
    .map(refund => refund.approvedAt)
    .sort((left, right) => Date.parse(left) - Date.parse(right))[0];
  if (Date.parse(event.occurredAt) <= Date.parse(approvedAt)) return "stale";
  throw new ProjectPaymentError(
    "TERMINAL_REFUND_FENCE",
    "A refunded transaction or subscription source cannot be reactivated."
  );
}

function findSubscriptionRefunds(state, subscriptionId) {
  if (!subscriptionId) return [];
  return Object.values(state.refundedTransactions)
    .filter(refund => refund?.subscriptionId === subscriptionId);
}

function findSubscriptionRefund(state, subscriptionId) {
  return findSubscriptionRefunds(state, subscriptionId)
    .sort((left, right) => Date.parse(left.approvedAt) - Date.parse(right.approvedAt))[0] ?? null;
}

function validateCancellationProjection(state, event) {
  const normalized = event.normalized;
  const current = state.subscriptions[normalized.subscriptionId];
  if (!current) {
    throw new ProjectPaymentError("SUBSCRIPTION_STATE_MISSING", "The cancellation has no trusted subscription projection.");
  }
  const linkedRefund = findSubscriptionRefund(state, normalized.subscriptionId);
  if (current.periodStartsAt !== normalized.periodStartsAt
      || current.periodEndsAt !== normalized.periodEndsAt) {
    if (linkedRefund && Date.parse(normalized.periodEndsAt) <= Date.parse(current.periodEndsAt)) {
      return {
        ignored: false,
        periodStartsAt: current.periodStartsAt,
        periodEndsAt: current.periodEndsAt
      };
    }
    if (Date.parse(normalized.periodEndsAt) <= Date.parse(current.periodEndsAt)) return { ignored: true };
    throw new ProjectPaymentError("SUBSCRIPTION_PERIOD_INVALID", "The cancellation does not reuse the trusted subscription period.");
  }
  if (current.status === "revoked") return { ignored: true };
  if (current.status !== "active" && current.status !== "scheduled_cancel") {
    throw new ProjectPaymentError("SUBSCRIPTION_STATE_INVALID", "The cancellation requires an active subscription projection.");
  }
  return {
    ignored: false,
    periodStartsAt: current.periodStartsAt,
    periodEndsAt: current.periodEndsAt
  };
}

function recordImmediateRefundIfComplete(state, subscriptionId) {
  if (!subscriptionId) return false;
  const subscription = state.subscriptions[subscriptionId];
  const refund = findSubscriptionRefund(state, subscriptionId);
  if (subscription?.status !== "revoked" || !refund) return false;
  addEvidence(state, "immediate-refund");
  return true;
}

function validateSubscriptionIdentity(state, normalized) {
  const current = state.subscriptions[normalized.subscriptionId];
  if (!current) return true;
  if (current.environmentId !== normalized.environmentId
      || current.subjectKey !== normalized.subjectKey
      || current.providerProductId !== normalized.providerProductId
      || current.providerPriceId !== normalized.providerPriceId
      || current.productKey !== normalized.productKey
      || current.priceKey !== normalized.priceKey
      || JSON.stringify(current.grants) !== JSON.stringify(normalized.grants)) {
    throw new ProjectPaymentError("SUBSCRIPTION_ID_COLLISION", "The subscription identifier conflicts with its trusted buyer or catalog mapping.");
  }
  return true;
}

function validateTransactionIdentity(state, normalized) {
  const current = state.transactions[normalized.transactionId];
  if (!current) return true;
  if (current.environmentId !== normalized.environmentId
      || current.subjectKey !== normalized.subjectKey
      || current.subscriptionId !== normalized.subscriptionId
      || current.providerProductId !== normalized.providerProductId
      || current.providerPriceId !== normalized.providerPriceId
      || current.productKey !== normalized.productKey
      || current.priceKey !== normalized.priceKey
      || current.priceType !== normalized.type
      || current.unitAmount !== normalized.unitAmount
      || current.currency !== normalized.currency
      || current.sourceKey !== sourceKeyFor(normalized)
      || current.periodStartsAt !== normalized.periodStartsAt
      || current.periodEndsAt !== normalized.periodEndsAt
      || current.occurredAt !== normalized.occurredAt
      || JSON.stringify(current.grants) !== JSON.stringify(normalized.grants)) {
    throw new ProjectPaymentError("TRANSACTION_ID_COLLISION", "The transaction identifier conflicts with its trusted buyer or catalog mapping.");
  }
  return true;
}

function validateRenewalAdvance(state, event) {
  const rows = requireSourceEntitlements(state, event.normalized);
  if (rows.some(row => row.effectiveUntil === null || (row.status !== "active" && row.status !== "scheduled_cancel"))) {
    throw new ProjectPaymentError("RENEWAL_STATE_INVALID", "The renewal has no active finite period to advance.");
  }
  const currentEnds = new Set(rows.map(row => row.periodEndsAt));
  if (currentEnds.size !== 1 || !currentEnds.has(event.normalized.periodStartsAt)) {
    throw new ProjectPaymentError("RENEWAL_PERIOD_INVALID", "The signed renewal period does not advance the current period exactly once.");
  }
  return true;
}

function validateRecurringTransactionPeriod(state, normalized) {
  if (normalized.type !== "recurring") return true;
  const rows = sourceEntitlements(state, normalized);
  if (rows.length === 0) return true;
  if (rows.length !== normalized.grants.length
      || rows.some(row => row.periodStartsAt !== normalized.periodStartsAt
        || row.periodEndsAt !== normalized.periodEndsAt)) {
    throw new ProjectPaymentError("TRANSACTION_PERIOD_INVALID", "The recurring transaction period does not match the subscription state.");
  }
  return true;
}

function persistSubscription(
  state,
  event,
  status,
  periodStartsAt = event.normalized.periodStartsAt,
  periodEndsAt = event.normalized.periodEndsAt
) {
  const normalized = event.normalized;
  state.subscriptions[normalized.subscriptionId] = {
    environmentId: normalized.environmentId,
    subjectKey: normalized.subjectKey,
    providerProductId: normalized.providerProductId,
    providerPriceId: normalized.providerPriceId,
    productKey: normalized.productKey,
    priceKey: normalized.priceKey,
    grants: normalized.grants,
    sourceKey: sourceKeyFor(normalized),
    status,
    periodStartsAt,
    periodEndsAt,
    sourceEventId: event.providerEventId,
    lastOccurredAt: event.occurredAt
  };
}

function requireSourceEntitlements(state, normalized) {
  const rows = sourceEntitlements(state, normalized);
  if (rows.length !== normalized.grants.length) {
    throw new ProjectPaymentError("SUBSCRIPTION_STATE_MISSING", "The subscription has no prior entitlement state.");
  }
  return rows;
}

function sourceEntitlements(state, normalized) {
  const sourceKey = sourceKeyFor(normalized);
  return normalized.grants
    .map(grant => state.entitlements[`${normalized.subjectKey}:${grant.entitlement}:${sourceKey}`])
    .filter(Boolean);
}

function sourceKeyFor(normalized) {
  if (normalized.subscriptionId) return `subscription:${normalized.subscriptionId}`;
  if (normalized.transactionId) return `transaction:${normalized.transactionId}`;
  throw new ProjectPaymentError("WEBHOOK_PAYLOAD_INVALID", "The event has no entitlement source.");
}

function normalizeState(state) {
  return {
    version: 1,
    nextSequence: Number.isSafeInteger(state.nextSequence) ? state.nextSequence : 1,
    events: Array.isArray(state.events) ? state.events : [],
    entitlements: isObject(state.entitlements) ? state.entitlements : {},
    entitlementAggregates: isObject(state.entitlementAggregates) ? state.entitlementAggregates : {},
    evidence: Array.isArray(state.evidence) ? [...new Set(state.evidence.filter(name => requiredLifecycleEvidence.includes(name)))] : [],
    observedClocks: isObject(state.observedClocks) ? state.observedClocks : {},
    catalogMappings: isObject(state.catalogMappings) ? state.catalogMappings : {},
    transactions: isObject(state.transactions) ? state.transactions : {},
    declinedTransactions: isObject(state.declinedTransactions) ? state.declinedTransactions : {},
    subscriptions: isObject(state.subscriptions) ? state.subscriptions : {},
    refundedTransactions: isObject(state.refundedTransactions) ? state.refundedTransactions : {}
  };
}

function addEvidence(state, name) {
  if (!state.evidence.includes(name)) state.evidence.push(name);
  return true;
}

function safeEqualSecret(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  if (Buffer.byteLength(actual, "utf8") < 32 || Buffer.byteLength(expected, "utf8") < 32) return false;
  const actualDigest = createHash("sha256").update(actual, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(actualDigest, expectedDigest);
}

function safeEqualFixedText(actual, expected, pattern) {
  if (typeof actual !== "string" || typeof expected !== "string"
      || !pattern.test(actual) || !pattern.test(expected)) return false;
  const actualBytes = Buffer.from(actual, "ascii");
  const expectedBytes = Buffer.from(expected, "ascii");
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

function assertPlainObject(value, label) {
  if (!isObject(value) || Array.isArray(value)) throw invalidPayload(`${label} must be an object.`);
}

function assertExactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw invalidPayload(`${label} has an unexpected shape.`);
  }
}

function assertIdentifier(value, regex, label) {
  if (typeof value !== "string" || !regex.test(value)) throw invalidPayload(`${label} is invalid.`);
}

function assertBuyerKey(value) {
  if (typeof value !== "string" || !idPatterns.buyer.test(value)) {
    throw new ProjectPaymentError("BUYER_INVALID", "The authenticated buyer identifier is invalid.");
  }
}

function assertTrustedPriceKey(priceKey) {
  const catalog = declaredCatalogs.find(item => item.priceKey === priceKey);
  if (!catalog) {
    throw new ProjectPaymentError("PRICE_UNKNOWN", "The requested price is not in the trusted catalog.");
  }
  return catalog;
}

function parseDate(value, label) {
  if (typeof value !== "string" || value.length > 64 || !Number.isFinite(Date.parse(value))) {
    throw invalidPayload(`${label} is invalid.`);
  }
  return new Date(value).toISOString();
}

function addBillingInterval(value, interval) {
  const input = new Date(value);
  if (interval === "year") {
    const month = input.getUTCMonth();
    input.setUTCFullYear(input.getUTCFullYear() + 1);
    if (input.getUTCMonth() !== month) input.setUTCDate(0);
    return input.toISOString();
  }
  if (interval !== "month") {
    throw new ProjectPaymentError("WEBHOOK_CATALOG_MISMATCH", "The trusted recurring interval is unsupported.");
  }
  const day = input.getUTCDate();
  input.setUTCDate(1);
  input.setUTCMonth(input.getUTCMonth() + 1);
  const lastDay = new Date(Date.UTC(input.getUTCFullYear(), input.getUTCMonth() + 1, 0)).getUTCDate();
  input.setUTCDate(Math.min(day, lastDay));
  return input.toISOString();
}

function toDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("A valid timestamp is required.");
  return date;
}

function toIso(value) {
  return toDate(value).toISOString();
}

function asRawBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value, "utf8");
  throw new TypeError("rawBody must be a Buffer or string.");
}

function stableId(prefix, ...parts) {
  return `${prefix}_${createHash("sha256").update(parts.join(""), "utf8").digest("hex").slice(0, 24)}`;
}

function unavailablePaddle() {
  return new ProjectPaymentError("PADDLE_NOT_CONFIGURED", "The future Paddle adapter is not configured.");
}

function invalidPayload(message) {
  return new ProjectPaymentError("WEBHOOK_PAYLOAD_INVALID", message);
}

function isObject(value) {
  return value !== null && typeof value === "object";
}

function markUnique(values, value) {
  if (values.has(value)) return false;
  values.add(value);
  return true;
}
