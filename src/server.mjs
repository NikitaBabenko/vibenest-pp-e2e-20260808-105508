import express from "express";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import {
  acceptSignedEvent,
  buildVerifierPayload,
  computeManifestDigest,
  createProjectPaymentProvider,
  DurableProjectPaymentStore,
  isSimulatorRuntime,
  oneTimeCatalog,
  ProjectPaymentError,
  providerModes,
  simulatorSessionId,
  startInboxWorker,
  trustedCatalog,
  validateSimulatorConfiguration,
  verifySimulatorSecret
} from "./project-payments.mjs";
import { sendLegalPage } from "./legal-pages.mjs";
import { scanProjectTree } from "./secret-scan.mjs";

const verifierPath = "/.well-known/vibenest/project-payments/verifier";
const harnessPath = "/.well-known/vibenest/project-payments/harness";

export function createApp(configuration = process.env, options = {}) {
  const runtimeCatalog = validateSimulatorConfiguration(configuration);
  const app = express();
  const projectRoot = resolve(options.projectRoot ?? process.cwd());
  const simulatorRuntime = isSimulatorRuntime(configuration);
  const storePath = resolveEvidenceScopedStorePath(
    resolve(projectRoot, configuration.PROJECT_PAYMENT_STORE_PATH ?? ".data/project-payments.sqlite"),
    simulatorRuntime
      ? {
          environmentId: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
          manifestDigest: configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST,
          builtCommit: resolveBuiltCommit(configuration)
        }
      : null
  );
  const store = new DurableProjectPaymentStore(storePath);
  const provider = createProjectPaymentProvider(configuration);
  const verifierRuntime = simulatorRuntime
    && configuration.VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED === "true";
  const webhookRateLimiter = createWebhookRateLimiter({
    maximumRequests: parsePositiveInteger(configuration.PROJECT_PAYMENT_WEBHOOK_RATE_LIMIT, 120),
    windowMilliseconds: parsePositiveInteger(configuration.PROJECT_PAYMENT_WEBHOOK_RATE_WINDOW_MS, 60_000)
  });
  const stopWorker = simulatorRuntime && options.startWorker !== false
    ? startInboxWorker(store, {
        intervalMilliseconds: parsePositiveInteger(configuration.PROJECT_PAYMENT_WORKER_INTERVAL_MS, 500)
      })
    : () => {};

  app.locals.projectPayments = { provider, store, storePath, stopWorker };

  if (configuration.VIBENEST_NOINDEX === "true") {
    app.use((_request, response, next) => {
      response.set("X-Robots-Tag", "noindex, nofollow");
      next();
    });
  }

  // This route must receive the exact bytes before any JSON parser is mounted.
  if (simulatorRuntime) {
    app.post(
      "/webhooks/project-payments",
      webhookRateLimiter,
      express.raw({ type: "application/json", limit: "128kb", inflate: false }),
      async (request, response) => {
        if (!Buffer.isBuffer(request.body)) return response.sendStatus(415);
        try {
          const result = await acceptSignedEvent({
            rawBody: request.body,
            signature: request.get("Paddle-Signature"),
            secret: configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET,
            nowSeconds: Math.floor(Date.now() / 1000),
            destinationKey: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
            environmentId: configuration.VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID,
            runtimeCatalog,
            store
          });
          // The durable SQLite transaction has committed before this acknowledgement.
          response.status(202).json({ accepted: true, duplicate: !result.inserted });
        } catch (error) {
          if (error instanceof ProjectPaymentError && error.code === "WEBHOOK_SIGNATURE_INVALID") {
            return response.sendStatus(401);
          }
          if (error instanceof ProjectPaymentError) return response.sendStatus(400);
          response.sendStatus(500);
        }
      }
    );
  }

  app.use(express.json({ limit: "32kb", strict: true }));
  app.use(express.urlencoded({ extended: false, limit: "8kb" }));

  app.get("/", (_request, response) => {
    response.type("html").send(`<!doctype html>
      <html lang="en">
        <head><meta charset="utf-8"><title>Project Payments QA</title></head>
        <body><main><h1>Project Payments QA</h1><p>Baseline application.</p>
        <nav><a href="/pricing">Pricing</a> · <a href="/terms">Terms</a> ·
        <a href="/privacy">Privacy</a> · <a href="/refund-policy">Refund policy</a></nav>
        </main></body>
      </html>`);
  });

  app.get("/api/me", requireQaBuyer, (request, response) => {
    response.json({ buyerId: request.buyerId });
  });

  app.get("/api/project-payments/prices", requireQaBuyer, async (request, response) => {
    try {
      const prices = await provider.previewPrices([trustedCatalog.priceKey, oneTimeCatalog.priceKey]);
      await store.recordEvidence("price-preview");
      response.json({ prices });
    } catch (error) {
      sendPaymentError(response, error);
    }
  });

  app.post("/api/project-payments/checkout", requireQaBuyer, async (request, response) => {
    if (!hasOnlyKeys(request.body, ["priceKey"])) return response.sendStatus(400);
    try {
      const checkout = await provider.createCheckout({
        buyerKey: request.buyerId,
        priceKey: request.body.priceKey,
        successUrl: trustedCatalog.successPath
      });
      response.status(201).json(checkout);
    } catch (error) {
      sendPaymentError(response, error);
    }
  });

  app.post("/api/project-payments/portal", requireQaBuyer, async (request, response) => {
    if (!hasOnlyKeys(request.body, [])) return response.sendStatus(400);
    try {
      const portal = await provider.createPortal(request.buyerId);
      await store.recordEvidence("customer-portal");
      response.status(201).json(portal);
    } catch (error) {
      sendPaymentError(response, error);
    }
  });

  app.post("/billing/checkout", requireQaBuyer, async (request, response) => {
    if (!hasOnlyKeys(request.body, ["priceKey"])) return response.sendStatus(400);
    try {
      const checkout = await provider.createCheckout({
        buyerKey: request.buyerId,
        priceKey: request.body.priceKey,
        successUrl: trustedCatalog.successPath
      });
      response.redirect(303, checkout.checkoutUrl);
    } catch (error) {
      sendPaymentError(response, error);
    }
  });

  app.get("/billing/simulator/:sessionId", requireQaBuyer, (request, response) => {
    const matches = [trustedCatalog.priceKey, "once"]
      .some(priceKey => simulatorSessionId(request.buyerId, priceKey) === request.params.sessionId);
    if (!matches) return response.sendStatus(404);
    response.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Simulator checkout</title></head><body><main><h1>Simulator checkout</h1><p>No charge is performed. Access changes only after a signed simulator event.</p><p><a href="${trustedCatalog.successPath}">Continue after success</a> · <a id="retry-checkout" href="${trustedCatalog.cancelPath}">Cancel or retry checkout</a></p></main></body></html>`);
  });

  app.get(`/api/project-payments/entitlements/${trustedCatalog.entitlement}`, requireQaBuyer, async (request, response) => {
    const entitlement = await store.getEntitlement(request.buyerId);
    response.json({ entitlement: trustedCatalog.entitlement, ...entitlement });
  });

  app.get("/api/team-exports", requireQaBuyer, async (request, response) => {
    const entitlement = await store.getEntitlement(request.buyerId);
    if (!entitlement.active) return response.sendStatus(403);
    response.json({ exports: [], authorizedBy: trustedCatalog.entitlement });
  });

  app.get("/pricing", async (_request, response) => {
    let prices = null;
    try { prices = await provider.previewPrices([trustedCatalog.priceKey, oneTimeCatalog.priceKey]); }
    catch { /* Disabled and future Paddle modes intentionally render no checkout control. */ }
    if (prices) await store.recordEvidence("price-preview");
    response.type("html").send(pricingPage(prices));
  });

  app.get("/billing/success", (_request, response) => {
    response.type("html").send("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Checkout result</title></head><body><main><h1>Checkout result pending</h1><p>Access is granted only after a signed payment event is durably processed.</p></main></body></html>");
  });

  for (const route of ["/terms", "/privacy", "/refund-policy"]) {
    app.get(route, (_request, response) => sendLegalPage(response, route));
  }

  if (verifierRuntime) {
    app.use(async (request, response, next) => {
      if (request.path !== verifierPath) return next();
      if (request.originalUrl !== verifierPath) return response.sendStatus(404);
      if (request.method !== "GET") return response.sendStatus(405);
      const configuredSecret = configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET;
      const computedDigest = computeManifestDigest();
      const configuredDigest = configuration.VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST;
      const installedManifestDigest = configuredDigest === computedDigest ? computedDigest : "";
      const payload = await buildVerifierPayload({
        provider: providerModes.simulator,
        paymentsEnabled: true,
        verifierEnabled: true,
        suppliedSecret: request.get("X-VibeNest-Simulator-Secret"),
        configuredSecret,
        expectedCommit: request.get("X-VibeNest-Expected-Commit"),
        builtCommit: resolveBuiltCommit(configuration),
        expectedManifestDigest: request.get("X-VibeNest-Expected-Manifest-Digest"),
        installedManifestDigest,
        store
      });
      if (!payload) return response.sendStatus(404);
      response.set("Cache-Control", "no-store").json(payload);
    });

    app.use(async (request, response, next) => {
      if (request.path !== harnessPath) return next();
      if (request.method !== "GET" && request.method !== "POST") return response.sendStatus(405);
      if (!verifySimulatorSecret(
        request.get("X-VibeNest-Simulator-Secret"),
        configuration.VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET
      )) return response.sendStatus(404);

      if (request.method === "GET") {
        const status = await store.verificationStatus();
        return response.set("Cache-Control", "no-store").json(status);
      }
      if (!hasOnlyKeys(request.body, ["action"]) || typeof request.body.action !== "string") {
        return response.sendStatus(400);
      }
      if (request.body.action === "process") {
        const restartedStore = new DurableProjectPaymentStore(storePath);
        const result = await restartedStore.processDue();
        const status = await restartedStore.verificationStatus();
        return response.json({ action: "process", ...result, pendingEvents: status.pendingEvents, deadLetteredEvents: status.deadLetteredEvents });
      }
      if (request.body.action === "restart-replay") {
        const result = await store.verifyRestartReplay();
        return response.json({ action: "restart-replay", ...result });
      }
      if (request.body.action === "secret-scan") {
        const scan = await scanProjectTree(projectRoot);
        if (!scan.clean) return response.status(422).json({ action: "secret-scan", passed: false, findings: scan.findings.length });
        await store.recordEvidence("secret-scan");
        return response.json({ action: "secret-scan", passed: true, scannedFiles: scan.scannedFiles });
      }
      response.sendStatus(400);
    });
  }

  app.use((error, _request, response, next) => {
    if (error?.type === "entity.too.large") return response.sendStatus(413);
    if (error?.type === "encoding.unsupported") return response.sendStatus(415);
    if (error instanceof SyntaxError && error?.status === 400) return response.sendStatus(400);
    next(error);
  });

  return app;
}

export function resolveEvidenceScopedStorePath(basePath, runtimeIdentity) {
  const resolvedBase = resolve(basePath);
  if (runtimeIdentity === null) return resolvedBase;
  const environmentId = runtimeIdentity?.environmentId ?? "";
  const manifestDigest = runtimeIdentity?.manifestDigest ?? "";
  const builtCommit = runtimeIdentity?.builtCommit ?? "";
  const scope = createHash("sha256")
    .update("vibenest-project-payments-evidence-v1\0", "utf8")
    .update(environmentId, "utf8")
    .update("\0", "utf8")
    .update(manifestDigest, "ascii")
    .update("\0", "utf8")
    .update(builtCommit, "ascii")
    .digest("hex");
  return `${resolvedBase}.${scope}`;
}

// Disposable simulator auth shim: the hosting QA boundary injects this header. All
// checkout, portal, entitlement and protected-operation routes consume request.buyerId
// from this middleware and never accept a buyer identifier from JSON or query data.
function requireQaBuyer(request, response, next) {
  const buyerId = request.get("X-QA-User-Id");
  if (typeof buyerId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(buyerId)) {
    return response.sendStatus(401);
  }
  request.buyerId = buyerId;
  next();
}

function sendPaymentError(response, error) {
  if (error instanceof ProjectPaymentError) {
    const status = error.code === "PAYMENTS_DISABLED" || error.code === "PADDLE_NOT_CONFIGURED" ? 503 : 400;
    return response.status(status).json({ code: error.code });
  }
  response.sendStatus(500);
}

function pricingPage(prices) {
  const offer = prices
    ? prices.map(price => {
        const catalog = price.priceKey === trustedCatalog.priceKey ? trustedCatalog : oneTimeCatalog;
        const cadence = catalog.type === "recurring" ? "per month" : "one time";
        return `<section><h2>${catalog.productName}</h2><p>${price.formatted} ${cadence}.</p><form method="post" action="/billing/checkout"><input type="hidden" name="priceKey" value="${catalog.priceKey}"><button type="submit">Start or retry checkout</button></form></section>`;
      }).join("")
    : "<p>Project payments are currently unavailable.</p>";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pricing</title></head><body><main><h1>Pricing</h1>${offer}</main></body></html>`;
}

function hasOnlyKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function resolveBuiltCommit(configuration) {
  if (Object.prototype.hasOwnProperty.call(configuration, "SOURCE_COMMIT")) {
    const sourceCommit = configuration.SOURCE_COMMIT?.trim() ?? "";
    return /^[0-9a-f]{40}$/i.test(sourceCommit) ? sourceCommit.toLowerCase() : "";
  }
  const legacy = configuration.VIBENEST_BUILD_COMMIT_SHA?.trim();
  return legacy && /^[0-9a-f]{40}$/i.test(legacy) ? legacy.toLowerCase() : "";
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function createWebhookRateLimiter({ maximumRequests, windowMilliseconds }) {
  const buckets = new Map();
  const maximumBuckets = 1_024;
  return (request, response, next) => {
    const now = Date.now();
    const key = request.ip ?? request.socket.remoteAddress ?? "unknown";
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      if (!bucket && buckets.size >= maximumBuckets) {
        const oldestKey = buckets.keys().next().value;
        if (oldestKey !== undefined) buckets.delete(oldestKey);
      }
      bucket = { count: 0, resetAt: now + windowMilliseconds };
      buckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > maximumRequests) {
      response.set("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000))));
      return response.sendStatus(429);
    }
    next();
  };
}

if (process.argv[1] && new URL(import.meta.url).pathname.endsWith(process.argv[1].replaceAll("\\", "/"))) {
  createApp().listen(Number.parseInt(process.env.PORT ?? "3000", 10));
}
