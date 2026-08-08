import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/server.mjs";

test("baseline app exposes a health-compatible root", async () => {
  const app = createApp();
  const server = app.listen(0);
  try {
    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/`);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Baseline application/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test("buyer identity is server-derived from existing middleware", async () => {
  const app = createApp();
  const server = app.listen(0);
  try {
    const address = server.address();
    const unauthenticated = await fetch(`http://127.0.0.1:${address.port}/api/me`);
    assert.equal(unauthenticated.status, 401);

    const authenticated = await fetch(`http://127.0.0.1:${address.port}/api/me`, {
      headers: { "X-QA-User-Id": "qa-buyer-01" }
    });
    assert.equal(authenticated.status, 200);
    assert.deepEqual(await authenticated.json(), { buyerId: "qa-buyer-01" });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
