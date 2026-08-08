import { DurableProjectPaymentStore } from "../src/project-payments.mjs";

const [storePath, evidenceScope] = process.argv.slice(2);
if (typeof storePath !== "string" || !/^[0-9a-f]{64}$/.test(evidenceScope ?? "")) {
  process.exitCode = 2;
} else {
  const store = new DurableProjectPaymentStore(storePath, { evidenceScope });
  const result = await store.processDue();
  const status = await store.verificationStatus();
  process.stdout.write(JSON.stringify({ result, status }));
}
