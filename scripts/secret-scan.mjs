import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { scanProjectTree } from "../src/secret-scan.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, "..");
const result = await scanProjectTree(projectRoot);

if (!result.clean) {
  console.error(`Credential/secret scan failed: ${result.findings.length} finding(s).`);
  for (const finding of result.findings) console.error(`${finding.file}: ${finding.kind}`);
  process.exitCode = 1;
} else {
  console.log(`Credential/secret scan passed: ${result.scannedFiles} file(s), 0 findings.`);
}
