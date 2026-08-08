import { readdir, readFile, stat } from "node:fs/promises";
import { relative, resolve } from "node:path";

const excludedDirectories = new Set([".git", ".data", "node_modules"]);
const maximumFileBytes = 2 * 1024 * 1024;

const credentialPatterns = Object.freeze([
  pattern("VibeNest install code", "vnp" + "i_[A-Za-z0-9_-]{16,}"),
  pattern("VibeNest access token", "vnp" + "a_[A-Za-z0-9_-]{16,}"),
  pattern("VibeNest refresh token", "vnp" + "r_[A-Za-z0-9_-]{16,}"),
  pattern("Paddle credential", "pdl_" + "(?:live|sandbox)_[A-Za-z0-9_-]{20,}"),
  pattern("Stripe-style secret", "sk_" + "(?:live|test)_[A-Za-z0-9]{16,}"),
  pattern("GitHub token", "gh" + "(?:p|o|u|s|r)_[A-Za-z0-9]{20,}"),
  pattern("GitHub fine-grained token", "github_" + "pat_[A-Za-z0-9_]{20,}"),
  pattern("AWS access key", "AK" + "IA[0-9A-Z]{16}"),
  pattern("private key material", "-----BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
]);

export async function scanProjectTree(rootDirectory) {
  const root = resolve(rootDirectory);
  const files = [];
  await collectFiles(root, root, files);
  const findings = [];
  let scannedFiles = 0;

  for (const file of files) {
    const info = await stat(file);
    if (!info.isFile() || info.size > maximumFileBytes) continue;
    const bytes = await readFile(file);
    if (bytes.includes(0)) continue;
    const text = bytes.toString("utf8");
    scannedFiles++;
    for (const entry of credentialPatterns) {
      entry.regex.lastIndex = 0;
      if (entry.regex.test(text)) {
        findings.push({ file: relative(root, file).replaceAll("\\", "/"), kind: entry.name });
      }
    }
  }

  return Object.freeze({ clean: findings.length === 0, scannedFiles, findings });
}

async function collectFiles(root, directory, output) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const fullPath = resolve(directory, entry.name);
    if (!fullPath.startsWith(root)) continue;
    if (entry.isDirectory()) await collectFiles(root, fullPath, output);
    else if (entry.isFile()) output.push(fullPath);
  }
}

function pattern(name, source) {
  return Object.freeze({ name, regex: new RegExp(source, "g") });
}
