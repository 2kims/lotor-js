import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

const ACTION_PINS = Object.freeze({
  "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
  "actions/create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",
  "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
  "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "googleapis/release-please-action": "45996ed1f6d02564a971a2fa1b5860e934307cf7",
  "pnpm/action-setup": "b906affcce14559ad1aafd4ab0e942779e9f58b1",
});

function invariant(condition, message) {
  if (!condition) throw new Error(`Workflow invariant failed: ${message}`);
}

function occurrences(source, pattern) {
  return [...source.matchAll(pattern)].length;
}

function jobBlock(source, name) {
  const marker = new RegExp(`^  ${name}:\\n`, "gm");
  const matches = [...source.matchAll(marker)];
  invariant(matches.length === 1, `release workflow must define ${name} exactly once`);
  const start = matches[0].index;
  const remainder = source.slice(start + matches[0][0].length);
  const next = remainder.search(/^  [A-Za-z0-9_-]+:\n/m);
  return source.slice(start, next === -1 ? source.length : start + matches[0][0].length + next);
}

function includes(source, text, message) {
  invariant(source.includes(text), message);
}

export function verifyWorkflowSources({ pullRequest, release, packageJson, allWorkflows }) {
  invariant(Array.isArray(allWorkflows) && allWorkflows.length === 2, "only reviewed pull-request and release workflows may exist");
  for (const [filename, source] of allWorkflows) {
    for (const match of source.matchAll(/^\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/gm)) {
      const pin = /^([^@]+)@([0-9a-f]{40})$/.exec(match[1]);
      invariant(pin, `${filename} action is not pinned to a full commit SHA: ${match[1]}`);
      invariant(ACTION_PINS[pin[1]] === pin[2], `${filename} action pin is not approved: ${match[1]}`);
    }
  }

  includes(pullRequest, "permissions:\n  contents: read", "pull-request workflow must be read-only");
  includes(pullRequest, "persist-credentials: false", "pull-request checkout must not persist credentials");
  includes(pullRequest, "pnpm install --frozen-lockfile", "pull-request checks must use the frozen lockfile");
  includes(pullRequest, "pnpm package:check", "pull-request checks must inspect the package");
  includes(pullRequest, "ACTIONLINT_SHA256: 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757", "Actionlint checksum must remain pinned");

  includes(release, "permissions: {}", "release workflow must deny permissions by default");
  for (const gate of ["vars.RELEASE_AUTOMATION_ENABLED == 'true'", "vars.NPM_TRUSTED_PUBLISHING_READY == 'true'", "github.ref == 'refs/heads/main'"]) {
    invariant(occurrences(release, new RegExp(gate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) === 4, `every release job must use gate: ${gate}`);
  }
  const jobs = [...release.slice(release.indexOf("\njobs:\n") + 7).matchAll(/^  ([A-Za-z0-9_-]+):\n/gm)].map((match) => match[1]);
  invariant(JSON.stringify(jobs) === JSON.stringify(["release", "validate", "package", "publish"]), "release job graph changed");

  const releaseJob = jobBlock(release, "release");
  const validate = jobBlock(release, "validate");
  const packageJob = jobBlock(release, "package");
  const publish = jobBlock(release, "publish");
  includes(releaseJob, "environment: release-automation", "release automation must use its protected environment");
  includes(releaseJob, "client-id: ${{ vars.BOT_2K_CLIENT_ID }}", "2K Bot must use its registered Client ID");
  includes(releaseJob, "private-key: ${{ secrets.BOT_2K_KEY }}", "2K Bot must use the registered private-key secret");
  invariant(occurrences(release, /\bsecrets(?:\.|\[)/g) === 1, "only release automation may reference one secret");

  invariant(!/\benvironment:/.test(validate), "validation must not enter a protected environment");
  invariant(!/\bid-token:/.test(validate), "validation must not receive OIDC");
  includes(validate, "pnpm install --frozen-lockfile", "validation must use the frozen lockfile");
  includes(validate, "pnpm package:check", "validation must exercise the package as a consumer");

  invariant(!/\benvironment:/.test(packageJob), "packaging must not enter a protected environment");
  invariant(!/\bid-token:/.test(packageJob), "packaging must not receive OIDC");
  includes(packageJob, "pnpm install --frozen-lockfile", "packaging must use the frozen lockfile");
  includes(packageJob, "npm pack --ignore-scripts --json --pack-destination", "packaging must disable lifecycle scripts");

  includes(publish, "environment: npm-publish", "publisher must use the npm-publish environment");
  includes(publish, "      actions: read\n      id-token: write", "publisher must receive only artifact read and OIDC");
  invariant(!/actions\/checkout@/.test(publish), "publisher must not check out source");
  invariant(!/\bpnpm\b/.test(publish), "publisher must not execute project tooling");
  invariant(!/\bsecrets(?:\.|\[)/.test(publish), "publisher must not reference secrets");
  invariant(occurrences(release, /^\s+npm publish "\$TARBALL_PATH" --access public --provenance --tag "\$DIST_TAG" --ignore-scripts$/gm) === 1, "publisher must publish exactly one verified tarball");
  invariant(occurrences(release, /^\s+id-token: write$/gm) === 1, "only publisher may receive OIDC");
  invariant(!/(NPM_TOKEN|secrets\.GITHUB_TOKEN)/.test(`${pullRequest}\n${release}`), "token fallbacks are forbidden");

  invariant(packageJson.publishConfig?.provenance === true, "package provenance must be enabled");
  invariant(packageJson.publishConfig?.registry === "https://registry.npmjs.org/", "npm registry must be explicit");
  invariant(packageJson.scripts?.["verify:workflows"] === "node scripts/verify-workflows.mjs", "workflow verifier must be wired");
}

export function verifyWorkflows(rootDir = process.cwd()) {
  const directory = path.join(rootDir, ".github/workflows");
  const files = fs.readdirSync(directory).filter((name) => /\.ya?ml$/.test(name)).sort();
  const allWorkflows = files.map((name) => [name, fs.readFileSync(path.join(directory, name), "utf8")]);
  const sources = new Map(allWorkflows);
  verifyWorkflowSources({
    pullRequest: sources.get("pull-request.yml"),
    release: sources.get("release-please.yml"),
    packageJson: JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8")),
    allWorkflows,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    verifyWorkflows();
    console.log("Verified release workflow trust boundaries.");
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
