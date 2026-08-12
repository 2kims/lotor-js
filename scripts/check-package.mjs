#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary = mkdtempSync(join(tmpdir(), "lotor-js-package-"));

function run(command, args, cwd = temporary) {
  execFileSync(command, args, { cwd, stdio: "inherit" });
}

try {
  const packed = JSON.parse(execFileSync(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
    { cwd: root, encoding: "utf8" },
  ));
  assert.equal(packed.length, 1);
  const artifact = packed[0];
  const paths = artifact.files.map(({ path }) => path).sort();
  const expected = [
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "dist/client.d.ts",
    "dist/client.js",
    "dist/decode.d.ts",
    "dist/decode.js",
    "dist/index.d.ts",
    "dist/index.js",
    "dist/transport.d.ts",
    "dist/transport.js",
    "dist/types.d.ts",
    "dist/types.js",
    "package.json",
  ];
  assert.deepEqual(paths, expected, "packed artifact contains an unexpected or missing file");

  const tarball = join(temporary, artifact.filename);
  const consumer = join(temporary, "consumer");
  mkdirSync(join(consumer, "src"), { recursive: true });
  writeFileSync(join(consumer, "package.json"), `${JSON.stringify({
    name: "lotor-js-clean-consumer",
    private: true,
    type: "module",
    dependencies: { "@lotor.dev/lotor-js": `file:${tarball}` },
  }, null, 2)}\n`);
  writeFileSync(join(consumer, "tsconfig.json"), `${JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "ESNext",
      moduleResolution: "Bundler",
      lib: ["ES2022", "DOM"],
      strict: true,
      noEmit: true,
      types: [],
    },
    include: ["src"],
  }, null, 2)}\n`);
  writeFileSync(join(consumer, "index.html"), '<div id="app"></div><script type="module" src="/src/main.ts"></script>\n');
  writeFileSync(join(consumer, "src/main.ts"), `
import { LotorBrowserClient, MemoryTokenStore, type CheckoutSession } from "@lotor.dev/lotor-js";

const client = new LotorBrowserClient({
  baseUrl: "https://api.lotor.test",
  clientId: "public_consumer",
  tokenStore: new MemoryTokenStore(),
});
const checkout: Promise<CheckoutSession> = client.billing.createCheckoutSession({
  organizationId: "organization_public",
  productId: "product_pro",
  priceId: "price_monthly",
  presentation: "hosted",
  successUrl: "https://app.example.test/success",
  cancelUrl: "https://app.example.test/cancel",
  idempotencyKey: "consumer-checkout",
});
void checkout;
`);
  writeFileSync(join(consumer, "runtime.mjs"), `
import assert from "node:assert/strict";
import { LotorBrowserClient } from "@lotor.dev/lotor-js";

const requests = [];
const fetcher = async (input, init = {}) => {
  const url = String(input);
  requests.push({ url, init });
  assert.ok(url.startsWith("https://api.lotor.test/v1/public/applications/public_consumer/"));
  assert.equal(init.credentials, "omit");
  const headers = new Headers(init.headers);
  const response = (value, status = 200) => new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "https://app.example.test" },
  });
  if (url.endsWith("/auth/passwordless/start")) return response({ challenge_id: "challenge_1", delivery: "email", expires_at: 1 });
  if (url.endsWith("/auth/passwordless/verify")) return response({ access_token: "opaque_test_bearer", subject: "user_1", email: "person@example.test" });
  assert.equal(headers.get("Authorization"), "Bearer opaque_test_bearer");
  if (url.endsWith("/session")) return response({ authenticated: true, subject: "user_1", email: "person@example.test" });
  if (url.endsWith("/organizations")) return response([{ id: "organization_public", name: "Personal workspace", current_role: "owner", member_count: 1, pending_invites: 0 }]);
  if (url.endsWith("/billing/checkout-sessions")) {
    const body = JSON.parse(init.body);
    return body.presentation === "hosted"
      ? response({ id: "checkout_hosted", presentation: "hosted", url: "https://checkout.stripe.test/session" }, 201)
      : response({ id: "checkout_custom", presentation: "custom", client_secret: "cs_test_public_fixture", publishable_key: "pk_test_public_fixture" }, 201);
  }
  throw new Error(\`unexpected request: \${url}\`);
};

const client = new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "public_consumer", fetch: fetcher });
const challenge = await client.startPasswordless("person@example.test");
assert.equal(challenge.challenge_id, "challenge_1");
assert.equal((await client.verifyPasswordless(challenge.challenge_id, "123456")).authenticated, true);
assert.equal((await client.session()).authenticated, true);
assert.equal((await client.organizations())[0].name, "Personal workspace");
assert.equal((await client.billing.createCheckoutSession({ organizationId: "organization_public", productId: "product_pro", priceId: "price_monthly", presentation: "hosted", successUrl: "https://app.example.test/success", cancelUrl: "https://app.example.test/cancel", idempotencyKey: "hosted" })).presentation, "hosted");
assert.equal((await client.billing.createCheckoutSession({ organizationId: "organization_public", productId: "product_pro", priceId: "price_monthly", presentation: "custom", returnUrl: "https://app.example.test/return", idempotencyKey: "custom" })).presentation, "custom");
assert.ok(requests.length >= 6);
process.stdout.write("packed client passed fake cross-origin runtime exercise\\n");
`);

  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], consumer);
  run(join(root, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.json"], consumer);
  run(join(root, "node_modules", ".bin", "esbuild"), ["src/main.ts", "--bundle", "--platform=browser", "--format=esm", "--outfile=dist-esbuild/main.js"], consumer);
  run(join(root, "node_modules", ".bin", "vite"), ["build", "--outDir", "dist-vite"], consumer);
  run(process.execPath, ["runtime.mjs"], consumer);

  const sourceManifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const packedManifest = JSON.parse(readFileSync(join(consumer, "node_modules", "@lotor.dev", "lotor-js", "package.json"), "utf8"));
  assert.equal(packedManifest.name, "@lotor.dev/lotor-js");
  assert.equal(packedManifest.version, sourceManifest.version);
  assert.equal(packedManifest.license, "Apache-2.0");
  assert.equal(packedManifest.private, undefined);
  assert.deepEqual(packedManifest.publishConfig, {
    access: "public",
    registry: "https://registry.npmjs.org/",
    provenance: true,
  });
  process.stdout.write(`clean packed consumer passed for ${packedManifest.name}@${packedManifest.version}\n`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
