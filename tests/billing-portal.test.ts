import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`billing portal preserves ${mode} user authority`, async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("alice");
  let calls = 0;
  let result: unknown = { id: "portal", url: "https://billing.stripe.com/session/test" };
  let status = 201;
  const sdk = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode, csrfToken: () => "csrf" }),
    clientId: "avault", publishableKey: "lp_sbx_test", fetch: async (input, init = {}) => {
      calls++;
      assert.ok(String(input).endsWith("/billing/portal-sessions"));
      assert.equal(init.method, "POST");
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer alice" : null);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      assert.equal(headers.get("X-Lotor-CSRF"), mode === "same-origin" ? "csrf" : null);
      assert.equal(init.credentials, mode === "same-origin" ? "same-origin" : "omit");
      assert.deepEqual(JSON.parse(String(init.body)), { organization_id: "org_acme", return_url: "https://avault.test/settings" });
      return Response.json(result, { status });
    },
  });
  const input = { organizationId: "org_acme", returnUrl: "https://avault.test/settings" };
  assert.deepEqual(await sdk.billing.createPortalSession(input), result);
  status = 403;
  await assert.rejects(sdk.billing.createPortalSession(input));
  assert.equal(calls, 2);
  await assert.rejects(sdk.billing.createPortalSession({ ...input, returnUrl: "javascript:alert(1)" }));
  for (const returnUrl of ["https://user:pass@avault.test/settings", "https://avault.test/settings?token=secret", "https://avault.test/settings#fragment", "http://avault.test/settings"]) {
    await assert.rejects(sdk.billing.createPortalSession({ ...input, returnUrl }));
  }
  assert.equal(calls, 2);
  status = 201; result = { id: "portal", url: "javascript:alert(1)" };
  await assert.rejects(sdk.billing.createPortalSession(input));
});

test("portal supports loopback return URLs for remote-backed local development", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("alice");
  const urls: string[] = [];
  const sdk = new LotorBrowserClient({ mode: "public", baseUrl: "https://api.lotor.test", tokenStore,
    clientId: "avault", publishableKey: "lp_sbx_test", fetch: async (_input, init) => {
      urls.push(JSON.parse(String(init?.body)).return_url);
      return Response.json({ id: "portal", url: "https://billing.stripe.com/session/test" });
    },
  });
  const expected = ["http://localhost:3300/settings", "http://127.0.0.1:3300/settings", "http://[::1]:3300/settings"];
  for (const returnUrl of expected) await sdk.billing.createPortalSession({ organizationId: "org_acme", returnUrl });
  assert.deepEqual(urls, expected);
});
