import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`asynchronous box challenge preserves ${mode} authority`, async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("alice");
  let result: unknown = { status: "pending", expires_at: 123 };
  let status = 202, calls = 0;
  const client = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode, csrfToken: () => "csrf" }),
    clientId: "avault", publishableKey: "lp_sbx_test",
    fetch: async (url, init = {}) => {
      calls++;
      assert.ok(String(url).endsWith("/resources/organization%3Aacme/e2ee/function-bindings/efb_acme/challenge"));
      assert.equal(init.method, "POST");
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer alice" : null);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      assert.equal(init.credentials, mode === "public" ? "omit" : "same-origin");
      if (mode === "same-origin") assert.equal(headers.get("X-Lotor-CSRF"), "csrf");
      return Response.json(result, { status });
    },
  });
  assert.deepEqual(await client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"), { status: "pending", expiresAt: 123 });
  for (result of [{ status: "ready" }, { status: "pending" }, { status: "ready", challenged_at: "bad" }, { status: "ready", challenged_at: 1, connector_token: "secret" }, { status: "unknown" }]) {
    await assert.rejects(client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"));
  }
  status = 403;
  const before = calls;
  await assert.rejects(client.startOrganizationFunctionBindingChallenge("organization:acme", "efb_acme"));
  assert.equal(calls, before + 1);
});
