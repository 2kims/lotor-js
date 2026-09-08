import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

test("organization binding discovery is bounded, secret-free and user-scoped", async () => {
  const tokens = new MemoryTokenStore(); tokens.setToken("alice");
  let response: unknown = [], calls = 0, status = 200;
  const client = new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "avault", publishableKey: "lp_sbx_test", tokenStore: tokens,
    fetch: async (url, init) => {
      calls++;
      assert.ok(String(url).endsWith("/resources/organization%3Aacme/e2ee/function-bindings"));
      assert.equal(init?.method ?? "GET", "GET");
      assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer alice");
      assert.equal(new Headers(init?.headers).get("X-Lotor-Secret-Key"), null);
      return Response.json(response, { status });
    },
  });
  assert.deepEqual(await client.organizationFunctionBindings("organization:acme"), []);
  response = [{ binding_id: "efb_acme", status: "expired", bootstrap_expires_at: 123, challenge: { status: "unavailable" } }];
  assert.deepEqual(await client.organizationFunctionBindings("organization:acme"), [{ bindingId: "efb_acme", status: "expired", bootstrapExpiresAt: 123, challenge: { status: "unavailable" } }]);
  for (response of [null, {}, [{ binding_id: "efb_one", status: "pending" }, { binding_id: "efb_two", status: "active" }], [{ binding_id: "efb_acme", status: "revoked", challenge: { status: "unavailable" } }], [{ binding_id: "efb_acme", status: "pending", bootstrap_token: "secret" }]]) await assert.rejects(client.organizationFunctionBindings("organization:acme"));
  status = 403;
  const before = calls;
  await assert.rejects(client.organizationFunctionBindings("organization:acme"));
  assert.equal(calls, before + 1);
});
