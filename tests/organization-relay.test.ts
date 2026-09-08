import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`organization box lifecycle preserves ${mode} user authority`, async () => {
  const tokens = new MemoryTokenStore(); tokens.setToken("alice");
  let calls = 0, denied = false;
  let statusResult: unknown = { binding_id: "efb_acme", status: "pending", bootstrap_expires_at: 123456789, challenge: { status: "not_started" } };
  const sdk = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore: tokens } : { mode, csrfToken: () => "csrf" }),
    clientId: "avault", publishableKey: "lp_sbx_test",
    fetch: async (input, init = {}) => {
      calls++;
      const method = init.method ?? "GET";
      assert.ok(String(input).endsWith(`/resources/organization%3Aacme/e2ee/function-bindings${method === "POST" ? "" : "/efb_acme"}`));
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer alice" : null);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      assert.equal(init.credentials, mode === "public" ? "omit" : "same-origin");
      if (mode === "same-origin" && method !== "GET") assert.equal(headers.get("X-Lotor-CSRF"), "csrf");
      if (denied) return Response.json({ error: "forbidden" }, { status: 403 });
      if (method === "POST") return Response.json({ binding_id: "efb_acme", status: "pending", bootstrap_token: "e2ee_bootstrap_once" }, { status: 201 });
      if (method === "DELETE") return new Response(null, { status: 204 });
      return Response.json(statusResult);
    },
  });
  assert.deepEqual(await sdk.createOrganizationFunctionBinding("organization:acme"), { bindingId: "efb_acme", status: "pending", bootstrapToken: "e2ee_bootstrap_once" });
  assert.deepEqual(await sdk.organizationFunctionBinding("organization:acme", "efb_acme"), { bindingId: "efb_acme", status: "pending", bootstrapExpiresAt: 123456789, challenge: { status: "not_started" } });
  await sdk.revokeOrganizationFunctionBinding("organization:acme", "efb_acme");
  assert.equal(tokens.getToken(), "alice");
  denied = true;
  await assert.rejects(sdk.createOrganizationFunctionBinding("organization:acme"));
  await assert.rejects(sdk.organizationFunctionBinding("organization:acme", "efb_acme"));
  await assert.rejects(sdk.revokeOrganizationFunctionBinding("organization:acme", "efb_acme"));
  assert.equal(calls, 6);
  denied = false;
  for (statusResult of [{ binding_id: "efb_other", status: "active", challenge: { status: "not_started" } }, { binding_id: "efb_acme", status: "ready" }, { binding_id: "efb_acme", status: "pending", bootstrap_token: "secret" }, { binding_id: "efb_acme", status: "pending", bootstrap_expires_at: "tomorrow", challenge: { status: "not_started" } }]) {
    await assert.rejects(sdk.organizationFunctionBinding("organization:acme", "efb_acme"));
  }
});
