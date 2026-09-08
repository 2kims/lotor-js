import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`system resource creation uses ${mode} parent-manager authority`, async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("owner");
  let calls = 0;
  let denied = false;
  const sdk = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode, csrfToken: () => "csrf" }),
    clientId: "avault", publishableKey: "lp_sbx_test", fetch: async (input, init = {}) => {
      calls++;
      assert.ok(String(input).endsWith("/resources"));
      assert.equal(init.method, "POST");
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer owner" : null);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      assert.equal(headers.get("X-Lotor-CSRF"), mode === "same-origin" ? "csrf" : null);
      assert.equal(headers.get("Idempotency-Key"), "create-key");
      const body = JSON.parse(String(init.body));
      assert.equal(body.parent, "org_acme");
      assert.equal(body.display_name, "Team");
      assert.equal(body.key_scope, "organization");
      if (denied) return Response.json({}, { status: 403 });
      return Response.json({ id: "op", kind: "resource_create", status: "pending", target_kind: "resource", target_id: `${body.resource_type}:generated`, request_hash: "hash", created_at: 1, updated_at: 1 });
    },
  });
  for (const resourceType of ["group", "service_account"] as const) {
    const operation = await sdk.createSystemResource({ resourceType, parent: "org_acme", displayName: "Team", keyScope: "organization" }, "create-key");
    assert.equal(operation.status, "pending");
    assert.equal(operation.targetId, `${resourceType}:generated`);
  }
  denied = true;
  await assert.rejects(sdk.createSystemResource({ resourceType: "group", parent: "org_acme", displayName: "Team", keyScope: "organization" }, "create-key"));
  await assert.rejects(sdk.createSystemResource({ resourceType: "group", parent: "", displayName: "Team" }, "create-key"));
  assert.equal(calls, 3);
});
