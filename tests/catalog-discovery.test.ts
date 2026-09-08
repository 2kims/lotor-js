import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`discovers and binds catalogs with ${mode} user authority`, async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("user-token");
  const calls: { url: URL; init: RequestInit }[] = [];
  let denied = false;
  const sdk = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode, csrfToken: () => "csrf" }),
    clientId: "avault", publishableKey: "lp_sbx_test",
    fetch: async (input, init = {}) => {
      const url = new URL(String(input), "https://avault.test"); calls.push({ url, init });
      const headers = new Headers(init.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer user-token" : null);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      if (denied) return Response.json({ error: "forbidden" }, { status: 403 });
      if (init.method === "PUT") return Response.json({ id: "op", kind: "catalog_binding", status: "succeeded", target_kind: "resource", target_id: "vault:one", request_hash: "hash", created_at: 1, updated_at: 2 });
      if (url.pathname.endsWith("/entries")) return Response.json({ items: [], next_cursor: null, snapshot_id: "snap" });
      return Response.json({ items: [{ id: "cat", namespace: "slack", catalog_type: "api", visibility: "application_private", discoverable: true, status: "active", published_snapshot_id: "snap", created_at: 1 }], next_cursor: null });
    },
  });
  assert.equal((await sdk.availableCatalogs({ limit: 10 })).items[0]?.publishedSnapshotId, "snap");
  assert.equal((await sdk.availableCatalogEntries("cat", { cursor: "opaque+cursor", limit: 1 })).snapshotId, "snap");
  assert.equal(calls[1]?.url.searchParams.get("cursor"), "opaque+cursor");
  const binding = { catalogId: "cat", snapshotId: "snap", entryKinds: ["api.operation"], expectedResourceRevision: 2, expectedLifecycleGeneration: 1 };
  assert.equal((await sdk.bindResourceCatalog("vault:one", binding, "bind-key")).status, "succeeded");
  assert.ok(calls[2]?.url.pathname.endsWith("/resources/vault%3Aone/catalog-binding"));
  assert.equal(new Headers(calls[2]?.init.headers).get("Idempotency-Key"), "bind-key");
  assert.deepEqual(JSON.parse(String(calls[2]?.init.body)), { catalog_id: "cat", snapshot_id: "snap", entry_kinds: ["api.operation"], expected_resource_revision: 2, expected_lifecycle_generation: 1 });
  await assert.rejects(sdk.bindResourceCatalog("vault:one", { ...binding, expectedResourceRevision: NaN }, "key"), /safe integers/);
  await assert.rejects(sdk.bindResourceCatalog("vault:one", { ...binding, entryKinds: ["api.operation", "api.operation"] }, "key"), /entry kinds/);
  await assert.rejects(sdk.availableCatalogs({ limit: 101 }), /limit/);
  assert.equal(calls.length, 3);
  denied = true;
  await assert.rejects(sdk.bindResourceCatalog("vault:one", binding, "denied"));
  assert.equal(calls.length, 4, "denial must not retry as the application");
});
