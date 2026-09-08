import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

const directory = { id: "res_directory", resource: "directory:acme", organization: "organization:acme", credential_resource: "api_key:scim", status: "disabled", revision: 1, base_url: "https://api.lotor.test/scim/v2/directories/res_directory" };
for (const mode of ["public", "same-origin"] as const) {
  test(`SCIM setup uses ${mode} user authority`, async () => {
    const tokenStore = new MemoryTokenStore(); tokenStore.setToken("alice");
    const requests: { url: string; init: RequestInit }[] = [];
    let response: unknown = directory;
    let status = 200;
    const client = new LotorBrowserClient({
      ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode, csrfToken: () => "csrf" }),
      clientId: "avault", publishableKey: "lp_sbx_test",
      fetch: async (url, init = {}) => {
        requests.push({ url: String(url), init });
        const headers = new Headers(init.headers);
        assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer alice" : null);
        assert.equal(headers.get("X-Lotor-Secret-Key"), null);
        assert.equal(init.credentials, mode === "public" ? "omit" : "same-origin");
        assert.equal(init.cache, "no-store");
        if (mode === "same-origin" && (init.method === "POST" || init.method === "PUT")) assert.equal(headers.get("X-Lotor-CSRF"), "csrf");
        return Response.json(response, { status });
      },
    });
    const input = { directoryResource: "directory:acme", credentialResource: "api_key:scim", expectedResourceRevision: 1, expectedLifecycleGeneration: 2 };
    const created = await client.createSCIMDirectory("organization:acme", input, "setup-once");
    assert.equal(created.credentialResource, "api_key:scim");
    assert.equal(created.status, "disabled");
    assert.equal(new Headers(requests[0].init.headers).get("Idempotency-Key"), "setup-once");
    assert.deepEqual(JSON.parse(String(requests[0].init.body)), { directory_resource: "directory:acme", credential_resource: "api_key:scim", expected_resource_revision: 1, expected_lifecycle_generation: 2 });
    assert.ok(requests[0].url.endsWith("/resources/organization%3Aacme/scim-directories"));
    assert.deepEqual(await client.scimDirectory("organization:acme", "res_directory"), created);
    assert.ok(requests[1].url.endsWith("/scim-directories/res_directory"));
    response = { ...directory, status: "active", revision: 2 };
    const updated = await client.updateSCIMDirectory("organization:acme", "res_directory", { enabled: true, expectedRevision: 1 }, "enable-once");
    assert.equal(updated.status, "active");
    assert.equal(requests[2].init.method, "PUT");
    assert.equal(new Headers(requests[2].init.headers).get("Idempotency-Key"), "enable-once");
    assert.deepEqual(JSON.parse(String(requests[2].init.body)), { enabled: true, expected_revision: 1 });
    response = { directories: [directory], next_cursor: "next+cursor" };
    assert.deepEqual(await client.scimDirectories("organization:acme", { limit: 1, cursor: "previous+cursor" }), { directories: [created], nextCursor: "next+cursor" });
    assert.ok(requests[3].url.endsWith("?cursor=previous%2Bcursor&limit=1"));
    const before = requests.length;
    await assert.rejects(client.scimDirectories("organization:acme", { limit: 101 }));
    await assert.rejects(client.createSCIMDirectory("organization:acme", { ...input, expectedResourceRevision: 0 }, "setup-once"));
    await assert.rejects(client.updateSCIMDirectory("organization:acme", "res_directory", { enabled: true, expectedRevision: 0 }, "enable-once"));
    await assert.rejects(client.updateSCIMDirectory("organization:acme", "../other", { enabled: true, expectedRevision: 1 }, "enable-once"));
    assert.equal(requests.length, before);
    for (response of [{ ...directory, id: "other" }, { ...directory, secret: "must-not-escape" }, { ...directory, revision: 0 }, { ...directory, status: "unknown" }, { ...directory, base_url: "http://unsafe.test" }]) {
      await assert.rejects(client.scimDirectory("organization:acme", "res_directory"));
    }
    status = 403; response = { error: "forbidden" };
    const beforeDenied = requests.length;
    await assert.rejects(client.scimDirectories("organization:acme"));
    assert.equal(requests.length, beforeDenied + 1);
  });
}
