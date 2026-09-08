import assert from "node:assert/strict";
import test from "node:test";
import { BrowserTransport, LotorBrowserError, SameOriginBrowserTransport, type BrowserFetch } from "../src/transport.js";

for (const mode of ["public", "same-origin"] as const) for (const deniedStatus of [403, 404]) {
  test(`${mode} API reads bypass the HTTP cache and propagate ${deniedStatus}`, async () => {
    let calls = 0;
    const fetcher: BrowserFetch = async (_url, init) => {
      calls++;
      assert.equal(init?.cache, "no-store");
      assert.equal(init?.credentials, mode === "public" ? "omit" : "same-origin");
      assert.equal(init?.redirect, "error");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer account-token" : null);
      return calls <= 2 ? Response.json({ revision: calls }) : new Response(null, { status: deniedStatus });
    };
    const transport = mode === "public"
      ? new BrowserTransport("https://api.lotor.test", fetcher, { getToken: () => "account-token", setToken: () => {}, clearToken: () => {} }, "pk-test")
      : new SameOriginBrowserTransport(fetcher, "pk-test");
    const path = mode === "public" ? "/v1/public/applications/app/resources/vault" : "/.lotor/v1/applications/app/resources/vault";
    assert.deepEqual(await transport.request(path, {}, true), { revision: 1 });
    assert.deepEqual(await transport.request(path, { cache: "force-cache" }, true), { revision: 2 });
    await assert.rejects(transport.request(path, {}, true), (error: unknown) => error instanceof LotorBrowserError && error.status === deniedStatus);
    assert.equal(calls, 3, "denied reads must not retry or return a previous response");
  });
}

for (const mode of ["public", "same-origin"] as const) {
  test(`${mode} transport rejects JSON responses over four MiB`, async () => {
    const fetcher: BrowserFetch = async () => new Response(`{"value":"${"x".repeat(4 * 1024 * 1024)}"}`, {
      headers: { "Content-Type": "application/json" },
    });
    const transport = mode === "public"
      ? new BrowserTransport("https://api.lotor.test", fetcher, { getToken: () => "account-token", setToken: () => {}, clearToken: () => {} }, "pk-test")
      : new SameOriginBrowserTransport(fetcher, "pk-test");
    const path = mode === "public" ? "/v1/public/applications/app/catalogs" : "/.lotor/v1/applications/app/catalogs";
    await assert.rejects(transport.request(path), /response exceeds limit/);
  });
}
