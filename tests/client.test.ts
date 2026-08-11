import assert from "node:assert/strict";
import test from "node:test";

import {
  LotorBrowserClient,
  LotorBrowserError,
  MemoryTokenStore,
  type BrowserFetch,
  type TokenStore,
} from "../src/index.js";

interface RecordedRequest { url: string; init: RequestInit }

function response(body: unknown, status = 200): Response {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fixtureFetch(requests: RecordedRequest[]): BrowserFetch {
  return async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, init });
    if (url.endsWith("/auth/passwordless/start")) return response({ challenge_id: "plc_1", delivery: "email", expires_at: 123 });
    if (url.endsWith("/auth/passwordless/verify")) return response({ subject: "user_1", email: "founder@example.test", access_token: "opaque-token" });
    if (url.endsWith("/session") && init.method === "DELETE") return response(undefined, 204);
    if (url.endsWith("/session")) return response({ authenticated: true, subject: "user_1", email: "founder@example.test" });
    if (url.endsWith("/organizations")) return response([{ id: "org_1", name: "Personal Workspace", current_role: "owner", member_count: 1, pending_invites: 0 }]);
    if (url.endsWith("/billing/checkout-sessions")) return response({ id: "cs_1", presentation: "custom", client_secret: "cs_test_secret", publishable_key: "pk_test_public" }, 201);
    return response({ error: "not found" }, 404);
  };
}

function client(requests: RecordedRequest[], tokenStore?: TokenStore): LotorBrowserClient {
  return new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    fetch: fixtureFetch(requests),
    tokenStore,
  });
}

test("calls the application-scoped public API and keeps the bearer out of return values", async () => {
  const requests: RecordedRequest[] = [];
  const sdk = client(requests);
  const challenge = await sdk.startPasswordless("founder@example.test");
  const verified = await sdk.verifyPasswordless(challenge.challenge_id, "111111");
  const session = await sdk.session();

  assert.deepEqual(verified, { authenticated: true, subject: "user_1", email: "founder@example.test" });
  assert.equal("access_token" in verified, false);
  assert.deepEqual(session, verified);
  assert.deepEqual(requests.map(({ url }) => url), [
    "https://api.lotor.test/v1/public/applications/signalbox_web/auth/passwordless/start",
    "https://api.lotor.test/v1/public/applications/signalbox_web/auth/passwordless/verify",
    "https://api.lotor.test/v1/public/applications/signalbox_web/session",
  ]);
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { email: "founder@example.test" });
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), { challenge_id: "plc_1", code: "111111" });
  assert.equal(new Headers(requests[0]?.init.headers).has("Authorization"), false);
  assert.equal(new Headers(requests[2]?.init.headers).get("Authorization"), "Bearer opaque-token");
  assert.ok(requests.every(({ init }) => init.credentials === "omit"));
});

test("uses non-persistent memory storage by default and supports an explicit async token store", async () => {
  let stored: string | null = null;
  const tokenStore: TokenStore = {
    async getToken() { return stored; },
    async setToken(token) { stored = token; },
    async clearToken() { stored = null; },
  };
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  await sdk.verifyPasswordless("plc_1", "111111");
  assert.equal(stored, "opaque-token");
  await sdk.logout();
  assert.equal(stored, null);
  assert.equal(new Headers(requests[1]?.init.headers).get("Authorization"), "Bearer opaque-token");

  const memory = new MemoryTokenStore();
  assert.equal(memory.getToken(), null);
  memory.setToken("value");
  assert.equal(memory.getToken(), "value");
});

test("maps missing and rejected sessions to anonymous and clears stale tokens", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("stale");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    tokenStore,
    fetch: async () => response({}, 401),
  });
  assert.deepEqual(await sdk.session(), { authenticated: false });
  assert.equal(tokenStore.getToken(), null);
  assert.deepEqual(await sdk.session(), { authenticated: false });
});

test("lists sanitized organizations with bearer authentication", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const organizations = await client(requests, tokenStore).organizations();
  assert.deepEqual(organizations, [{ id: "org_1", name: "Personal Workspace", currentRole: "owner", memberCount: 1, pendingInvites: 0 }]);
  assert.equal(new Headers(requests[0]?.init.headers).get("Authorization"), "Bearer token");
});

test("creates typed custom checkout sessions with required browser return URLs", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const result = await client(requests, tokenStore).billing.createCheckoutSession({
    organizationId: "org_1",
    productId: "product_pro",
    priceId: "price_month",
    presentation: "custom",
    returnUrl: "https://signalbox.example/billing/return",
    idempotencyKey: "checkout-1",
  });
  assert.deepEqual(result, { id: "cs_1", presentation: "custom", clientSecret: "cs_test_secret", publishableKey: "pk_test_public" });
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/billing/checkout-sessions");
  assert.equal(new Headers(requests[0]?.init.headers).get("X-Lotor-Request"), "lotor-js-v1");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), {
    organization_id: "org_1", product_id: "product_pro", price_id: "price_month", presentation: "custom",
    idempotency_key: "checkout-1", return_url: "https://signalbox.example/billing/return",
  });
});

test("requires a secure absolute origin and gates loopback HTTP explicitly", () => {
  const fetch = fixtureFetch([]);
  for (const baseUrl of ["/api/lotor", "http://api.example.test", "https://api.example.test/v1", "https://user@api.example.test"]) {
    assert.throws(() => new LotorBrowserClient({ baseUrl, clientId: "app", fetch }));
  }
  assert.throws(() => new LotorBrowserClient({ baseUrl: "http://127.0.0.1:8080", clientId: "app", fetch }), /allowInsecureLoopback/);
  assert.doesNotThrow(() => new LotorBrowserClient({ baseUrl: "http://127.0.0.1:8080", clientId: "app", allowInsecureLoopback: true, fetch }));
  assert.doesNotThrow(() => new LotorBrowserClient({ baseUrl: "http://[::1]:8080", clientId: "app", allowInsecureLoopback: true, fetch }));
});

test("errors contain status but never echo an unsafe response body", async () => {
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    fetch: async () => response({ error: "secret response detail", tenant_id: "must-not-escape" }, 500),
  });
  await assert.rejects(sdk.startPasswordless("founder@example.test"), (error: unknown) => {
    assert.ok(error instanceof LotorBrowserError);
    assert.equal(error.status, 500);
    assert.doesNotMatch(error.message, /secret|tenant/);
    return true;
  });
});
