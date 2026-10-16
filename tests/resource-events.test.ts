import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

for (const mode of ["public", "same-origin"] as const) test(`resource events preserve snapshot and user authority (${mode})`, async () => {
  const tokens = new MemoryTokenStore(); tokens.setToken("user-session");
  const calls: string[] = []; let unavailable = false;
  const sdk = new LotorBrowserClient({
    ...(mode === "public" ? { mode, baseUrl: "https://lotor.test", tokenStore: tokens } : { mode, csrfToken: () => "csrf" }),
    clientId: "app", publishableKey: "pk_fixture",
    fetch: async (input, init = {}) => {
      const url = new URL(String(input), "https://app.test"), headers = new Headers(init.headers);
      calls.push(url.pathname);
      assert.equal(headers.get("X-Lotor-Secret-Key"), null);
      assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer user-session" : null);
      assert.match(url.pathname, /resources\/organization%3Aone\/event-streams\/audit/);
      if (unavailable) return Response.json({ error: "unavailable" }, { status: 503 });
      if (init.method === "PUT" || init.method === "POST" && url.pathname.endsWith("/events")) return new Response(null, { status: 204 });
      if (url.pathname.endsWith("/queries")) return Response.json({ id: "snapshot", from: "2026-10-16T00:00:00Z", to: "2026-10-16T01:00:00Z", expires_at: "2026-10-16T01:10:00Z" });
      if (url.pathname.endsWith("/histogram")) {
        assert.equal(url.searchParams.get("group_by"), "result");
        assert.equal(url.searchParams.get("interval_seconds"), "60");
        return Response.json([{ start: "2026-10-16T00:00:00Z", end: "2026-10-16T00:01:00Z", counts: { no_response: 2 } }]);
      }
      if (url.pathname.endsWith("/events")) {
        assert.equal(url.searchParams.get("cursor"), "opaque+cursor");
        return Response.json({ items: [], next_cursor: null });
      }
      return Response.json({ id: "one", producer_subject:"user-session", recorded_at:"2026-10-16T00:00:00Z", occurred_at: "2026-10-16T00:00:00Z", attributes: {}, representation: "encrypted", body: "AAE=" });
    },
  });
  const stream = sdk.eventStream("organization:one", "audit");
  await stream.configure({ attributeKeys: ["result"], retentionDays: 7 });
  await stream.append({ id: "one", occurredAt: "2026-10-16T00:00:00Z", attributes: {}, representation: "encrypted", bodyBase64: "AAE=" });
  const query = await stream.createQuery({ from: "2026-10-16T00:00:00Z", to: "2026-10-16T01:00:00Z", filters: {} });
  assert.deepEqual(await stream.events(query.id, { cursor: "opaque+cursor" }), { items: [], nextCursor: null });
  assert.equal((await stream.histogram(query.id, { groupBy: "result", intervalSeconds: 60 }))[0]?.counts.no_response, 2);
  assert.equal((await stream.event("one")).bodyBase64, "AAE=");
  unavailable = true;
  await assert.rejects(stream.events(query.id), /unavailable|503/);
  assert.equal(calls.length, 7, "storage errors must not retry or fall back");
  assert.throws(() => sdk.eventStream("organization:one", ".."));
});

test("bucket selection sends the parent snapshot in the canonical wire contract", async () => {
  const tokens = new MemoryTokenStore(); tokens.setToken("user-session");
  let calls = 0;
  const sdk = new LotorBrowserClient({ mode: "public", baseUrl: "https://lotor.test", tokenStore: tokens, clientId: "app", publishableKey: "pk_fixture",
    fetch: async (_input, init = {}) => {
      calls++;
      assert.deepEqual(JSON.parse(String(init.body)), { from: "2026-10-16T00:00:00Z", to: "2026-10-16T00:15:00Z", filters: {}, parent_query_id: "parent" });
      return Response.json({ id: "child", from: "2026-10-16T00:00:00Z", to: "2026-10-16T00:15:00Z", expires_at: "2026-10-16T01:10:00Z" });
    },
  });
  const query = await sdk.eventStream("organization:one", "audit").createQuery({ parentQueryId: "parent", from: "2026-10-16T00:00:00Z", to: "2026-10-16T00:15:00Z", filters: {} });
  assert.equal(query.id, "child");
  assert.equal(calls, 1);
});
