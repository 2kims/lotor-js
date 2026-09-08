import assert from "node:assert/strict";
import test from "node:test";
import { iteratePages, pollOperation } from "../src/async-helpers.js";
import { LotorBrowserClient, MemoryTokenStore } from "../src/index.js";

async function collect<T>(items: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of items) result.push(item);
  return result;
}

test("client helpers preserve directory filters, user authority and transport cancellation", async () => {
  for (const mode of ["public", "same-origin"] as const) {
    const controller = new AbortController();
    const tokenStore = new MemoryTokenStore(); tokenStore.setToken("user-token");
    const requests: URL[] = [];
    let reads = 0;
    const sdk = new LotorBrowserClient({
      ...(mode === "public" ? { mode, baseUrl: "https://api.lotor.test", tokenStore } : { mode }),
      clientId: "avault", publishableKey: "lp_sbx_test",
      fetch: async (input, init) => {
        assert.equal(init?.signal, controller.signal);
        assert.equal(init?.cache, "no-store");
        const headers = new Headers(init?.headers);
        assert.equal(headers.get("Authorization"), mode === "public" ? "Bearer user-token" : null);
        assert.equal(init?.credentials, mode === "public" ? "omit" : "same-origin");
        const url = new URL(String(input), "https://avault.test");
        requests.push(url);
        if (url.pathname.endsWith("/me/resources")) {
          return Response.json({ resources: [], next_cursor: requests.length === 1 ? "opaque+cursor" : null });
        }
        return Response.json({ id: "op_1", kind: "resource_move", status: ++reads === 1 ? "running" : "failed", target_kind: "resource", target_id: "vault:one", request_hash: "a".repeat(64), created_at: 1, updated_at: 2 });
      },
    });
    assert.deepEqual(await collect(sdk.iterateAccountResources({ parent: "project:one", types: ["vault"], accessStates: ["active"], limit: 10, signal: controller.signal })), []);
    assert.equal(requests.length, 2);
    for (const url of requests) {
      assert.equal(url.searchParams.get("parent"), "project:one");
      assert.equal(url.searchParams.get("type"), "vault");
      assert.equal(url.searchParams.get("access_state"), "active");
      assert.equal(url.searchParams.get("limit"), "10");
    }
    assert.equal(requests[1]?.searchParams.get("cursor"), "opaque+cursor");
    assert.equal((await sdk.waitForOperation("op_1", { signal: controller.signal, intervalMs: 0 })).status, "failed");
    assert.equal(reads, 2);
    controller.abort(new Error("stop"));
    await assert.rejects(sdk.waitForOperation("op_1", { signal: controller.signal }), /stop/);
    assert.equal(requests.length, 4);
  }
});

test("iterates opaque cursors lazily, including empty intermediate pages", async () => {
  const cursors: Array<string | undefined> = [];
  const values = await collect(iteratePages(async cursor => {
    cursors.push(cursor);
    return cursor === undefined ? { items: [], nextCursor: "opaque+cursor" } : { items: [1, 2], nextCursor: null };
  }));
  assert.deepEqual(values, [1, 2]);
  assert.deepEqual(cursors, [undefined, "opaque+cursor"]);
  let calls = 0;
  for await (const _item of iteratePages(async () => { calls++; return { items: [1, 2], nextCursor: "next" }; })) break;
  assert.equal(calls, 1);
});

test("client polling cancels an in-flight fetch without retrying", async () => {
  const controller = new AbortController();
  let calls = 0;
  const sdk = new LotorBrowserClient({
    mode: "same-origin", clientId: "avault", publishableKey: "lp_sbx_test",
    fetch: async (_input, init) => {
      calls++;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
        controller.abort(new Error("cancel fetch"));
      });
    },
  });
  await assert.rejects(sdk.waitForOperation("op_1", { signal: controller.signal }), /cancel fetch/);
  assert.equal(calls, 1);
});

test("rejects repeated cursors and bounded traversal without hidden retries", async () => {
  await assert.rejects(collect(iteratePages(async () => ({ items: [], nextCursor: "loop" }))), /repeated cursor/);
  await assert.rejects(collect(iteratePages(async () => ({ items: [], nextCursor: "next" }), { maxPages: 1 })), /maxPages/);
  let calls = 0;
  await assert.rejects(collect(iteratePages(async () => { calls++; throw new Error("forbidden"); })), /forbidden/);
  assert.equal(calls, 1);
  await assert.rejects(collect(iteratePages(async () => { calls++; return { items: [], nextCursor: null }; }, { maxPages: 0 })), /maxPages/);
  assert.equal(calls, 1);
});

test("propagates cancellation to page reads and rejects results arriving after abort", async () => {
  const controller = new AbortController();
  await assert.rejects(collect(iteratePages(async (_cursor, signal) => {
    assert.equal(signal, controller.signal);
    controller.abort(new Error("cancelled"));
    return { items: [1], nextCursor: null };
  }, { signal: controller.signal })), /cancelled/);
});

test("polls only pending states and preserves every terminal outcome", async () => {
  for (const status of ["succeeded", "failed", "cancelled"]) {
    let calls = 0;
    const result = await pollOperation(async () => ({ status: ++calls === 1 ? "running" : status, errorCode: "reason" }), { intervalMs: 0 });
    assert.equal(result.status, status);
    assert.equal(result.errorCode, "reason");
    assert.equal(calls, 2);
  }
  await assert.rejects(pollOperation(async () => ({ status: "unknown" })), /unknown/);
  await assert.rejects(pollOperation(async () => ({ status: "pending" }), { maxAttempts: 1 }), /maxAttempts/);
  await assert.rejects(pollOperation(async () => { throw new Error("unauthorized"); }), /unauthorized/);
});

test("aborts a long polling delay immediately and performs no subsequent read", async () => {
  const controller = new AbortController();
  let calls = 0;
  const waiting = pollOperation(async signal => {
    calls++;
    assert.equal(signal, controller.signal);
    setTimeout(() => controller.abort(new Error("stop")), 0);
    return { status: "pending" };
  }, { signal: controller.signal, intervalMs: 60000 });
  await assert.rejects(waiting, /stop/);
  assert.equal(calls, 1);
});
