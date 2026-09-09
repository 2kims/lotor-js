import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalProviderQuery, openProviderResponse, protectProviderRequest, type ResourceExecutionPreflight } from "../src/index.js";

function preflight(body: Uint8Array): ResourceExecutionPreflight {
  return { requestFingerprint: "fingerprint", resource: "credential:slack", catalogEntryId: "entry", payloadSlot: "provider_credential", payloadVersion: 2, payloadRepresentation: "encrypted-envelope-v1", executionMode: "managed", expiresAt: 123, method: "GET", path: "/messages", query: "channel=C123&limit=10", contentType: "application/json", requestBodyDigest: createHash("sha256").update(body).digest("hex"), requestBodySize: body.length, requestAad: Buffer.from("bound-query-aad").toString("base64url"), responsePolicyRef: "encrypt_all" };
}

test("canonicalizes provider query order and encoding", () => {
  assert.equal(canonicalProviderQuery(new URLSearchParams([["z", "hello world"], ["a", "2"]])), "a=2&z=hello+world");
});

test("protects only a body matching preflight", async () => {
  const body = new TextEncoder().encode("{}");
  const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const request = { method: "GET", path: "/messages", query: "channel=C123&limit=10", contentType: "application/json", body };
  assert.match(await protectProviderRequest(key, preflight(body), { ...request, headers: { Accept: "application/json" } }), /^[A-Za-z0-9_-]+$/u);
  await assert.rejects(() => protectProviderRequest(key, preflight(body), { ...request, body: new TextEncoder().encode("changed") }), /does not match/u);
  await assert.rejects(() => protectProviderRequest(key, preflight(body), { ...request, query: "channel=other" }), /metadata does not match/u);
  await assert.rejects(() => protectProviderRequest(key, preflight(body), { ...request, headers: { Authorization: "secret" } }), /unsupported header/u);
});

test("rejects a protected response from another authorization", async () => {
  const body = new TextEncoder().encode("{}");
  const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  await assert.rejects(() => openProviderResponse(key, preflight(body), { status: "completed", requestFingerprint: "other", resource: "credential:slack", catalogEntryId: "entry", payloadSlot: "provider_credential", payloadVersion: 2, payloadRepresentation: "encrypted-envelope-v1", executionMode: "managed", expiresAt: 123, providerStatus: 200, protectedResponse: "invalid" }), /does not match/u);
});

test("opens a response bound to the same preflight and provider status", async () => {
  const body = new TextEncoder().encode("{}");
  const keyBytes = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const plan = preflight(body);
  const requestAad = Buffer.from(plan.requestAad!, "base64url");
  const requestHash = createHash("sha256").update(requestAad).digest("hex");
  const responseAad = new TextEncoder().encode(`lotor-provider-response-v1\0${requestHash}\0${200}`);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ status: 200, headers: { "Content-Type": "application/json" }, body: Buffer.from("ok").toString("base64url") }));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: responseAad }, key, plaintext));
  const envelope = Buffer.from(JSON.stringify({ nonce: Buffer.from(nonce).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url"), aad_hash: createHash("sha256").update(responseAad).digest("hex") })).toString("base64url");
  const opened = await openProviderResponse(keyBytes, plan, { status: "completed", requestFingerprint: plan.requestFingerprint, resource: plan.resource, catalogEntryId: plan.catalogEntryId, payloadSlot: plan.payloadSlot, payloadVersion: plan.payloadVersion, payloadRepresentation: plan.payloadRepresentation, executionMode: plan.executionMode, expiresAt: plan.expiresAt, providerStatus: 200, protectedResponse: envelope });
  assert.equal(new TextDecoder().decode(opened.body), "ok");
});
