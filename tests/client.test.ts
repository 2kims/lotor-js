import assert from "node:assert/strict";
import test from "node:test";

import {
  LotorBrowserClient,
  LotorBrowserError,
  MemoryTokenStore,
  createSubjectKeyRegistration,
  groupResourcesByType,
  type BrowserFetch,
  type TokenStore,
} from "../src/index.js";

interface RecordedRequest { url: string; init: RequestInit }

test("downloads payload bytes with integrity checks and isolated storage transport", async () => {
  const bytes = new TextEncoder().encode("payload");
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
  const lease = { resource: "vault:one", slot: "content", payloadVersion: 1, representation: "raw" as const, objectDigest: digest, objectSize: bytes.length, downloadUrl: "https://objects.test/file", downloadMethod: "GET" as const, expiresAt: 9999999999, audience: "alice", resourceRevision: 1, lifecycleGeneration: 1 };
  let calls = 0;
  let body: Uint8Array<ArrayBuffer> = bytes;
  const sdk = new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "app", publishableKey: "pk", fetch: async (url, init = {}) => {
    calls++;
    assert.equal(String(url), lease.downloadUrl);
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    assert.deepEqual([...new Headers(init.headers).entries()], []);
    return new Response(body);
  } });
  assert.deepEqual(await sdk.downloadResourcePayload(lease), bytes);
  await assert.rejects(sdk.downloadResourcePayload({ ...lease, objectDigest: "0".repeat(64) }), /digest/);
  body = new Uint8Array(bytes.length + 1);
  await assert.rejects(sdk.downloadResourcePayload(lease), /size/);
  body = new Uint8Array(0);
  await assert.rejects(sdk.downloadResourcePayload(lease), /size/);
  const beforeInvalid = calls;
  await assert.rejects(sdk.downloadResourcePayload({ ...lease, downloadUrl: "http://objects.test/file" }));
  await assert.rejects(sdk.downloadResourcePayload({ ...lease, objectSize: 64 * 1024 * 1024 + 1 }));
  await assert.rejects(sdk.downloadResourcePayload(lease, { signal: AbortSignal.abort() }));
  const intent = { resource: "vault:one", slot: "content", payloadVersion: 1, expectedPayloadVersion: 0, uploadUrl: "https://objects.test/upload", uploadMethod: "PUT" as const, expiresAt: 99, requiredHeaders: {} };
  for (const name of ["Authorization", "Cookie", "Lotor-Payload-Token", "X-Lotor-Secret-Key"]) await assert.rejects(sdk.uploadResourcePayloadObject({ ...intent, requiredHeaders: { [name]: "private" } }, bytes));
  assert.equal(calls, beforeInvalid);
});

function response(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function resourceLinkResult(keyRequirements: unknown[] = [], status = "ready") {
  return {
    resource: "vault:one", status, expires_at: 123, idempotent: false, committable: status === "ready",
    revisions: { customer: "customer", graph: "1", policy: "policy", identity: "identity", billing: "0", seat: "0", key: "key" },
    outcomes: [{ resource: "vault:one", subject: "user:bob", relation: "member", state: keyRequirements.length ? "pending_encryption" : "active", allowed: true }],
    capacity: { scope: "per_organization", before: 0, after: 0, claim: 0, release: 0 },
    billing: { current_quantity: 0, next_cycle_quantity: 0, increase: 0, next_cycle_reduction: 0 },
    invitation_actions: [], key_requirements: keyRequirements,
    impact: { impacted_resources: ["vault:one"], retained_resources: [], rekey_resources: [] },
  };
}

function fixtureFetch(requests: RecordedRequest[]): BrowserFetch {
  return async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === "https://objects.test/upload") return response(undefined, 200);
    if (url.endsWith("/auth/passwordless/start")) return response({ challenge_id: "plc_1", delivery: "email", expires_at: 123 });
    if (url.endsWith("/auth/passwordless/verify")) return response({ subject: "user_1", email: "founder@example.test", access_token: "opaque-token" });
    if (url.endsWith("/session") && init.method === "DELETE") return response(undefined, 204);
    if (url.endsWith("/session")) return response({ authenticated: true, subject: "user_1", email: "founder@example.test" });
    if (url.endsWith("/organizations") && init.method === "POST") return response({ id: "org_2", name: "Acme Operations", current_role: "owner", member_count: 1, pending_invites: 0 }, 201);
    if (url.endsWith("/organizations")) return response([{ id: "org_1", name: "Personal Workspace", current_role: "owner", member_count: 1, pending_invites: 0 }]);
    if (url.endsWith("/me/resources?parent=project%3Aexample&type=vault")) return response({ resources: [], next_cursor: null });
    if (url.endsWith("/me/resources?type=organization&type=vault&access_state=active&limit=25")) return response({ resources: [
      { id: "res_org", resource: "organization:res_org", type: "organization", name: "Personal Workspace", relations: ["member"], access_state: "active", access: { direct: false, paths: [{ type: "group", relation: "member", via: [{ id: "res_group", resource: "group:res_group", type: "group", name: "Engineering", subject_relation: "member" }] }] } },
      { id: "res_vault", resource: "vault:res_vault", type: "vault", name: "Production", parent: { id: "res_org", resource: "organization:res_org", type: "organization", name: "Personal Workspace" }, relations: ["owner"], access_state: "active", access: { direct: true, paths: [{ type: "direct", relation: "owner", via: [] }] } },
    ], next_cursor: "next_resources" });
    if (url.endsWith("/me/invitations?limit=25")) return response({ invitations: [{ id: "cinv_1", resource: { id: "res_1", resource: "vault:res_1", type: "vault", name: "Production" }, relation: "member", status: "pending_acceptance", expires_at: 123, encryption_required: true }], next_cursor: "next_1" });
    if (url.endsWith("/me/invitations/cinv_1/accept")) return response({ id: "cinv_1", status: "active" });
    if (url.endsWith("/me/invitations/cinv_2/decline")) return response({ id: "cinv_2", status: "declined" });
    if (url.endsWith("/billing/checkout-sessions")) return response({ id: "cs_1", presentation: "custom", client_secret: "cs_test_secret", publishable_key: "pk_test_public" }, 201);
    if (url.endsWith("/resources/vault%3Aone/links/preflight")) return response(resourceLinkResult([{
      manifest_item_id: "item_1", grant_id: "lenv_1", resource: "vault:one", relation: "member", key_resource: "vault:one", key_version: "1",
      recipient_subject: "user:bob", recipient_key_id: "key_1", encryption_algorithm: "X25519",
      public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }]), 200, { "Lotor-Link-Token": "abcdefghijklmnopqrstuvwxyzABCDEFGH12345678" });
    if (url.endsWith("/resources/vault%3Aone/collaborators?view=effective")) return response({ resource: "vault:one", collaborators: [{ kind: "invitation", id: "cinv_1", link_id: "lnk_1", relations: ["member"], status: "pending_acceptance", recipient: { type: "email", display: "kim@example.com" }, expires_at: 123 }], next_cursor: null });
    if (url.endsWith("/resources/personal-bcc69c42b94e9d215af82ddb/collaborators?view=effective")) return response({ resource: "personal-bcc69c42b94e9d215af82ddb", collaborators: [{ kind: "invitation", id: "cinv_1", link_id: "lnk_1", relations: ["member"], status: "pending_acceptance", recipient: { type: "email", display: "kim@example.com" }, expires_at: 123 }], next_cursor: null });
    if (url.includes("/resources/vault%3Aone/collaborators?view=effective&email=kim%40example.com")) return response({ resource: "vault:one", collaborators: [{ kind: "user", id: "user:kim", email: "kim@example.com", relations: ["member"], status: "active", access: { direct: false, paths: [{ type: "group", relation: "member", group: "group:engineering", subject_relation: "member", via: [{ resource: "group:engineering", subject_relation: "member" }] }] } }], next_cursor: null });
    if (url.endsWith("/resources/search")) return response({ resources: [{ resource: "vault:one", resource_type: "vault", display_name: "Production", status: "active", parent: { resource: "project:platform", resource_type: "project", display_name: "Platform" }, collaborator_matches: [{ kind: "user", id: "user:kim", email: "kim@example.com", relations: ["member"], status: "active", access: { direct: false, paths: [{ type: "group", relation: "member", group: "group:engineering", subject_relation: "member", via: [{ resource: "group:engineering", subject_relation: "member" }] }] } }] }], next_cursor: "next_search" });
    if (url.endsWith("/resources/group%3Aincident-commanders") && init.method === "PUT") return response({ id: "res_group", resource: "group:incident-commanders", resource_type: "group", display_name: "Incident Commanders", parent: "org:acme", status: "pending_encryption", revision: 1, lifecycle_generation: 1, encryption: { required: true, status: "provisioning", key_scope: "resource", effective_key_resource: "group:incident-commanders" } }, 202);
    if (url.endsWith("/resources/group%3Aincident-commanders")) return response({ id: "res_group", resource: "group:incident-commanders", resource_type: "group", display_name: "Incident Commanders", parent: "org:acme", status: "active", revision: 1, lifecycle_generation: 1, encryption: { required: true, status: "ready", key_scope: "resource", effective_key_resource: "group:incident-commanders", key_resource: "group:incident-commanders", key_version: 1 } });
    if (url.endsWith("/resources/vault%3Aone/payloads/content/uploads")) return response({ resource: "vault:one", slot: "content", payload_version: 3, expected_payload_version: 0, upload_url: "https://objects.test/upload", upload_method: "PUT", required_headers: { "x-amz-meta-sha256": "abc" }, expires_at: 123 }, 201, { "Lotor-Payload-Token": "payload-token" });
    if (url.endsWith("/resources/vault%3Aone/payloads/content/commits")) return response({ resource: "vault:one", slot: "content", schema_id: "av.vault.v1", payload_version: 1, representation: "encrypted-envelope-v1", object_digest: "a".repeat(64), object_size: 64, encryption_suite: "AES-256-GCM", key_binding_ref: "vault:one", key_version: 1, wrapped_payload_key: "wrapped", aad_hash: "aad", encryptor_subject: "user:owner", encryptor_key_id: "key_1", resource_revision: 1, lifecycle_generation: 1, state: "committed", committed_at: 123 });
    if (url.endsWith("/resources/vault%3Aone/payloads/content/access")) return response({ resource: "vault:one", slot: "content", payload_version: 1, representation: "encrypted-envelope-v1", object_digest: "a".repeat(64), object_size: 64, download_url: "https://objects.test/download", download_method: "GET", expires_at: 123, audience: "user:owner", resource_revision: 1, lifecycle_generation: 1 });
    if (url.endsWith("/resources/vault%3Aone/payloads/content/rewraps")) return response({ resource: "vault:one", slot: "content", payload_version: 1, wrap_revision: 1, key_binding_ref: "vault:one", previous_key_version: 1, key_version: 2, wrapped_payload_key: "new-wrap", aad_hash: "A".repeat(43), rewrapper_subject: "service_account:box", rewrapper_key_id: "box-key", resource_revision: 1, lifecycle_generation: 1 });
	if (url.endsWith("/resources/vault%3Aone/payloads/content") && init.method === "DELETE") return response({ resource: "vault:one", slot: "content", payload_version: 1, state: "deleting", idempotent: false }, 202);
	if (url.endsWith("/resources/vault%3Aone/move")) return response({ id: "op_move", kind: "resource_move", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "a".repeat(64), created_at: 1, updated_at: 1 }, 202);
	if (url.endsWith("/resources/vault%3Aone/disable")) return response({ id: "op_disable", kind: "resource_disable", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "b".repeat(64), created_at: 1, updated_at: 1 }, 202);
	if (url.endsWith("/resources/vault%3Aone/restore")) return response({ id: "op_restore", kind: "resource_restore", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "c".repeat(64), created_at: 1, updated_at: 1 }, 202);
	if (url.endsWith("/resources/vault%3Aone") && init.method === "DELETE") return response({ id: "op_delete", kind: "resource_delete", status: "pending", target_kind: "resource", target_id: "vault:one", request_hash: "d".repeat(64), created_at: 1, updated_at: 1 }, 202);
	if (url.endsWith("/operations/op_move")) return response({ id: "op_move", kind: "resource_move", status: "succeeded", target_kind: "resource", target_id: "vault:one", request_hash: "a".repeat(64), created_at: 1, updated_at: 2 });
    if (url.endsWith("/invitations/accept")) return response({ id: "cinv_1", resource: "vault:one", relation: "member", recipient: { type: "email" }, status: "active", idempotent: false });
    return response({ error: "not found" }, 404);
  };
}

function client(requests: RecordedRequest[], tokenStore?: TokenStore): LotorBrowserClient {
  return new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    publishableKey: "lp_sbx_test",
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
  assert.ok(requests.every(({ init }) => new Headers(init.headers).get("X-Lotor-Publishable-Key") === "lp_sbx_test"));
  assert.equal(new Headers(requests[0]?.init.headers).has("Authorization"), false);
  assert.equal(new Headers(requests[2]?.init.headers).get("Authorization"), "Bearer opaque-token");
  assert.ok(requests.every(({ init }) => init.credentials === "omit"));
});

test("uses relative cookie-only gateway requests in same-origin mode", async () => {
  const requests: RecordedRequest[] = [];
  const fetcher: BrowserFetch = async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, init });
    if (url.endsWith("/auth/passwordless/start")) return response({ challenge_id: "plc_gateway", delivery: "email", expires_at: 123 });
    if (url.endsWith("/auth/passwordless/verify")) return response({ authenticated: true, subject: "user_gateway", csrf_token: "csrf-proof", expires_at: 456 });
    if (url.endsWith("/session") && init.method === "DELETE") return response(undefined, 204);
    if (url.endsWith("/session")) return response({ authenticated: true, subject: "user_gateway", expires_at: 456 });
    if (url.endsWith("/organizations") && init.method === "POST") return response({ id: "org_gateway", name: "Gateway Org", current_role: "owner", member_count: 1, pending_invites: 0 }, 201);
    return response({ error: "not found" }, 404);
  };
  const sdk = new LotorBrowserClient({
    mode: "same-origin", clientId: "signalbox_web", publishableKey: "lp_sbx_test", fetch: fetcher, csrfToken: () => "csrf-proof",
  });
  const challenge = await sdk.startPasswordless("founder@example.test");
  assert.deepEqual(await sdk.verifyPasswordless(challenge.challenge_id, "111111"), {
    authenticated: true, subject: "user_gateway",
  });
  assert.deepEqual(await sdk.session(), { authenticated: true, subject: "user_gateway" });
  await sdk.createOrganization("Gateway Org", "create-org-1");
  await sdk.logout();
  assert.deepEqual(requests.map(({ url }) => url), [
    "/.lotor/v1/auth/passwordless/start",
    "/.lotor/v1/auth/passwordless/verify",
    "/.lotor/v1/session",
    "/.lotor/v1/organizations",
    "/.lotor/v1/session",
  ]);
  assert.ok(requests.every(({ init }) => init.credentials === "same-origin"));
  assert.ok(requests.every(({ init }) => new Headers(init.headers).get("X-Lotor-Publishable-Key") === "lp_sbx_test"));
  assert.ok(requests.every(({ init }) => !new Headers(init.headers).has("Authorization")));
  assert.equal(new Headers(requests[3]?.init.headers).get("X-Lotor-CSRF"), "csrf-proof");
  assert.equal(new Headers(requests[4]?.init.headers).get("X-Lotor-CSRF"), "csrf-proof");
});

test("same-origin mutations fail before fetch when CSRF proof is unavailable", async () => {
  let called = false;
  const sdk = new LotorBrowserClient({
    mode: "same-origin", clientId: "signalbox_web", publishableKey: "lp_sbx_test", csrfToken: () => null,
    fetch: async () => { called = true; return response(undefined, 204); },
  });
  await assert.rejects(sdk.logout(), (error: unknown) =>
    error instanceof LotorBrowserError && error.code === "csrf_unavailable");
  assert.equal(called, false);
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

test("uses a fixed payload token header for an encrypted object", async () => {
  const requests: RecordedRequest[] = [];
  const sdk = client(requests);
  await sdk.verifyPasswordless("plc_1", "111111");
  const intent = await sdk.createResourcePayloadUpload("vault:one", "content", {
    schemaId: "av.vault.v1", representation: "encrypted-envelope-v1", expectedPayloadVersion: 0, objectDigest: "a".repeat(64), objectSize: 64,
    encryptionSuite: "AES-256-GCM", keyBindingRef: "vault:one", keyVersion: 1,
    wrappedPayloadKey: "wrapped", aadHash: "A".repeat(43), encryptorSubject: "user:owner", encryptorKeyId: "key_1", encryptionReceipt: "receipt",
    resourceRevision: 1, lifecycleGeneration: 1,
  });
  assert.equal(intent.token, "payload-token");
  await sdk.uploadResourcePayloadObject(intent, new Uint8Array([1, 2, 3]));
  assert.equal(requests.at(-1)?.url, "https://objects.test/upload");
  assert.equal(requests.at(-1)?.init.credentials, "omit");
  assert.equal(requests.at(-1)?.init.redirect, "error");
  assert.equal(new Headers(requests.at(-1)?.init.headers).has("Authorization"), false);
  await sdk.commitResourcePayload("vault:one", "content", intent);
  assert.equal(new Headers(requests.at(-1)?.init.headers).get("Lotor-Payload-Token"), "payload-token");
  assert.equal((JSON.parse(String(requests.at(-1)?.init.body)) as Record<string, unknown>).expected_payload_version, 0);
  assert.equal((await sdk.accessResourcePayload("vault:one", "content")).downloadUrl, "https://objects.test/download");
  const rewrap = await sdk.rewrapResourcePayload("vault:one", "content", {
    payloadVersion: 1, expectedWrapRevision: 0, keyBindingRef: "vault:one",
    previousKeyVersion: 1, keyVersion: 2, resourceRevision: 1, lifecycleGeneration: 1,
  });
  assert.equal(rewrap.wrapRevision, 1);
  assert.equal(rewrap.wrappedPayloadKey, "new-wrap");
  const rewrapBody = JSON.parse(String(requests.at(-1)?.init.body)) as Record<string, unknown>;
  assert.equal(rewrapBody.previous_key_version, 1);
  assert.equal("wrapped_payload_key" in rewrapBody, false);
  assert.equal((await sdk.deleteResourcePayload("vault:one", "content", "delete-content-1")).state, "deleting");
});

test("uploads raw objects without inventing encryption custody metadata", async () => {
  const requests: RecordedRequest[] = [];
  const sdk = client(requests);
  await sdk.verifyPasswordless("plc_1", "111111");
  const intent = await sdk.createResourcePayloadUpload("vault:one", "content", {
    schemaId: "av.vault.v1", representation: "raw", expectedPayloadVersion: 0,
    objectDigest: "a".repeat(64), objectSize: 3, resourceRevision: 1, lifecycleGeneration: 1,
  });
  const body = JSON.parse(String(requests.at(-1)?.init.body)) as Record<string, unknown>;
  assert.equal(body.representation, "raw");
  assert.equal(body.object_digest, "a".repeat(64));
  assert.equal("encryption_suite" in body, false);
  assert.equal("key_binding_ref" in body, false);
  assert.equal("encryption_receipt" in body, false);
  await sdk.uploadResourcePayloadObject(intent, new Uint8Array([1, 2, 3]));
});

test("uses the production resource lifecycle signatures and durable operation polling", async () => {
	const requests: RecordedRequest[] = [];
	const sdk = client(requests);
	await sdk.verifyPasswordless("plc_1", "111111");
	const fence = { expectedRevision: 7, expectedLifecycleGeneration: 11 };
	assert.equal((await sdk.moveResource("vault:one", { ...fence, parent: "project:two" }, "move-1")).id, "op_move");
	assert.equal((await sdk.disableResource("vault:one", fence, "disable-1")).id, "op_disable");
	assert.equal((await sdk.restoreResource("vault:one", fence, "restore-1")).id, "op_restore");
	assert.equal((await sdk.deleteResource("vault:one", { ...fence, subtree: true }, "delete-1")).id, "op_delete");
	assert.equal((await sdk.operation("op_move")).status, "succeeded");
	const move = requests.find(({ url }) => url.endsWith("/resources/vault%3Aone/move"));
	assert.deepEqual(JSON.parse(String(move?.init.body)), {
		expected_revision: 7, expected_lifecycle_generation: 11, parent: "project:two",
	});
	assert.equal(new Headers(move?.init.headers).get("Idempotency-Key"), "move-1");
	const deletion = requests.find(({ url, init }) => url.endsWith("/resources/vault%3Aone") && init.method === "DELETE");
	assert.deepEqual(JSON.parse(String(deletion?.init.body)), {
		expected_revision: 7, expected_lifecycle_generation: 11, subtree: true,
	});
});

test("keeps the payload credential out of JavaScript in same-origin gateway mode", async () => {
  const requests: RecordedRequest[] = [];
  const fetcher: BrowserFetch = async (input, init = {}) => {
    requests.push({ url: String(input), init });
    if (String(input).endsWith("/uploads")) return response({ resource: "vault:one", slot: "content", payload_version: 3, expected_payload_version: 0, upload_url: "https://objects.test/upload", upload_method: "PUT", required_headers: {}, expires_at: 123 }, 201);
    return response({ resource: "vault:one", slot: "content", schema_id: "av.vault.v1", payload_version: 1, representation: "encrypted-envelope-v1", object_digest: "a".repeat(64), object_size: 64, encryption_suite: "AES-256-GCM", key_binding_ref: "vault:one", key_version: 1, wrapped_payload_key: "wrapped", aad_hash: "aad", encryptor_subject: "user:owner", encryptor_key_id: "key_1", resource_revision: 1, lifecycle_generation: 1, state: "committed", committed_at: 123 });
  };
  const sdk = new LotorBrowserClient({ mode: "same-origin", clientId: "signalbox_web", publishableKey: "lp_sbx_test", fetch: fetcher, csrfToken: () => "csrf" });
  const intent = await sdk.createResourcePayloadUpload("vault:one", "content", {
    schemaId: "av.vault.v1", representation: "encrypted-envelope-v1", expectedPayloadVersion: 0, objectDigest: "a".repeat(64), objectSize: 64,
    encryptionSuite: "AES-256-GCM", keyBindingRef: "vault:one", keyVersion: 1,
    wrappedPayloadKey: "wrapped", aadHash: "A".repeat(43), encryptorSubject: "user:owner", encryptorKeyId: "key_1", encryptionReceipt: "receipt",
    resourceRevision: 1, lifecycleGeneration: 1,
  });
  assert.equal(intent.token, undefined);
  await sdk.commitResourcePayload("vault:one", "content", intent);
  assert.equal(new Headers(requests.at(-1)?.init.headers).has("Lotor-Payload-Token"), false);
  assert.ok(requests.every(({ init }) => init.credentials === "same-origin"));
});

test("maps missing and rejected sessions to anonymous and clears stale tokens", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("stale");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    publishableKey: "lp_sbx_test",
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

test("creates organizations and child resources through authenticated public operations", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  assert.equal((await sdk.createOrganization("Acme Operations", "create-org-1")).id, "org_2");
  const group = await sdk.putResource("group:incident-commanders", { resourceType: "group", displayName: "Incident Commanders", parent: "org:acme", keyScope: "resource" });
  assert.equal(group.parent, "org:acme");
  assert.equal(group.status, "pending_encryption");
  assert.deepEqual(group.encryption, { required: true, status: "provisioning", keyScope: "resource", effectiveKeyResource: "group:incident-commanders" });
  assert.equal(new Headers(requests[0]?.init.headers).get("Idempotency-Key"), "create-org-1");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { name: "Acme Operations" });
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), { resource_type: "group", display_name: "Incident Commanders", parent: "org:acme", key_scope: "resource" });
  assert.equal((await sdk.resource("group:incident-commanders")).encryption.status, "ready");
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

test("preflights resource links and captures the server token outside the JSON body", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const result = await client(requests, tokenStore).preflightResourceLinks("vault:one", [{
    action: "grant", relation: "member", subject: "user:bob", provisioning: "existing_only", delivery: "none",
  }]);
  assert.equal(result.result.keyRequirements[0]?.grantId, "lenv_1");
  assert.equal(result.result.keyRequirements[0]?.publicKey.length, 32);
  assert.equal(result.token, "abcdefghijklmnopqrstuvwxyzABCDEFGH12345678");
  assert.equal(new Headers(requests[0]?.init.headers).get("Idempotency-Key"), null);
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { changes: [{ action: "grant", relation: "member", subject: "user:bob", provisioning: "existing_only", delivery: "none" }] });
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/resources/vault%3Aone/links/preflight");
});

test("keeps the gateway link token in its strict cookie and out of browser JavaScript", async () => {
  const requests: RecordedRequest[] = [];
  const fetcher: BrowserFetch = async (raw, init = {}) => {
    const url = String(raw);
    requests.push({ url, init });
    if (url.endsWith("/resources/vault%3Aone/links/preflight")) return response(resourceLinkResult());
    if (url.endsWith("/resources/vault%3Aone/links/commit")) return response(resourceLinkResult([], "active"));
    return response({ error: "not found" }, 404);
  };
  const sdk = new LotorBrowserClient({
    mode: "same-origin", clientId: "signalbox_web", publishableKey: "lp_sbx_test", fetch: fetcher, csrfToken: () => "csrf-proof",
  });
  const sent = await sdk.sendResourceLinks("vault:one", { changes: [{
    action: "grant", relation: "member", subject: "user:bob",
    provisioning: "existing_only", delivery: "none",
  }] });
  assert.equal(sent.preflight.token, undefined);
  assert.equal(requests[0]?.url, "/.lotor/v1/resources/vault%3Aone/links/preflight");
  assert.equal(requests[1]?.url, "/.lotor/v1/resources/vault%3Aone/links/commit");
  assert.equal(new Headers(requests[1]?.init.headers).get("Lotor-Link-Token"), null);
});

test("lets Lotor manage E2EE resource-link material without exposing keys to the SDK", async () => {
  const requests: RecordedRequest[] = [];
  let requirements: unknown[] = [];
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (raw, init = {}) => {
      const url = String(raw);
      requests.push({ url, init });
      if (url.endsWith("/links/preflight")) return response(resourceLinkResult(requirements), 200, { "Lotor-Link-Token": "abcdefghijklmnopqrstuvwxyzABCDEFGH12345678" });
      if (url.endsWith("/links/commit")) return response(resourceLinkResult([], "active"));
      return response({ error: "not found" }, 404);
    },
  });
  const changes = [{
    action: "grant" as const, relation: "member", subject: "user:bob",
    provisioning: "existing_only" as const, delivery: "none" as const,
  }];

  assert.equal((await sdk.sendResourceLinks("organization:one", { changes })).committed.status, "active");
  requirements = [{
    manifest_item_id: "item_1", grant_id: "grant_1", resource: "vault:one", relation: "member",
    key_resource: "incident:one", key_version: "1", recipient_subject: "user:bob",
    recipient_key_id: "key_bob", encryption_algorithm: "X25519",
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  }];
  assert.equal((await sdk.sendResourceLinks("incident:one", { changes })).committed.status, "active");
  requirements.push({
    manifest_item_id: "item_2", grant_id: "grant_2", resource: "vault:one", relation: "member",
    key_resource: "incident:two", key_version: "1", recipient_subject: "user:bob",
    recipient_key_id: "key_bob", encryption_algorithm: "X25519",
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  assert.equal((await sdk.sendResourceLinks("incident:one", { changes })).committed.status, "active");
  assert.equal(requests.filter(({ url }) => url.endsWith("/links/commit")).length, 3);
  for (const request of requests.filter(({ url }) => url.endsWith("/links/commit"))) {
    assert.deepEqual(JSON.parse(String(request.init.body)), {});
  }
});

test("exposes browser E2EE policy session and resumable action signatures", async () => {
  const requests: RecordedRequest[] = [];
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const keyRequirement = {
    manifest_item_id: "grant_browser", grant_id: "grant_browser", resource: "vault:one", relation: "viewer",
    associated_data: "Y29udGV4dA",
    key_resource: "vault:one", key_version: "1", recipient_subject: "user:bob", recipient_key_id: "key_bob",
    encryption_algorithm: "X25519", public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (raw, init = {}) => {
      const url = String(raw); requests.push({ url, init });
      if (url.endsWith("/resources/organization%3Aone/e2ee")) return response({ organization: "organization:one", required_account_custody: "browser_passphrase", resource_key_executor: "browser", automation_executor: "none", resource_key_policy: "organization_default", status: "ready", revision: 2 });
      if (url.endsWith("/key-access/resource-envelope")) return response({ resource: "vault:one", key_resource: "vault:one", key_version: 1,
        encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM", ephemeral_public_key: "ephemeral", nonce: "nonce", ciphertext: "ciphertext",
        associated_data: "aad", aad_hash: "0".repeat(64), expires_at: 123 });
      if (url.endsWith("/me/encryption-actions")) return response({ actions: [{ id: "rkj_one", kind: "envelope_rewrap", resource: "vault:one", status: "awaiting_browser", revision: "a".repeat(64), key_requirements: [keyRequirement] }] });
      if (url.endsWith("/me/encryption-actions/rkj_one/complete")) return response({ id: "rkj_one", status: "projecting", idempotent: false });
      return response({ error: "not found" }, 404);
    },
  });
  assert.equal((await sdk.organizationE2EEPolicy("organization:one")).resourceKeyExecutor, "browser");
  await sdk.configureOrganizationE2EE("organization:one", { requiredAccountCustody: "browser_passphrase", resourceKeyExecutor: "browser", automationExecutor: "none", resourceKeyPolicy: "organization_default" });
  assert.equal((await sdk.resourceSessionEnvelope("vault:one", "A".repeat(43), "client-nonce-123456")).associatedData, "aad");
  const actions = await sdk.encryptionActions();
  assert.equal(actions[0]?.keyRequirements[0]?.resource, "vault:one");
  assert.deepEqual(actions[0]?.keyRequirements[0]?.associatedData, new TextEncoder().encode("context"));
  const envelope = { manifestItemId: "grant_browser", encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM" as const,
    ciphertext: "ciphertext", aadHash: "aad", issuer: "user:owner", issuerKeyId: "key_owner", signature: "signature" };
  assert.equal((await sdk.completeEncryptionAction("rkj_one", "a".repeat(64), [envelope])).status, "projecting");
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), { required_account_custody: "browser_passphrase", resource_key_executor: "browser", automation_executor: "none", resource_key_policy: "organization_default" });
  assert.deepEqual(JSON.parse(String(requests[4]?.init.body)).envelopes[0], {
    manifest_item_id: "grant_browser", encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM", ciphertext: "ciphertext",
    aad_hash: "aad", issuer: "user:owner", issuer_key_id: "key_owner", signature: "signature",
  });
});

test("completes a browser encryption action from an in-memory resource key", async () => {
  const requests: RecordedRequest[] = [];
  const enrolled = await createSubjectKeyRegistration({ clientId: "signalbox_web", subject: "user:owner", passphrase: "correct horse battery staple", backupPrivateKeys: false });
  const action = {
    id: "rkj_create", kind: "resource_key_create" as const, resource: "project:one", status: "awaiting_browser" as const,
    revision: "a".repeat(64), keyRequirements: [{
      manifestItemId: "owner_grant", grantId: "owner_grant", resource: "project:one", relation: "owner",
      associatedData: new TextEncoder().encode(["lotor-resource-envelope-v1", "tenant", "app", "env", "project:one", "1", "user:owner", enrolled.keys.keyId, "1", "2", "3", "4", "5"].join("\0")),
      keyResource: "project:one", keyVersion: "1", recipientSubject: "user:owner", recipientKeyId: enrolled.keys.keyId,
      encryptionAlgorithm: "X25519" as const, publicKey: new Uint8Array(Buffer.from(enrolled.request.encryption_public_key, "base64url")),
    }],
  };
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (raw, init = {}) => {
      requests.push({ url: String(raw), init });
      if (String(raw).endsWith("/session")) return response({ authenticated: true, subject: "user:owner", email: "owner@example.test" });
      return response({ id: action.id, status: "projecting", idempotent: false }, 202);
    },
  });
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    assert.equal((await sdk.completeEncryptionActionWithResourceKey(action, resourceKey, enrolled.keys)).status, "projecting");
    const body = JSON.parse(String(requests[1]?.init.body));
    assert.equal(body.revision, action.revision);
    assert.equal(body.envelopes.length, 1);
    assert.equal(body.envelopes[0].manifest_item_id, "owner_grant");
    assert.equal(body.envelopes[0].issuer, "user:owner");
  } finally {
    resourceKey.fill(0);
  }
});

test("uses URL-safe organization IDs for collaborator calls and accepts resource invitations", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  const listed = await sdk.resourceCollaborators("personal-bcc69c42b94e9d215af82ddb", { view: "effective" });
  assert.equal(listed.collaborators[0]?.linkId, "lnk_1");
  assert.equal((await sdk.acceptResourceInvitation("ticket_1")).status, "active");
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/resources/personal-bcc69c42b94e9d215af82ddb/collaborators?view=effective");
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), { ticket: "ticket_1" });
});

test("searches collaborators and manageable resources with group path context", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  const collaborators = await sdk.resourceCollaborators("vault:one", {
    view: "effective", email: "kim@example.com", viaGroup: "group:engineering",
    kinds: ["user"], relations: ["member"], limit: 25,
  });
  assert.equal(collaborators.collaborators[0]?.access?.paths[0]?.group, "group:engineering");
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/resources/vault%3Aone/collaborators?view=effective&email=kim%40example.com&via_group=group%3Aengineering&kind=user&relation=member&limit=25");

  const resources = await sdk.searchResources({
    filters: {
      resource: { types: ["vault"] },
      collaborator: { email: "kim@example.com", view: "effective", viaGroups: ["group:engineering"] },
    },
    include: ["parent", "collaborator_matches"],
    sort: { field: "resource", direction: "asc" },
    page: { limit: 25 },
  });
  assert.equal(resources.resources[0]?.parent?.resource, "project:platform");
  assert.equal(resources.resources[0]?.collaboratorMatches?.[0]?.access?.paths[0]?.group, "group:engineering");
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), {
    filters: {
      resource: { types: ["vault"] },
      collaborator: { email: "kim@example.com", view: "effective", via_groups: ["group:engineering"] },
    },
    include: ["parent", "collaborator_matches"],
    sort: { field: "resource", direction: "asc" },
    page: { limit: 25 },
  });
});

test("resource collaboration discovery preserves service-account graph principals", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (input, init = {}) => {
      requests.push({ url: String(input), init });
      if (String(input).endsWith("/link-candidates/search")) return response({ candidates: [{ kind: "service_account", resource: "service_account:deploy", display_name: "Deploy", link_state: "available", selectable: true }], next_cursor: null });
      return response({ resource: "vault:one", collaborators: [{ kind: "service_account", id: "service_account:deploy", resource: "service_account:deploy", relations: ["operator"], status: "active" }], next_cursor: null });
    },
  });
  const candidates = await sdk.searchResourceLinkCandidates("vault:one", { query: "dep", relation: "operator", kinds: ["service_account"] });
  assert.equal(candidates.candidates[0]?.kind, "service_account");
  assert.equal((await sdk.resourceCollaborators("vault:one", { kind: "service_account" })).collaborators[0]?.kind, "service_account");
  await assert.rejects(sdk.searchResourceLinkCandidates("vault:one", { query: "d", relation: "operator" }));
  assert.equal(requests.length, 2);
});

test("resource guest policy keeps public camelCase types and canonical wire fields", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (input, init = {}) => { requests.push({ url: String(input), init }); return response({ resource: "vault:one", revision: 2 }); } });
  assert.equal((await sdk.setResourceCollaborationPolicy("vault:one", { guests: { allowed: true, allowedDomains: ["example.com"] } })).revision, 2);
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { guests: { allowed: true, allowed_domains: ["example.com"] } });
  await assert.rejects(sdk.setResourceCollaborationPolicy("vault:one", { guests: {} }));
  await assert.rejects(sdk.setResourceCollaborationPolicy("vault:one", { guests: { allowedDomains: [] } }));
  assert.equal(requests.length, 1);
});

test("lists the authenticated invitation inbox with canonical resource references", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const listed = await client(requests, tokenStore).accountInvitations({ limit: 25 });
  assert.deepEqual(listed, { invitations: [{ id: "cinv_1", resource: { id: "res_1", resource: "vault:res_1", type: "vault", name: "Production" }, relation: "member", status: "pending_acceptance", expiresAt: 123, encryptionRequired: true }], nextCursor: "next_1" });
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/me/invitations?limit=25");
  assert.equal(new Headers(requests[0]?.init.headers).get("Authorization"), "Bearer token");
  assert.deepEqual(await client(requests, tokenStore).acceptAccountInvitation("cinv_1"), { id: "cinv_1", status: "active" });
  assert.deepEqual(await client(requests, tokenStore).declineAccountInvitation("cinv_2"), { id: "cinv_2", status: "declined" });
  assert.equal(requests[1]?.init.method, "POST");
  assert.equal(requests[2]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/me/invitations/cinv_2/decline");
  await assert.rejects(client([], tokenStore).accountInvitations({ limit: 0 }), /limit/);
});

test("lists and generically groups the authenticated account resource directory", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const listed = await client(requests, tokenStore).accountResources({ types: ["organization", "vault"], accessStates: ["active"], limit: 25 });
  assert.equal(listed.resources[0]?.access.paths[0]?.via[0]?.id, "res_group");
  assert.equal(listed.resources[0]?.access.paths[0]?.via[0]?.resource, "group:res_group");
  assert.equal(listed.resources[1]?.resource, "vault:res_vault");
  assert.equal(listed.resources[1]?.parent?.resource, "organization:res_org");
  assert.equal(listed.resources[1]?.parent?.id, "res_org");
  assert.deepEqual(groupResourcesByType(listed.resources).map(group => [group.type, group.resources.length]), [["organization", 1], ["vault", 1]]);
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/me/resources?type=organization&type=vault&access_state=active&limit=25");
  await assert.rejects(client([], tokenStore).accountResources({ limit: 101 }), /limit/);
  await client(requests, tokenStore).accountResources({ parent: "project:example", types: ["vault"] });
  assert.equal(requests[1]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/me/resources?parent=project%3Aexample&type=vault");
  await assert.rejects(client([], tokenStore).accountResources({ parent: "" }), /parent/);
});

test("rejects an account invitation response missing its canonical resource reference", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async () => response({ invitations: [{ id: "cinv_1", resource: { id: "organization:internal-secret", type: "organization", name: "Personal Workspace" }, relation: "member", status: "pending_acceptance", expires_at: 123, encryption_required: false }], next_cursor: null }),
  });
  await assert.rejects(sdk.accountInvitations(), /invalid account invitation resource resource response/);
});

test("reads resource-bound catalog entries with user authority and no application secret", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("user-session");
  const requests: RecordedRequest[] = [];
  const entry = { id: "entry_1", catalog_id: "catalog_1", semantic_key: "send", entry_kind: "api.operation", revision_id: "revision_1", revision_digest: "a".repeat(64), definition: { method: "POST", path: "/messages" } };
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "app", publishableKey: "lp_sbx_test", tokenStore,
    fetch: async (input, init = {}) => {
      requests.push({ url: String(input), init });
      return response(String(input).includes("/entries/entry_1?") ? entry : { items: [entry], next_cursor: "next" });
    },
  });
  const page = await sdk.resourceCatalogEntries("vault:one", "catalog_1", { limit: 1 });
  assert.equal(page.items[0]?.revisionId, "revision_1");
  assert.equal(page.nextCursor, "next");
  assert.equal((await sdk.resourceCatalogEntry("vault:one", "catalog_1", "entry_1")).semanticKey, "send");
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/app/catalogs/catalog_1/entries?resource=vault%3Aone&limit=1");
  assert.equal(requests[1]?.url, "https://api.lotor.test/v1/public/applications/app/catalogs/catalog_1/entries/entry_1?resource=vault%3Aone");
  assert.equal(new Headers(requests[0]?.init.headers).get("Authorization"), "Bearer user-session");
  assert.equal(new Headers(requests[0]?.init.headers).get("X-Lotor-Secret-Key"), null);
  await assert.rejects(sdk.resourceCatalogEntries("", "catalog_1"), /resource/);
  await assert.rejects(sdk.resourceCatalogEntries("vault:one", "catalog_1", { limit: 101 }), /limit/);
});

for (const mode of ["direct", "same-origin"] as const) test(`manages resource credentials with ${mode} user transport`, async () => {
  const requests: RecordedRequest[] = [];
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("session-token");
  const metadata = { id: "credential_1", resource: "api_key:one", issued_to: "user:alice", status: "active", version: 1, display_hint: "key_hint", created_at: 100, expires_at: null };
  const fetcher: typeof fetch = async (input, init = {}) => {
    requests.push({ url: String(input), init });
    if (init.method === "POST") return response({ ...metadata, credential: "one-time-presentation" }, 201);
    if (init.method === "DELETE") return response({ ...metadata, status: "revoked" });
    return response({ items: [metadata] });
  };
  const sdk = new LotorBrowserClient(mode === "direct"
    ? { baseUrl: "https://api.lotor.test", clientId: "app", publishableKey: "lp_sbx_test", tokenStore, fetch: fetcher }
    : { mode: "same-origin", clientId: "app", publishableKey: "lp_sbx_test", csrfToken: () => "csrf", fetch: fetcher });
  const issued = await sdk.issueResourceCredential("api_key:one", { issuedTo: "user:alice", expiresAt: 1000 }, "issue-1");
  assert.equal(issued.credential, "one-time-presentation");
  assert.equal(tokenStore.getToken(), "session-token");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { issued_to: "user:alice", expires_at: 1000 });
  const listed = await sdk.resourceCredentials("api_key:one");
  assert.equal("credential" in listed[0]!, false);
  await sdk.rotateResourceCredential("api_key:one", "credential_1", { revokePreviousAt: 2000 }, "rotate-1");
  assert.deepEqual(JSON.parse(String(requests[2]?.init.body)), { revoke_previous_at: 2000 });
  assert.equal((await sdk.revokeResourceCredential("api_key:one", "credential_1", "revoke-1")).status, "revoked");
  assert.equal(requests[3]?.init.method, "DELETE");
  for (const [index, key] of [[0, "issue-1"], [2, "rotate-1"], [3, "revoke-1"]] as const) {
    assert.equal(new Headers(requests[index]?.init.headers).get("Idempotency-Key"), key);
  }
  for (const { init } of requests) {
    assert.equal(new Headers(init.headers).get("X-Lotor-Secret-Key"), null);
    assert.equal(new Headers(init.headers).get("Authorization"), mode === "direct" ? "Bearer session-token" : null);
    if (mode === "same-origin") assert.equal(init.credentials, "same-origin");
  }
  await assert.rejects(sdk.issueResourceCredential("api_key:one", { issuedTo: "user:alice", expiresAt: NaN }, "invalid"));
  await assert.rejects(sdk.rotateResourceCredential("api_key:one", "credential_1", { revokePreviousAt: Infinity }, "invalid"));
  await assert.rejects(sdk.revokeResourceCredential("api_key:one", "credential_1", ""));
  assert.equal(requests.length, 4);
});

test("requires a secure absolute origin and gates loopback HTTP explicitly", () => {
  const fetch = fixtureFetch([]);
  assert.throws(() => new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "app", fetch } as never), /publishableKey is required/);
  for (const baseUrl of ["/api/lotor", "http://api.example.test", "https://api.example.test/v1", "https://user@api.example.test"]) {
    assert.throws(() => new LotorBrowserClient({ baseUrl, clientId: "app", publishableKey: "lp_sbx_test", fetch }));
  }
  assert.throws(() => new LotorBrowserClient({ baseUrl: "http://127.0.0.1:8080", clientId: "app", publishableKey: "lp_sbx_test", fetch }), /allowInsecureLoopback/);
  assert.doesNotThrow(() => new LotorBrowserClient({ baseUrl: "http://127.0.0.1:8080", clientId: "app", publishableKey: "lp_sbx_test", allowInsecureLoopback: true, fetch }));
  assert.doesNotThrow(() => new LotorBrowserClient({ baseUrl: "http://[::1]:8080", clientId: "app", publishableKey: "lp_sbx_test", allowInsecureLoopback: true, fetch }));
});

test("errors contain status but never echo an unsafe response body", async () => {
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test",
    clientId: "signalbox_web",
    publishableKey: "lp_sbx_test",
    fetch: async () => response({ error: "secret response detail", tenant_id: "must-not-escape" }, 500),
  });
  await assert.rejects(sdk.startPasswordless("founder@example.test"), (error: unknown) => {
    assert.ok(error instanceof LotorBrowserError);
    assert.equal(error.status, 500);
    assert.doesNotMatch(error.message, /secret|tenant/);
    return true;
  });
});
