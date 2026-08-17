import assert from "node:assert/strict";
import test from "node:test";

import {
  LotorBrowserClient,
  LotorBrowserError,
  MemoryTokenStore,
  createSubjectKeyRegistration,
  groupResourcesByType,
  unwrapResourceEnvelope,
  type BrowserFetch,
  type TokenStore,
} from "../src/index.js";
import { decodeBase64url } from "../src/key-access.js";

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
    if (url.endsWith("/organizations") && init.method === "POST") return response({ id: "org_2", name: "Acme Operations", current_role: "owner", member_count: 1, pending_invites: 0 }, 201);
    if (url.endsWith("/organizations")) return response([{ id: "org_1", name: "Personal Workspace", current_role: "owner", member_count: 1, pending_invites: 0 }]);
    if (url.endsWith("/me/resources?type=organization&type=vault&access_state=active&limit=25")) return response({ resources: [
      { id: "res_org", type: "organization", name: "Personal Workspace", relations: ["member"], access_state: "active", access: { direct: false, paths: [{ type: "group", relation: "member", via: [{ id: "res_group", type: "group", name: "Engineering", subject_relation: "member" }] }] } },
      { id: "res_vault", type: "vault", name: "Production", parent: { id: "res_org", type: "organization", name: "Personal Workspace" }, relations: ["owner"], access_state: "active", access: { direct: true, paths: [{ type: "direct", relation: "owner", via: [] }] } },
    ], next_cursor: "next_resources" });
    if (url.endsWith("/me/invitations?limit=25")) return response({ invitations: [{ id: "cinv_1", resource: { id: "res_1", type: "vault", name: "Production" }, relation: "member", status: "pending_acceptance", expires_at: 123, encryption_required: true }], next_cursor: "next_1" });
    if (url.endsWith("/me/invitations/cinv_1/accept")) return response({ id: "cinv_1", status: "active" });
    if (url.endsWith("/me/invitations/cinv_2/decline")) return response({ id: "cinv_2", status: "declined" });
    if (url.endsWith("/billing/checkout-sessions")) return response({ id: "cs_1", presentation: "custom", client_secret: "cs_test_secret", publishable_key: "pk_test_public" }, 201);
    if (url.endsWith("/resources/vault%3Aone/links/preflight")) return response({
      preflight_id: "pfl_1", resource: "vault:one", relation: "member", policy_revision: "rev_1", expires_at: 123,
      targets: [{ id: "pft_1", type: "direct", kind: "user", subject: "user:bob", classification: "internal", provisioning: "existing_only", delivery: "none", reason_code: "allowed", message: "allowed", recipient_keys: [{ subject: "user:bob", grant_id: "lenv_1", key_id: "key_1", encryption_algorithm: "X25519", public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }], acceptance_required: false, encryption_ready: true, allowed: true }],
      encryption: { required: true, key_resource: "vault:one", ready: true }, ready: true, idempotent: false,
    });
    if (url.endsWith("/resources/vault%3Aone/collaborators?view=effective")) return response({ resource: "vault:one", collaborators: [{ kind: "invitation", id: "cinv_1", link_id: "lnk_1", relations: ["member"], status: "pending_acceptance", recipient: { type: "email", display: "kim@example.com" }, expires_at: 123 }], next_cursor: null });
    if (url.endsWith("/resources/personal-bcc69c42b94e9d215af82ddb/collaborators?view=effective")) return response({ resource: "personal-bcc69c42b94e9d215af82ddb", collaborators: [{ kind: "invitation", id: "cinv_1", link_id: "lnk_1", relations: ["member"], status: "pending_acceptance", recipient: { type: "email", display: "kim@example.com" }, expires_at: 123 }], next_cursor: null });
    if (url.includes("/resources/vault%3Aone/collaborators?view=effective&email=kim%40example.com")) return response({ resource: "vault:one", collaborators: [{ kind: "user", id: "user:kim", email: "kim@example.com", relations: ["member"], status: "active", access: { direct: false, paths: [{ type: "group", relation: "member", group: "group:engineering", subject_relation: "member", via: [{ resource: "group:engineering", subject_relation: "member" }] }] } }], next_cursor: null });
    if (url.endsWith("/resources/search")) return response({ resources: [{ resource: "vault:one", resource_type: "vault", display_name: "Production", status: "active", parent: { resource: "project:platform", resource_type: "project", display_name: "Platform" }, collaborator_matches: [{ kind: "user", id: "user:kim", email: "kim@example.com", relations: ["member"], status: "active", access: { direct: false, paths: [{ type: "group", relation: "member", group: "group:engineering", subject_relation: "member", via: [{ resource: "group:engineering", subject_relation: "member" }] }] } }] }], next_cursor: "next_search" });
    if (url.endsWith("/resources/group%3Aincident-commanders") && init.method === "PUT") return response({ id: "res_group", resource: "group:incident-commanders", resource_type: "group", display_name: "Incident Commanders", parent: "org:acme", status: "active" });
    if (url.endsWith("/key-access/resource-key-versions")) return response({ accepted: true, reason: "created", key_resource: "vault:one", version: 1, log_seq: 41 });
    if (url.endsWith("/key-access/resource-grants")) return response({ accepted: true, reason: "prepared", grant_id: "grant_owner", status: "pending_provisioning", log_seq: 42 });
    if (url.endsWith("/invitations/accept")) return response({ id: "cinv_1", resource: "vault:one", relation: "member", recipient: { type: "email" }, status: "active", idempotent: false });
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

test("creates organizations and child resources through authenticated public operations", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  assert.equal((await sdk.createOrganization("Acme Operations", "create-org-1")).id, "org_2");
  const group = await sdk.putResource("group:incident-commanders", { resourceType: "group", displayName: "Incident Commanders", parent: "org:acme" });
  assert.equal(group.parent, "org:acme");
  assert.equal(new Headers(requests[0]?.init.headers).get("Idempotency-Key"), "create-org-1");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), { name: "Acme Operations" });
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), { resource_type: "group", display_name: "Incident Commanders", parent: "org:acme" });
});

test("bootstraps encrypted resources with a key version and owner grant", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = client(requests, tokenStore);
  const key = await sdk.createResourceKeyVersion({ scope: "vault:one", keyResource: "vault:one", version: 1 });
  const grant = await sdk.prepareResourceGrant({
    grantId: "grant_owner", scope: "vault:one", resource: "vault:one", subject: "user:owner",
    relation: "owner", keyResource: "vault:one", keyVersion: 1, recipientKeyId: "key_owner",
  });
  assert.equal(key.keyResource, "vault:one");
  assert.equal(grant.grantId, "grant_owner");
  assert.deepEqual(JSON.parse(String(requests[0]?.init.body)), {
    scope: "vault:one", key_resource: "vault:one", version: 1, algorithm: "AES-256-GCM",
  });
  assert.deepEqual(JSON.parse(String(requests[1]?.init.body)), {
    grant_id: "grant_owner", scope: "vault:one", resource: "vault:one", subject: "user:owner",
    relation: "owner", key_resource: "vault:one", key_version: 1, recipient_key_id: "key_owner",
  });
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

test("preflights collaboration through the public endpoint and preserves Lotor grant IDs", async () => {
  const tokenStore = new MemoryTokenStore();
  tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const result = await client(requests, tokenStore).preflightResourceLinks("vault:one", {
    relation: "member", targets: [{ type: "direct", subject: "user:bob", provisioning: "existing_only", delivery: "none" }],
  }, "preflight-1");
  assert.equal(result.targets[0]?.recipientKeys[0]?.grantId, "lenv_1");
  assert.equal(result.targets[0]?.recipientKeys[0]?.publicKey.length, 32);
  assert.equal(new Headers(requests[0]?.init.headers).get("Idempotency-Key"), "preflight-1");
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/resources/vault%3Aone/links/preflight");
});

test("bootstraps and sends encrypted links with an application-provided resource key", async () => {
  const passphrase = "correct horse battery staple";
  const owner = await createSubjectKeyRegistration({
    clientId: "avault_web", subject: "user:owner", passphrase, deviceId: "owner-device",
  });
  const recipient = await createSubjectKeyRegistration({
    clientId: "avault_web", subject: "user:recipient", passphrase, deviceId: "recipient-device",
  });
  const subjectKey = (registration: typeof owner) => ({
    key_id: registration.request.key_id, device_id: registration.request.device_id,
    encryption_algorithm: registration.request.encryption_algorithm,
    encryption_public_key: registration.request.encryption_public_key,
    signing_algorithm: registration.request.signing_algorithm,
    signing_public_key: registration.request.signing_public_key,
    encrypted_private_key_backup: registration.request.encrypted_private_key_backup,
    backup_kdf: registration.request.backup_kdf, backup_salt: registration.request.backup_salt,
    backup_nonce: registration.request.backup_nonce,
    backup_format_version: registration.request.backup_format_version,
    status: "active", log_seq: 1,
  });
  const bytes = (length: number) => Buffer.alloc(length).toString("base64url");
  const requests: RecordedRequest[] = [];
  const fetcher: BrowserFetch = async (raw, init = {}) => {
    const url = String(raw);
    requests.push({ url, init });
    if (url.endsWith("/key-access/resource-envelope?resource=project%3Aone")) return response({ error: "not found" }, 404);
    if (url.endsWith("/session")) return response({ authenticated: true, subject: "user:owner", email: "owner@example.test" });
    if (url.endsWith("/key-access/subject-keys")) return response({ keys: [subjectKey(owner)] });
    if (url.endsWith("/key-access/resource-key-versions")) return response({ accepted: true, reason: "created", key_resource: "project:one", version: 1, log_seq: 2 });
    if (url.endsWith("/key-access/resource-grants")) {
      const body = JSON.parse(String(init.body)) as { grant_id: string };
      return response({ accepted: true, reason: "prepared", grant_id: body.grant_id, status: "pending_provisioning", log_seq: 3 });
    }
    if (url.endsWith("/key-access/resource-envelopes")) {
      const body = JSON.parse(String(init.body)) as { grant_id: string };
      return response({ accepted: true, reason: "activated", grant_id: body.grant_id, status: "active", log_seq: 4 });
    }
    if (url.endsWith("/resources/vault%3Aone/links/preflight")) return response({
      preflight_id: "pfl_encrypted", resource: "vault:one", relation: "member",
      policy_revision: "rev_1", expires_at: 123,
      targets: [{
        id: "target_1", type: "invite", kind: "user", email: "recipient@example.test",
        subject: "user:recipient", classification: "internal", provisioning: "existing_only",
        delivery: "email", reason_code: "allowed", message: "allowed",
        recipient_keys: [{
          subject: "user:recipient", grant_id: "grant_recipient",
          key_id: recipient.request.key_id, encryption_algorithm: "X25519",
          public_key: recipient.request.encryption_public_key,
        }],
        acceptance_required: true, encryption_ready: true, allowed: true,
      }],
      encryption: {
        required: true, key_resource: "project:one", ready: true,
        source_envelope: {
          grant_id: "grant_owner", scope: "project:one", resource: "project:one",
          relation: "owner", key_resource: "project:one", recipient_subject: "user:owner",
          recipient_key_id: owner.request.key_id,
          encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM", ciphertext: bytes(61),
          aad_hash: bytes(32), issuer: "user:owner", issuer_key_id: owner.request.key_id,
          issuer_signing_algorithm: "Ed25519", issuer_signing_public_key: owner.request.signing_public_key,
          issuer_key_status: "active", signature: bytes(64), key_version: 1,
        },
      },
      ready: true, idempotent: false,
    });
    if (url.endsWith("/resources/vault%3Aone/links/send")) return response({
      preflight_id: "pfl_encrypted", resource: "vault:one",
      links: [{ id: "link_1", target_id: "target_1", type: "invite", subject: "user:recipient", status: "pending_acceptance" }],
    });
    if (url.endsWith("/resources/vault%3Aone/key-provisioning-jobs")) return response({
      resource: "vault:one",
      jobs: [{
        grant_id: "grant_post_enrollment", link_id: "link_pending", resource: "vault:one",
        relation: "member", key_resource: "project:one", key_version: 1,
        subject: "user:recipient", recipient_key_id: recipient.request.key_id,
        encryption_algorithm: "X25519", public_key: recipient.request.encryption_public_key,
        link_status: "pending_encryption",
      }],
    });
    if (url.endsWith("/resources/vault%3Aone/key-provisioning-jobs/commit")) return response({
      resource: "vault:one", submitted: 1,
    }, 201);
    return response({ error: "not found" }, 404);
  };
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const sdk = new LotorBrowserClient({ baseUrl: "https://api.lotor.test", clientId: "avault_web", fetch: fetcher, tokenStore });
  const resourceKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const bootstrap = await sdk.ensureEncryptedResource({
    scope: "org:one", resource: "project:one", resourceKey, passphrase,
  });
  assert.equal(bootstrap.created, true);
  const linked = await sdk.sendEncryptedResourceLinks("vault:one", {
    relation: "member",
    targets: [{ type: "invite", email: "recipient@example.test", provisioning: "existing_only", delivery: "email" }],
    resourceKey, passphrase, preflightIdempotencyKey: "preflight-1", sendIdempotencyKey: "send-1",
  });
  assert.equal(linked.sent.links[0]?.status, "pending_acceptance");
  assert.deepEqual(resourceKey, Uint8Array.from({ length: 32 }, (_, index) => index + 1));
  const send = requests.find(({ url }) => url.endsWith("/links/send"));
  assert.ok(send);
  const envelope = (JSON.parse(String(send.init.body)) as { targets: Array<{ envelopes: Array<Record<string, string>> }> }).targets[0]?.envelopes[0];
  assert.ok(envelope);
  const unwrapped = await unwrapResourceEnvelope("avault_web", {
    grantId: envelope.grant_id!, scope: "project:one", resource: "vault:one",
    subject: envelope.recipient_subject!, relation: "member", keyResource: "project:one", keyVersion: 1,
    recipientKeyId: envelope.recipient_key_id!, encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM",
    ciphertext: decodeBase64url(envelope.ciphertext!), aadHash: decodeBase64url(envelope.aad_hash!),
    issuer: "user:owner", issuerKeyId: envelope.issuer_key_id!, issuerSigningAlgorithm: "Ed25519",
    issuerSigningPublicKey: decodeBase64url(owner.request.signing_public_key), issuerKeyStatus: "active",
    signature: decodeBase64url(envelope.signature!),
  }, recipient.keys.encryptionPrivateKey);
  assert.deepEqual(unwrapped, resourceKey);
  const provisioned = await sdk.provisionEncryptedResourceLinks("vault:one", { resourceKey, passphrase });
  assert.deepEqual(provisioned, { resource: "vault:one", submitted: 1 });
  assert.deepEqual(resourceKey, Uint8Array.from({ length: 32 }, (_, index) => index + 1));
  const commit = requests.find(({ url }) => url.endsWith("/key-provisioning-jobs/commit"));
  assert.ok(commit);
  const provisionedEnvelope = (JSON.parse(String(commit.init.body)) as { envelopes: Array<Record<string, string>> }).envelopes[0];
  assert.equal(provisionedEnvelope?.link_id, "link_pending");
  const provisionedKey = await unwrapResourceEnvelope("avault_web", {
    grantId: provisionedEnvelope!.grant_id!, scope: "project:one", resource: "vault:one",
    subject: provisionedEnvelope!.recipient_subject!, relation: "member", keyResource: "project:one", keyVersion: 1,
    recipientKeyId: provisionedEnvelope!.recipient_key_id!, encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM",
    ciphertext: decodeBase64url(provisionedEnvelope!.ciphertext!), aadHash: decodeBase64url(provisionedEnvelope!.aad_hash!),
    issuer: "user:owner", issuerKeyId: provisionedEnvelope!.issuer_key_id!, issuerSigningAlgorithm: "Ed25519",
    issuerSigningPublicKey: decodeBase64url(owner.request.signing_public_key), issuerKeyStatus: "active",
    signature: decodeBase64url(provisionedEnvelope!.signature!),
  }, recipient.keys.encryptionPrivateKey);
  assert.deepEqual(provisionedKey, resourceKey);
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

test("forces collaborator removal through the existing delete endpoint", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", tokenStore,
    fetch: async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return response({
        resource: "organization:acme", collaborator: "user:kim", relations: ["member"],
        status: "revoked", force: true, cascaded_groups: ["group:engineering#member"],
        rekey_required: false,
      });
    },
  });
  const removed = await sdk.deleteResourceCollaborator("organization:acme", "user:kim", { force: true });
  assert.equal(removed.force, true);
  assert.deepEqual(removed.cascaded_groups, ["group:engineering#member"]);
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/resources/organization%3Aacme/collaborators/user%3Akim?force=true");
  assert.equal(requests[0]?.init.method, "DELETE");
});

test("lists the authenticated account invitation inbox without internal resource references", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const requests: RecordedRequest[] = [];
  const listed = await client(requests, tokenStore).accountInvitations({ limit: 25 });
  assert.deepEqual(listed, { invitations: [{ id: "cinv_1", resource: { id: "res_1", type: "vault", name: "Production" }, relation: "member", status: "pending_acceptance", expiresAt: 123, encryptionRequired: true }], nextCursor: "next_1" });
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
  assert.equal(listed.resources[1]?.parent?.id, "res_org");
  assert.deepEqual(groupResourcesByType(listed.resources).map(group => [group.type, group.resources.length]), [["organization", 1], ["vault", 1]]);
  assert.equal(requests[0]?.url, "https://api.lotor.test/v1/public/applications/signalbox_web/me/resources?type=organization&type=vault&access_state=active&limit=25");
  await assert.rejects(client([], tokenStore).accountResources({ limit: 101 }), /limit/);
});

test("rejects an account invitation response that leaks an internal typed resource reference", async () => {
  const tokenStore = new MemoryTokenStore(); tokenStore.setToken("token");
  const sdk = new LotorBrowserClient({
    baseUrl: "https://api.lotor.test", clientId: "signalbox_web", tokenStore,
    fetch: async () => response({ invitations: [{ id: "cinv_1", resource: { id: "organization:internal-secret", type: "organization", name: "Personal Workspace" }, relation: "member", status: "pending_acceptance", expires_at: 123, encryption_required: false }], next_cursor: null }),
  });
  await assert.rejects(sdk.accountInvitations(), /internal resource reference/);
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
