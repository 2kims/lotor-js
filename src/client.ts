import { BrowserTransport, LotorBrowserError, type BrowserFetch } from "./transport.js";
import * as decode from "./decode.js";
import { createResourceEnvelope, createSubjectKeyRegistration, unlockSubjectKeyBackup, type DeviceKeyMaterial } from "./key-access.js";
import {
  MemoryTokenStore,
  type ApplicationSession,
  type AuthenticatedSession,
  type CheckoutSession,
  type CreateCheckoutSessionInput,
  type OrganizationSummary,
  type PasswordlessChallenge,
  type PublicApplicationConfiguration,
  type PublicApplicationPricing,
  type TokenStore,
  type EnrollSubjectKeyInput,
  type SubjectKeyEnrollment,
  type SubjectKeyMutation,
  type SubjectKeyRecord,
  type ResourceGrantMutation,
  type ResourceGrantInput,
  type ResourceKeyMutation,
  type ResourceKeyVersionInput,
  type ResourceMember,
  type EncryptedInvitationMutation,
  type LinkPreflightInput,
  type LinkPreflight,
  type LinkSendInput,
  type LinkSendResult,
  type SubjectKeyCredentials,
  type EnsureEncryptedResourceInput,
  type EnsureEncryptedResourceResult,
  type EncryptedResourceLinkInput,
  type EncryptedResourceLinkResult,
  type KeyProvisioningJobList,
  type ProvisionEncryptedResourceLinksInput,
  type KeyProvisioningMutation,
  type UnlinkResult,
  type ResourceCollaborationPolicyOverride,
  type ResourceCollaborationPolicyMutation,
  type ResourceCollaboratorList,
  type ResourceSearchInput,
  type ResourceSearchList,
  type AccountInvitationList,
  type AccountInvitationMutation,
  type AccountResourceList,
  type ResourceInvitationMutation,
  type ResourceCollaboratorMutation,
} from "./types.js";

export interface LotorBrowserOptions {
  /** Absolute Lotor public API origin, for example https://api.example.com. */
  baseUrl: string;
  clientId: string;
  tokenStore?: TokenStore;
  /** Allows HTTP only for localhost, 127.0.0.0/8, or ::1 development endpoints. */
  allowInsecureLoopback?: boolean;
  fetch?: BrowserFetch;
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized === "") throw new Error(`${name} is required`);
  return normalized;
}

function bounded(value: string, name: string, maximum = 2048): string {
  const normalized = required(value, name);
  if (normalized.length > maximum) throw new Error(`${name} is too long`);
  return normalized;
}

function publicBaseUrl(value: string, allowInsecureLoopback: boolean): string {
  let url: URL;
  try {
    url = new URL(required(value, "baseUrl"));
  } catch {
    throw new Error("baseUrl must be an absolute URL");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  if (url.protocol !== "https:" && !(allowInsecureLoopback && url.protocol === "http:" && loopback)) {
    throw new Error("baseUrl must use HTTPS; loopback HTTP requires allowInsecureLoopback");
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "" && url.pathname !== "/")) {
    throw new Error("baseUrl must contain only an origin");
  }
  return url.origin;
}

function safeRedirectUrl(value: string, name: string): string {
  const normalized = bounded(value, name);
  let url: URL;
  try { url = new URL(normalized); } catch { throw new Error(`${name} must be an absolute URL`); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname)))) {
    throw new Error(`${name} must use HTTPS or loopback HTTP`);
  }
  return url.toString();
}

async function stableOwnerGrantId(resource: string, subject: string, keyId: string): Promise<string> {
  const value = new TextEncoder().encode(`${resource}\u0000${subject}\u0000${keyId}`);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", value));
  const suffix = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 32);
  return `grant_owner_${suffix}`;
}

async function resolveSubjectKey(
  keys: SubjectKeyRecord[],
  credentials: SubjectKeyCredentials,
): Promise<{ record: SubjectKeyRecord; material: DeviceKeyMaterial }> {
  if (credentials.keyMaterial !== undefined) {
    const record = keys.find((key) =>
      key.keyId === credentials.keyMaterial.keyId &&
      key.deviceId === credentials.keyMaterial.deviceId &&
      key.status === "active"
    );
    if (record === undefined) throw new Error("provided Lotor subject key is not active for this session");
    return { record, material: credentials.keyMaterial };
  }
  const record = keys.find((key) => key.status === "active" && key.encryptedPrivateKeyBackup.length > 0);
  if (record === undefined) throw new Error("no recoverable active Lotor subject key is enrolled");
  return { record, material: await unlockSubjectKeyBackup(record, credentials.passphrase) };
}

export class LotorBrowserClient {
  readonly clientId: string;
  readonly billing: { createCheckoutSession: (input: CreateCheckoutSessionInput) => Promise<CheckoutSession> };
  private readonly transport: BrowserTransport;
  private readonly tokenStore: TokenStore;
  private readonly applicationPath: string;

  constructor(options: LotorBrowserOptions) {
    this.clientId = bounded(options.clientId, "clientId", 256);
    const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (fetcher === undefined) throw new Error("a browser Fetch implementation is required");
    this.tokenStore = options.tokenStore ?? new MemoryTokenStore();
    this.transport = new BrowserTransport(publicBaseUrl(options.baseUrl, options.allowInsecureLoopback === true), fetcher, this.tokenStore);
    this.applicationPath = `/v1/public/applications/${encodeURIComponent(this.clientId)}`;
    this.billing = { createCheckoutSession: (input) => this.createCheckoutSession(input) };
  }

  async configuration(): Promise<PublicApplicationConfiguration> {
    return decode.configuration(await this.transport.request(`${this.applicationPath}/configuration`));
  }

  async pricing(): Promise<PublicApplicationPricing> {
    return decode.pricing(await this.transport.request(`${this.applicationPath}/pricing`));
  }

  async startPasswordless(email: string): Promise<PasswordlessChallenge> {
    return decode.challenge(await this.transport.request(`${this.applicationPath}/auth/passwordless/start`, {
      method: "POST",
      body: JSON.stringify({ email: bounded(email, "email", 320) }),
    }));
  }

  async verifyPasswordless(challengeId: string, code: string): Promise<AuthenticatedSession> {
    const verified = decode.verification(await this.transport.request(`${this.applicationPath}/auth/passwordless/verify`, {
      method: "POST",
      body: JSON.stringify({
        challenge_id: bounded(challengeId, "challengeId", 256),
        code: bounded(code, "code", 64),
      }),
    }));
    await this.tokenStore.setToken(verified.token);
    return verified.session;
  }

  async session(): Promise<ApplicationSession> {
    try {
      return decode.session(await this.transport.request(`${this.applicationPath}/session`, {}, true));
    } catch (error) {
      if (error instanceof LotorBrowserError && error.status === 401) {
        await this.tokenStore.clearToken();
        return { authenticated: false };
      }
      throw error;
    }
  }

  async logout(): Promise<void> {
    try {
      await this.transport.request(`${this.applicationPath}/session`, { method: "DELETE" }, true);
    } finally {
      await this.tokenStore.clearToken();
    }
  }

  async organizations(): Promise<OrganizationSummary[]> {
    return decode.organizations(await this.transport.request(`${this.applicationPath}/organizations`, {}, true));
  }

  async createOrganization(name: string, idempotencyKey: string): Promise<OrganizationSummary> {
    return decode.organization(await this.transport.request(`${this.applicationPath}/organizations`, {
      method: "POST", headers: { "Idempotency-Key": bounded(idempotencyKey, "idempotencyKey", 256), "X-Lotor-Request": "lotor-js-v1" },
      body: JSON.stringify({ name: bounded(name, "organization name", 256) }),
    }, true));
  }

  async putResource(resource: string, input: import("./types.js").ResourceRegistration): Promise<import("./types.js").CollaborationResource> {
    return decode.collaborationResource(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}`, {
      method: "PUT", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        resource_type: bounded(input.resourceType, "resourceType", 128),
        ...(input.displayName === undefined ? {} : { display_name: bounded(input.displayName, "displayName", 512) }),
        ...(input.parent === undefined ? {} : { parent: bounded(input.parent, "parent", 512) }),
      }),
    }, true));
  }

  async enrollSubjectKey(input: EnrollSubjectKeyInput): Promise<SubjectKeyEnrollment> {
    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const registration = await createSubjectKeyRegistration({
      clientId: this.clientId, subject: session.subject, passphrase: input.passphrase,
      ...(input.deviceId === undefined ? {} : { deviceId: input.deviceId }),
      ...(input.backupPrivateKeys === undefined ? {} : { backupPrivateKeys: input.backupPrivateKeys }),
    });
    const result = decode.subjectKeyMutation(await this.transport.request(`${this.applicationPath}/key-access/subject-keys`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify(registration.request),
    }, true));
    if (!result.accepted) throw new LotorBrowserError(`Lotor key enrollment rejected: ${result.reason}`, 409, result.reason);
    return { ...result, deviceId: registration.keys.deviceId, encryptionPrivateKey: registration.keys.encryptionPrivateKey, signingPrivateKey: registration.keys.signingPrivateKey };
  }

  async subjectKeys(): Promise<SubjectKeyRecord[]> {
    return decode.subjectKeys(await this.transport.request(`${this.applicationPath}/key-access/subject-keys`, {}, true));
  }

  async revokeSubjectKey(keyId: string): Promise<SubjectKeyMutation> {
    return decode.subjectKeyMutation(await this.transport.request(`${this.applicationPath}/key-access/subject-keys/${encodeURIComponent(bounded(keyId, "keyId", 256))}`, { method: "DELETE", headers: { "X-Lotor-Request": "lotor-js-v1" } }, true));
  }

  async resourceMembers(scope: string, resource: string): Promise<ResourceMember[]> {
    const normalizedScope = bounded(scope, "scope", 512);
    return decode.resourceMembers(await this.transport.request(`${this.applicationPath}/key-access/resource-members?scope=${encodeURIComponent(normalizedScope)}&resource=${encodeURIComponent(bounded(resource, "resource", 512))}`, {}, true), normalizedScope);
  }

  async createResourceKeyVersion(input: ResourceKeyVersionInput): Promise<ResourceKeyMutation> {
    if (!Number.isSafeInteger(input.version) || input.version < 1) throw new Error("version must be a positive safe integer");
    return decode.resourceKeyMutation(await this.transport.request(`${this.applicationPath}/key-access/resource-key-versions`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        scope: bounded(input.scope, "scope", 512), key_resource: bounded(input.keyResource, "keyResource", 512),
        version: input.version, algorithm: input.algorithm ?? "AES-256-GCM",
      }),
    }, true));
  }

  async prepareResourceGrant(input: ResourceGrantInput): Promise<ResourceGrantMutation> {
    if (!Number.isSafeInteger(input.keyVersion) || input.keyVersion < 1) throw new Error("keyVersion must be a positive safe integer");
    return decode.resourceGrantMutation(await this.transport.request(`${this.applicationPath}/key-access/resource-grants`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        grant_id: bounded(input.grantId, "grantId", 256), scope: bounded(input.scope, "scope", 512),
        resource: bounded(input.resource, "resource", 512), subject: bounded(input.subject, "subject", 512),
        relation: bounded(input.relation, "relation", 128), key_resource: bounded(input.keyResource, "keyResource", 512),
        key_version: input.keyVersion, recipient_key_id: bounded(input.recipientKeyId, "recipientKeyId", 256),
        ...(input.invitationId === undefined ? {} : { invitation_id: bounded(input.invitationId, "invitationId", 256) }),
      }),
    }, true));
  }

  async submitResourceEnvelope(input: import("./key-access.js").ResourceEnvelopeRequest): Promise<ResourceGrantMutation> {
    return decode.resourceGrantMutation(await this.transport.request(`${this.applicationPath}/key-access/resource-envelopes`, { method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify(input) }, true));
  }

  async resourceEnvelope(resource: string): Promise<import("./key-access.js").EncryptedResourceEnvelope> {
    return decode.resourceEnvelope(await this.transport.request(`${this.applicationPath}/key-access/resource-envelope?resource=${encodeURIComponent(bounded(resource, "resource", 512))}`, {}, true));
  }

  async acceptEncryptedInvitation(ticket: string, recipientKeyId: string, idempotencyKey: string): Promise<EncryptedInvitationMutation> {
    return decode.encryptedInvitationMutation(await this.transport.request(`${this.applicationPath}/key-access/invitations/accept`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({ ticket: bounded(ticket, "ticket", 512), recipient_key_id: bounded(recipientKeyId, "recipientKeyId", 256), idempotency_key: bounded(idempotencyKey, "idempotencyKey", 256) }),
    }, true));
  }

  async preflightResourceLinks(resource: string, input: LinkPreflightInput, idempotencyKey: string): Promise<LinkPreflight> {
    return decode.linkPreflight(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/links/preflight`, {
      method: "POST", headers: { "Idempotency-Key": bounded(idempotencyKey, "idempotencyKey", 256), "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify(input),
    }, true));
  }

  async sendResourceLinks(resource: string, input: LinkSendInput, idempotencyKey?: string): Promise<LinkSendResult> {
    const headers: Record<string, string> = { "X-Lotor-Request": "lotor-js-v1" };
    if (idempotencyKey !== undefined) headers["Idempotency-Key"] = bounded(idempotencyKey, "idempotencyKey", 256);
    return decode.linkSendResult(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/links/send`, { method: "POST", headers, body: JSON.stringify(input) }, true));
  }

  async ensureEncryptedResource(input: EnsureEncryptedResourceInput): Promise<EnsureEncryptedResourceResult> {
    if (input.resourceKey.length !== 32) throw new Error("resourceKey must contain 32 bytes");
    const scope = bounded(input.scope, "scope", 512);
    const resource = bounded(input.resource, "resource", 512);
    const keyResource = bounded(input.keyResource ?? input.resource, "keyResource", 512);
    const relation = bounded(input.relation ?? "owner", "relation", 128);
    const version = input.version ?? 1;
    if (!Number.isSafeInteger(version) || version < 1) throw new Error("version must be a positive safe integer");
    try {
      const existing = await this.resourceEnvelope(keyResource);
      return { created: false, keyResource, version: existing.keyVersion, grantId: existing.grantId };
    } catch (error) {
      if (!(error instanceof LotorBrowserError) || error.status !== 404) throw error;
    }

    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const { record: ownerKey, material: ownerMaterial } = await resolveSubjectKey(await this.subjectKeys(), input);
    const grantId = await stableOwnerGrantId(keyResource, session.subject, ownerKey.keyId);
    const resourceKey = input.resourceKey.slice();
    try {
      const keyMutation = await this.createResourceKeyVersion({ scope, keyResource, version });
      if (!keyMutation.accepted) throw new Error(`Lotor rejected the resource key: ${keyMutation.reason}`);
      const grantMutation = await this.prepareResourceGrant({
        grantId, scope, resource, subject: session.subject, relation, keyResource,
        keyVersion: version, recipientKeyId: ownerKey.keyId,
      });
      if (!grantMutation.accepted) throw new Error(`Lotor rejected the owner grant: ${grantMutation.reason}`);
      const envelope = await createResourceEnvelope({
        clientId: this.clientId, issuer: session.subject, issuerKeyId: ownerKey.keyId,
        issuerSigningPrivateKey: ownerMaterial.signingPrivateKey,
        member: {
          grantId, scope, resource, subject: session.subject, relation, keyResource,
          keyVersion: version, recipientKeyId: ownerKey.keyId,
          recipientEncryptionPublicKey: ownerKey.encryptionPublicKey,
        },
        resourceKey,
      });
      const submitted = await this.submitResourceEnvelope(envelope);
      if (!submitted.accepted) throw new Error(`Lotor rejected the owner envelope: ${submitted.reason}`);
      return { created: true, keyResource, version, grantId };
    } finally {
      resourceKey.fill(0);
    }
  }

  async sendEncryptedResourceLinks(resource: string, input: EncryptedResourceLinkInput): Promise<EncryptedResourceLinkResult> {
    if (input.resourceKey.length !== 32) throw new Error("resourceKey must contain 32 bytes");
    const normalizedResource = bounded(resource, "resource", 512);
    const preflight = await this.preflightResourceLinks(normalizedResource, {
      relation: bounded(input.relation, "relation", 128),
      targets: input.targets,
      ...(input.ttlSeconds === undefined ? {} : { ttl_seconds: input.ttlSeconds }),
    }, input.preflightIdempotencyKey);
    const rejected = preflight.targets.find((target) => !target.allowed);
    if (rejected !== undefined) throw new LotorBrowserError(rejected.message || "Lotor rejected a collaboration target", 409, rejected.reasonCode);

    if (!preflight.encryption.required) {
      const sent = await this.sendResourceLinks(normalizedResource, {
        preflight_id: preflight.preflightId,
        targets: preflight.targets.map((target) => ({ target_id: target.id })),
      }, input.sendIdempotencyKey);
      return { preflight, sent };
    }
    if (preflight.encryption.sourceEnvelope === undefined || preflight.encryption.keyResource === undefined) {
      throw new LotorBrowserError("Lotor resource encryption is not bootstrapped", 409, "source_envelope_unavailable");
    }

    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const { record: issuerKey, material: issuerMaterial } = await resolveSubjectKey(await this.subjectKeys(), input);
    const source = preflight.encryption.sourceEnvelope;
    const resourceKey = input.resourceKey.slice();
    try {
      const targets = await Promise.all(preflight.targets.map(async (target) => ({
        target_id: target.id,
        envelopes: await Promise.all(target.recipientKeys.map(async (recipient) => {
          const envelope = await createResourceEnvelope({
            clientId: this.clientId, issuer: session.subject, issuerKeyId: issuerKey.keyId,
            issuerSigningPrivateKey: issuerMaterial.signingPrivateKey,
            member: {
              grantId: recipient.grantId, scope: preflight.encryption.keyResource!, resource: normalizedResource,
              subject: recipient.subject, relation: preflight.relation,
              keyResource: preflight.encryption.keyResource!, keyVersion: source.keyVersion,
              recipientKeyId: recipient.keyId, recipientEncryptionPublicKey: recipient.publicKey,
            },
            resourceKey,
          });
          return {
            grant_id: envelope.grant_id, recipient_subject: envelope.recipient_subject,
            recipient_key_id: envelope.recipient_key_id, encryption_suite: envelope.encryption_suite,
            ciphertext: envelope.ciphertext, aad_hash: envelope.aad_hash,
            issuer_key_id: envelope.issuer_key_id, signature: envelope.signature,
          };
        })),
      })));
      const sent = await this.sendResourceLinks(normalizedResource, {
        preflight_id: preflight.preflightId,
        targets,
      }, input.sendIdempotencyKey);
      return { preflight, sent };
    } finally {
      resourceKey.fill(0);
    }
  }

  async keyProvisioningJobs(resource: string): Promise<KeyProvisioningJobList> {
    const normalizedResource = bounded(resource, "resource", 512);
    return decode.keyProvisioningJobs(await this.transport.request(
      `${this.applicationPath}/resources/${encodeURIComponent(normalizedResource)}/key-provisioning-jobs`,
      {},
      true,
    ));
  }

  async provisionEncryptedResourceLinks(
    resource: string,
    input: ProvisionEncryptedResourceLinksInput,
  ): Promise<KeyProvisioningMutation> {
    if (input.resourceKey.length !== 32) throw new Error("resourceKey must contain 32 bytes");
    const normalizedResource = bounded(resource, "resource", 512);
    const pending = await this.keyProvisioningJobs(normalizedResource);
    if (pending.jobs.length === 0) return { resource: normalizedResource, submitted: 0 };
    if (pending.resource !== normalizedResource) throw new Error("Lotor returned provisioning jobs for another resource");
    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const { record: issuerKey, material: issuerMaterial } = await resolveSubjectKey(await this.subjectKeys(), input);
    const resourceKey = input.resourceKey.slice();
    try {
      const envelopes = await Promise.all(pending.jobs.map(async (job) => {
        const envelope = await createResourceEnvelope({
          clientId: this.clientId, issuer: session.subject, issuerKeyId: issuerKey.keyId,
          issuerSigningPrivateKey: issuerMaterial.signingPrivateKey,
          member: {
            grantId: job.grantId, scope: job.keyResource, resource: normalizedResource,
            subject: job.subject, relation: job.relation, keyResource: job.keyResource,
            keyVersion: job.keyVersion, recipientKeyId: job.recipientKeyId,
            recipientEncryptionPublicKey: job.publicKey,
          },
          resourceKey,
        });
        return {
          link_id: job.linkId, grant_id: envelope.grant_id,
          recipient_subject: envelope.recipient_subject,
          recipient_key_id: envelope.recipient_key_id,
          encryption_suite: envelope.encryption_suite,
          ciphertext: envelope.ciphertext, aad_hash: envelope.aad_hash,
          issuer_key_id: envelope.issuer_key_id, signature: envelope.signature,
        };
      }));
      return decode.keyProvisioningMutation(await this.transport.request(
        `${this.applicationPath}/resources/${encodeURIComponent(normalizedResource)}/key-provisioning-jobs/commit`,
        {
          method: "POST",
          headers: { "X-Lotor-Request": "lotor-js-v1" },
          body: JSON.stringify({ envelopes }),
        },
        true,
      ));
    } finally {
      resourceKey.fill(0);
    }
  }

  async unlinkResource(resource: string, linkId: string, idempotencyKey?: string): Promise<UnlinkResult> {
    const headers: Record<string, string> = { "X-Lotor-Request": "lotor-js-v1" };
    if (idempotencyKey !== undefined) headers["Idempotency-Key"] = bounded(idempotencyKey, "idempotencyKey", 256);
    return decode.unlinkResult(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/links/${encodeURIComponent(bounded(linkId, "linkId", 256))}`, { method: "DELETE", headers }, true));
  }

  async resourceCollaborators(resource: string, options: { view?: "direct" | "effective"; search?: string; email?: string; subject?: string; resourceSubject?: string; viaGroup?: string; direct?: boolean; kind?: "user" | "group" | "invitation"; kinds?: Array<"user" | "group" | "invitation">; status?: string; statuses?: string[]; relations?: string[]; cursor?: string; limit?: number } = {}): Promise<ResourceCollaboratorList> {
    const query = new URLSearchParams();
    if (options.view) query.set("view", options.view);
    if (options.search) query.set("search", bounded(options.search, "search", 256));
    if (options.email) query.set("email", bounded(options.email, "email", 320));
    if (options.subject) query.set("subject", bounded(options.subject, "subject", 512));
    if (options.resourceSubject) query.set("resource_subject", bounded(options.resourceSubject, "resourceSubject", 640));
    if (options.viaGroup) query.set("via_group", bounded(options.viaGroup, "viaGroup", 512));
    if (options.direct !== undefined) query.set("direct", String(options.direct));
    for (const kind of [...(options.kind === undefined ? [] : [options.kind]), ...(options.kinds ?? [])]) query.append("kind", kind);
    for (const status of [...(options.status === undefined ? [] : [options.status]), ...(options.statuses ?? [])]) query.append("status", bounded(status, "status", 64));
    for (const relation of options.relations ?? []) query.append("relation", bounded(relation, "relation", 128));
    if (options.cursor) query.set("cursor", bounded(options.cursor, "cursor", 2048));
    if (options.limit !== undefined) {
      if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new Error("limit must be between 1 and 100");
      query.set("limit", String(options.limit));
    }
    const suffix = query.size === 0 ? "" : `?${query}`;
    return decode.collaborators(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/collaborators${suffix}`, {}, true));
  }

  async searchResources(input: ResourceSearchInput = {}): Promise<ResourceSearchList> {
    const resource = input.filters?.resource;
    const collaborator = input.filters?.collaborator;
    if (input.page?.limit !== undefined && (!Number.isInteger(input.page.limit) || input.page.limit < 1 || input.page.limit > 100)) throw new Error("limit must be between 1 and 100");
    const payload = {
      ...(input.filters === undefined ? {} : { filters: {
        ...(resource === undefined ? {} : { resource: {
          ...(resource.search === undefined ? {} : { search: bounded(resource.search, "resource search", 256) }),
          ...(resource.resources === undefined ? {} : { resources: resource.resources.map(value => bounded(value, "resource", 512)) }),
          ...(resource.types === undefined ? {} : { types: resource.types.map(value => bounded(value, "resource type", 128)) }),
          ...(resource.parent === undefined ? {} : { parent: bounded(resource.parent, "resource parent", 512) }),
          ...(resource.statuses === undefined ? {} : { statuses: resource.statuses.map(value => bounded(value, "resource status", 64)) }),
        } }),
        ...(collaborator === undefined ? {} : { collaborator: {
          ...(collaborator.search === undefined ? {} : { search: bounded(collaborator.search, "collaborator search", 256) }),
          ...(collaborator.email === undefined ? {} : { email: bounded(collaborator.email, "collaborator email", 320) }),
          ...(collaborator.subjects === undefined ? {} : { subjects: collaborator.subjects.map(value => bounded(value, "collaborator subject", 512)) }),
          ...(collaborator.kinds === undefined ? {} : { kinds: collaborator.kinds }),
          ...(collaborator.relations === undefined ? {} : { relations: collaborator.relations.map(value => bounded(value, "collaborator relation", 128)) }),
          ...(collaborator.statuses === undefined ? {} : { statuses: collaborator.statuses.map(value => bounded(value, "collaborator status", 64)) }),
          ...(collaborator.view === undefined ? {} : { view: collaborator.view }),
          ...(collaborator.viaGroups === undefined ? {} : { via_groups: collaborator.viaGroups.map(value => bounded(value, "collaborator viaGroup", 512)) }),
          ...(collaborator.resourceSubject === undefined ? {} : { resource_subject: bounded(collaborator.resourceSubject, "collaborator resourceSubject", 640) }),
          ...(collaborator.direct === undefined ? {} : { direct: collaborator.direct }),
        } }),
      } }),
      ...(input.include === undefined ? {} : { include: input.include }),
      ...(input.sort === undefined ? {} : { sort: input.sort }),
      ...(input.page === undefined ? {} : { page: {
        ...(input.page.limit === undefined ? {} : { limit: input.page.limit }),
        ...(input.page.cursor === undefined ? {} : { cursor: bounded(input.page.cursor, "resource search cursor", 2048) }),
      } }),
    };
    return decode.resourceSearch(await this.transport.request(`${this.applicationPath}/resources/search`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify(payload),
    }, true));
  }

  async accountInvitations(options: { cursor?: string; limit?: number } = {}): Promise<AccountInvitationList> {
    const query = new URLSearchParams();
    if (options.cursor) query.set("cursor", bounded(options.cursor, "cursor", 2048));
    if (options.limit !== undefined) {
      if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new Error("limit must be between 1 and 100");
      query.set("limit", String(options.limit));
    }
    const suffix = query.size === 0 ? "" : `?${query}`;
    return decode.accountInvitations(await this.transport.request(`${this.applicationPath}/me/invitations${suffix}`, {}, true));
  }

  async accountResources(options: { types?: string[]; accessStates?: Array<"active" | "pending_encryption">; cursor?: string; limit?: number } = {}): Promise<AccountResourceList> {
    const query = new URLSearchParams();
    for (const resourceType of options.types ?? []) query.append("type", bounded(resourceType, "resourceType", 128));
    for (const accessState of options.accessStates ?? []) query.append("access_state", accessState);
    if (options.cursor) query.set("cursor", bounded(options.cursor, "cursor", 2048));
    if (options.limit !== undefined) {
      if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 100) throw new Error("limit must be between 1 and 100");
      query.set("limit", String(options.limit));
    }
    const suffix = query.size === 0 ? "" : `?${query}`;
    return decode.accountResources(await this.transport.request(`${this.applicationPath}/me/resources${suffix}`, {}, true));
  }

  async acceptAccountInvitation(invitationId: string): Promise<AccountInvitationMutation> {
    return decode.accountInvitationMutation(await this.transport.request(`${this.applicationPath}/me/invitations/${encodeURIComponent(bounded(invitationId, "invitationId", 128))}/accept`, { method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" } }, true));
  }

  async declineAccountInvitation(invitationId: string): Promise<AccountInvitationMutation> {
    return decode.accountInvitationMutation(await this.transport.request(`${this.applicationPath}/me/invitations/${encodeURIComponent(bounded(invitationId, "invitationId", 128))}/decline`, { method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" } }, true));
  }

  async acceptResourceInvitation(ticket: string): Promise<ResourceInvitationMutation> {
    return decode.resourceInvitationMutation(await this.transport.request(`${this.applicationPath}/invitations/accept`, { method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({ ticket: bounded(ticket, "ticket", 512) }) }, true));
  }

  async updateResourceCollaborator(resource: string, collaborator: string, relation: string): Promise<ResourceCollaboratorMutation> {
    return decode.collaboratorMutation(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/collaborators/${encodeURIComponent(bounded(collaborator, "collaborator", 512))}`, { method: "PATCH", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({ relation: bounded(relation, "relation", 128) }) }, true));
  }

  async deleteResourceCollaborator(resource: string, collaborator: string, options: { force?: boolean } = {}): Promise<ResourceCollaboratorMutation> {
    const suffix = options.force === true ? "?force=true" : "";
    return decode.collaboratorMutation(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/collaborators/${encodeURIComponent(bounded(collaborator, "collaborator", 512))}${suffix}`, { method: "DELETE", headers: { "X-Lotor-Request": "lotor-js-v1" } }, true));
  }

  async setResourceCollaborationPolicy(resource: string, input: ResourceCollaborationPolicyOverride): Promise<ResourceCollaborationPolicyMutation> {
    return decode.resourcePolicyMutation(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/collaboration-policy`, { method: "PUT", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify(input) }, true));
  }

  private async createCheckoutSession(input: CreateCheckoutSessionInput): Promise<CheckoutSession> {
    const body: Record<string, string> = {
      organization_id: bounded(input.organizationId, "organizationId", 256),
      product_id: bounded(input.productId, "productId", 256),
      price_id: bounded(input.priceId, "priceId", 256),
      presentation: input.presentation,
      idempotency_key: bounded(input.idempotencyKey, "idempotencyKey", 256),
    };
    if (input.presentation === "hosted") {
      body.success_url = safeRedirectUrl(input.successUrl, "successUrl");
      body.cancel_url = safeRedirectUrl(input.cancelUrl, "cancelUrl");
    } else {
      body.return_url = safeRedirectUrl(input.returnUrl, "returnUrl");
    }
    return decode.checkout(await this.transport.request(`${this.applicationPath}/billing/checkout-sessions`, {
      method: "POST",
      headers: { "X-Lotor-Request": "lotor-js-v1" },
      body: JSON.stringify(body),
    }, true));
  }
}
