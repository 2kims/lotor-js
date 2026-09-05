import {
  BrowserTransport,
  LotorBrowserError,
  SameOriginBrowserTransport,
  type BrowserFetch,
  type BrowserRequestTransport,
  type CSRFTokenProvider,
} from "./transport.js";
import * as decode from "./decode.js";
import { claimTransferredSubjectKey, createClaimTransferKey, createSubjectKeyRegistration, unlockSubjectKeyBackup } from "./key-access.js";
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
  type ResourceLinkChange,
  type ResourceLinkCandidateSearchInput,
  type ResourceLinkCandidateSearchResult,
  type ResourceLinkPreflight,
  type ResourceLinkSendInput,
  type ResourceLinkSendResult,
  type ResourceLinkResult,
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
  type ClaimSubjectKeyInput,
  type ClaimedSubjectKey,
  type ResourceLinkEnvelopeSubmission,
  type OrganizationE2EEPolicy,
  type ResourceSessionEnvelope,
  type EncryptionAction,
  type EncryptionActionMutation,
  type ResourcePayloadAccessLease,
  type ResourcePayloadManifest,
  type ResourcePayloadMutation,
  type ResourcePayloadUploadInput,
  type ResourcePayloadUploadIntent,
  type DurableOperation,
  type ResourceLifecycleFence,
  type ResourceMoveInput,
  type ResourceDeleteInput,
} from "./types.js";

interface LotorBrowserCommonOptions {
  clientId: string;
  /** Browser-safe key scoped to the same application and live/sandbox mode as clientId. */
  publishableKey: string;
  fetch?: BrowserFetch;
}

export type LotorBrowserOptions = LotorBrowserCommonOptions & ({
  /** Cross-origin/headless public API mode. */
  mode?: "public";
  /** Absolute Lotor public API origin, for example https://api.example.com. */
  baseUrl: string;
  tokenStore?: TokenStore;
  /** Allows HTTP only for localhost, 127.0.0.0/8, or ::1 development endpoints. */
  allowInsecureLoopback?: boolean;
  csrfToken?: never;
} | {
  /** Cookie-only mode through the Lotor gateway on the application's own origin. */
  mode: "same-origin";
  baseUrl?: never;
  tokenStore?: never;
  allowInsecureLoopback?: never;
  /** Override only for non-DOM runtimes and tests; browsers read the Lotor CSRF cookie. */
  csrfToken?: CSRFTokenProvider;
});

function required(value: string, name: string): string {
  const normalized = value?.trim() ?? "";
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

export class LotorBrowserClient {
  readonly clientId: string;
  readonly publishableKey: string;
  readonly billing: { createCheckoutSession: (input: CreateCheckoutSessionInput) => Promise<CheckoutSession> };
  private readonly transport: BrowserRequestTransport;
  private readonly tokenStore: TokenStore;
  private readonly applicationPath: string;
  private readonly sameOrigin: boolean;
  private readonly fetcher: BrowserFetch;

  constructor(options: LotorBrowserOptions) {
    this.clientId = bounded(options.clientId, "clientId", 256);
    this.publishableKey = bounded(options.publishableKey, "publishableKey", 512);
    const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (fetcher === undefined) throw new Error("a browser Fetch implementation is required");
    this.fetcher = fetcher;
    this.sameOrigin = options.mode === "same-origin";
    this.tokenStore = options.mode === "same-origin" ? new MemoryTokenStore() : options.tokenStore ?? new MemoryTokenStore();
    this.transport = options.mode === "same-origin"
      ? new SameOriginBrowserTransport(fetcher, this.publishableKey, options.csrfToken)
      : new BrowserTransport(publicBaseUrl(options.baseUrl, options.allowInsecureLoopback === true), fetcher, this.tokenStore, this.publishableKey);
    this.applicationPath = this.sameOrigin ? "/.lotor/v1" : `/v1/public/applications/${encodeURIComponent(this.clientId)}`;
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
    const response = await this.transport.requestWithMetadata<unknown>(`${this.applicationPath}/auth/passwordless/verify`, {
      method: "POST",
      body: JSON.stringify({
        challenge_id: bounded(challengeId, "challengeId", 256),
        code: bounded(code, "code", 64),
      }),
    });
    if (this.sameOrigin) return decode.sameOriginVerification(response.body);
    const verified = decode.verification(response.body);
    const claimToken = response.headers.get("Lotor-Key-Claim-Token")?.trim();
    if (verified.session.e2ee?.claimRequired) {
      if (!claimToken) throw new Error("Lotor key claim response is missing its credential");
      verified.session.e2ee.claimToken = claimToken;
    }
    await this.tokenStore.setToken(verified.token);
    return verified.session;
  }

  async session(): Promise<ApplicationSession> {
    try {
      return decode.session(await this.transport.request(`${this.applicationPath}/session`, {}, true));
    } catch (error) {
      if (error instanceof LotorBrowserError && error.status === 401) {
        if (!this.sameOrigin) await this.tokenStore.clearToken();
        return { authenticated: false };
      }
      throw error;
    }
  }

  async logout(): Promise<void> {
    try {
      await this.transport.request(`${this.applicationPath}/session`, { method: "DELETE" }, true);
    } finally {
      if (!this.sameOrigin) await this.tokenStore.clearToken();
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
        ...(input.keyScope === undefined ? {} : { key_scope: input.keyScope }),
      }),
    }, true));
  }

  async resource(resource: string): Promise<import("./types.js").CollaborationResource> {
    return decode.collaborationResource(await this.transport.request(
      `${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}`,
      {},
      true,
    ));
  }

  async moveResource(resource: string, input: ResourceMoveInput, idempotencyKey: string): Promise<DurableOperation> {
	return this.resourceLifecycleOperation(resource, "move", input, idempotencyKey);
  }

  async disableResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation> {
	return this.resourceLifecycleOperation(resource, "disable", input, idempotencyKey);
  }

  async restoreResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation> {
	return this.resourceLifecycleOperation(resource, "restore", input, idempotencyKey);
  }

  async deleteResource(resource: string, input: ResourceDeleteInput, idempotencyKey: string): Promise<DurableOperation> {
	return decode.durableOperation(await this.transport.request(
		`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}`,
		{ method: "DELETE", headers: { "X-Lotor-Request": "lotor-js-v1", "Idempotency-Key": bounded(idempotencyKey, "idempotencyKey", 256) }, body: JSON.stringify({
			expected_revision: input.expectedRevision, expected_lifecycle_generation: input.expectedLifecycleGeneration, subtree: input.subtree,
		}) }, true,
	));
  }

  async operation(operationId: string): Promise<DurableOperation> {
	return decode.durableOperation(await this.transport.request(
		`${this.applicationPath}/operations/${encodeURIComponent(bounded(operationId, "operationId", 256))}`, {}, true,
	));
  }

  private async resourceLifecycleOperation(resource: string, action: "move" | "disable" | "restore", input: ResourceLifecycleFence & { parent?: string }, idempotencyKey: string): Promise<DurableOperation> {
	return decode.durableOperation(await this.transport.request(
		`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/${action}`,
		{ method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1", "Idempotency-Key": bounded(idempotencyKey, "idempotencyKey", 256) }, body: JSON.stringify({
			expected_revision: input.expectedRevision, expected_lifecycle_generation: input.expectedLifecycleGeneration,
			...(input.parent === undefined ? {} : { parent: bounded(input.parent, "parent", 512) }),
		}) }, true,
	));
  }

  async resourcePayload(resource: string, slot: string): Promise<ResourcePayloadManifest> {
    return decode.resourcePayloadManifest(await this.transport.request(this.resourcePayloadPath(resource, slot), {}, true));
  }

  async createResourcePayloadUpload(resource: string, slot: string, input: ResourcePayloadUploadInput): Promise<ResourcePayloadUploadIntent> {
    const result = await this.transport.requestWithMetadata<unknown>(`${this.resourcePayloadPath(resource, slot)}/uploads`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        schema_id: input.schemaId, expected_payload_version: input.expectedPayloadVersion,
        representation: input.representation, object_digest: input.objectDigest, object_size: input.objectSize,
        ...(input.representation === "encrypted-envelope-v1" ? {
          encryption_suite: input.encryptionSuite, key_binding_ref: input.keyBindingRef, key_version: input.keyVersion,
          wrapped_payload_key: input.wrappedPayloadKey, aad_hash: input.aadHash, encryptor_subject: input.encryptorSubject,
          encryptor_key_id: input.encryptorKeyId, encryption_receipt: input.encryptionReceipt,
        } : {}),
        resource_revision: input.resourceRevision, lifecycle_generation: input.lifecycleGeneration,
      }),
    }, true);
    const intent = decode.resourcePayloadUploadIntent(result.body);
    const token = result.headers.get("Lotor-Payload-Token")?.trim();
    if (!this.sameOrigin && !token) throw new Error("Lotor resource payload upload response is missing its credential");
    return token ? { ...intent, token } : intent;
  }

  async commitResourcePayload(resource: string, slot: string, intent: ResourcePayloadUploadIntent): Promise<ResourcePayloadManifest> {
    const headers: Record<string, string> = { "X-Lotor-Request": "lotor-js-v1" };
    if (!this.sameOrigin) headers["Lotor-Payload-Token"] = bounded(intent.token ?? "", "payload token", 512);
    return decode.resourcePayloadManifest(await this.transport.request(`${this.resourcePayloadPath(resource, slot)}/commits`, {
      method: "POST", headers, body: JSON.stringify({ expected_payload_version: intent.expectedPayloadVersion }),
    }, true));
  }

  async uploadResourcePayloadObject(intent: ResourcePayloadUploadIntent, object: Uint8Array): Promise<void> {
    if (object.length === 0) throw new Error("resource payload object must not be empty");
    const response = await this.fetcher(intent.uploadUrl, {
      method: intent.uploadMethod, headers: intent.requiredHeaders, body: object.slice().buffer,
      credentials: "omit", redirect: "error",
    });
    if (!response.ok) throw new LotorBrowserError(`Lotor resource payload upload failed with status ${response.status}`, response.status, "payload_upload_failed");
  }

  async accessResourcePayload(resource: string, slot: string, payloadVersion?: number): Promise<ResourcePayloadAccessLease> {
    return decode.resourcePayloadAccessLease(await this.transport.request(`${this.resourcePayloadPath(resource, slot)}/access`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" },
      body: JSON.stringify(payloadVersion === undefined ? {} : { payload_version: payloadVersion }),
    }, true));
  }

  async rewrapResourcePayload(resource: string, slot: string, input: import("./types.js").ResourcePayloadRewrapInput): Promise<import("./types.js").ResourcePayloadRewrapResult> {
    return decode.resourcePayloadRewrapResult(await this.transport.request(`${this.resourcePayloadPath(resource, slot)}/rewraps`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        payload_version: input.payloadVersion, expected_wrap_revision: input.expectedWrapRevision,
        key_binding_ref: input.keyBindingRef, previous_key_version: input.previousKeyVersion, key_version: input.keyVersion,
        resource_revision: input.resourceRevision, lifecycle_generation: input.lifecycleGeneration,
        ...(input.wrappedPayloadKey === undefined ? {} : {
          wrapped_payload_key: input.wrappedPayloadKey, rewrapper_subject: input.rewrapperSubject,
          rewrapper_key_id: input.rewrapperKeyId, rewrap_receipt: input.rewrapReceipt,
        }),
      }),
    }, true));
  }

  async deleteResourcePayload(resource: string, slot: string, idempotencyKey: string): Promise<ResourcePayloadMutation> {
    return decode.resourcePayloadMutation(await this.transport.request(this.resourcePayloadPath(resource, slot), {
      method: "DELETE", headers: { "X-Lotor-Request": "lotor-js-v1", "Idempotency-Key": bounded(idempotencyKey, "idempotencyKey", 256) },
    }, true));
  }

  private resourcePayloadPath(resource: string, slot: string): string {
    return `${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/payloads/${encodeURIComponent(bounded(slot, "slot", 128))}`;
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

  async claimSubjectKey(input: ClaimSubjectKeyInput): Promise<ClaimedSubjectKey> {
    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const claimId = bounded(input.claimId, "claimId", 256);
    const headers: Record<string, string> = { "X-Lotor-Request": "lotor-js-v1" };
    if (input.claimToken !== undefined) headers["Lotor-Key-Claim-Token"] = bounded(input.claimToken, "claimToken", 512);
    if (!this.sameOrigin && headers["Lotor-Key-Claim-Token"] === undefined) throw new Error("claimToken is required in public API mode");
    const claim = decode.publicKeyClaim(await this.transport.request(`${this.applicationPath}/key-access/claims/${encodeURIComponent(claimId)}`, { headers }, true));
    const transferKey = await createClaimTransferKey();
    const transfer = decode.publicKeyClaimTransfer(await this.transport.request(`${this.applicationPath}/key-access/claims/${encodeURIComponent(claimId)}/transfer`, {
      method: "POST", headers, body: JSON.stringify({ browser_transfer_public_key: transferKey.publicKey }),
    }, true), claim);
    const material = await claimTransferredSubjectKey({
      clientId: this.clientId, subject: session.subject, claimId, passphrase: input.passphrase,
      transferPrivateKey: transferKey.privateKey,
      transfer: {
        encryptedPrivateBundle: transfer.encryptedPrivateBundle, boxPublicKey: transfer.boxPublicKey,
        nonce: transfer.nonce, aadHash: transfer.aadHash, associatedData: transfer.associatedData,
        encryptionPublicKey: transfer.encryptionPublicKey, signingPublicKey: transfer.signingPublicKey, keyId: transfer.keyId,
      },
    });
    const completed = decode.publicKeyClaim(await this.transport.request(`${this.applicationPath}/key-access/claims/${encodeURIComponent(claimId)}/complete`, {
      method: "POST", headers, body: JSON.stringify({
        encrypted_private_key_backup: material.request.encrypted_private_key_backup,
        backup_kdf: material.request.backup_kdf, backup_salt: material.request.backup_salt,
        backup_nonce: material.request.backup_nonce, backup_format_version: material.request.backup_format_version,
        possession_proof: material.request.proof,
      }),
    }, true));
    if (completed.status !== "completed" || completed.keyId !== transfer.keyId) throw new Error("Lotor key claim did not complete");
    return { ...material.keys, accepted: true, reason: "claimed", keyId: completed.keyId, logSeq: 0 };
  }

  async resourceEnvelope(resource: string): Promise<import("./key-access.js").EncryptedResourceEnvelope> {
    return decode.resourceEnvelope(await this.transport.request(`${this.applicationPath}/key-access/resource-envelope?resource=${encodeURIComponent(bounded(resource, "resource", 512))}`, {}, true));
  }

  async resourceSessionEnvelope(resource: string, sessionPublicKey: string, clientNonce: string): Promise<ResourceSessionEnvelope> {
    return decode.resourceSessionEnvelope(await this.transport.request(`${this.applicationPath}/key-access/resource-envelope`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        resource: bounded(resource, "resource", 512), session_public_key: bounded(sessionPublicKey, "session public key", 128),
        client_nonce: bounded(clientNonce, "client nonce", 256),
      }),
    }, true));
  }

  async resourceSession(resource: string): Promise<import("./types.js").ResourceSession> {
    const { createResourceSessionKeyRequest, unwrapResourceSessionEnvelope } = await import("./key-access.js");
    const request = await createResourceSessionKeyRequest();
    const envelope = await this.resourceSessionEnvelope(resource, request.publicKey, request.clientNonce);
    return { ...envelope, resourceKey: await unwrapResourceSessionEnvelope(envelope, request, resource) };
  }

  async organizationE2EEPolicy(organization: string): Promise<OrganizationE2EEPolicy> {
    return decode.organizationE2EEPolicy(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(organization, "organization", 512))}/e2ee`, {}, true));
  }

  async configureOrganizationE2EE(organization: string, input: import("./types.js").OrganizationE2EEPolicyInput): Promise<OrganizationE2EEPolicy> {
    return decode.organizationE2EEPolicy(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(organization, "organization", 512))}/e2ee`, {
      method: "PUT", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        required_account_custody: input.requiredAccountCustody,
        resource_key_executor: input.resourceKeyExecutor,
        automation_executor: input.automationExecutor,
        ...(input.functionBindingId === undefined ? {} : { function_binding_id: bounded(input.functionBindingId, "function binding", 256) }),
        resource_key_policy: input.resourceKeyPolicy,
      }),
    }, true));
  }

  async encryptionActions(): Promise<EncryptionAction[]> {
    return decode.encryptionActions(await this.transport.request(`${this.applicationPath}/me/encryption-actions`, {}, true));
  }

  async completeEncryptionAction(jobId: string, revision: string, envelopes: ResourceLinkEnvelopeSubmission[]): Promise<EncryptionActionMutation> {
    return decode.encryptionActionMutation(await this.transport.request(`${this.applicationPath}/me/encryption-actions/${encodeURIComponent(bounded(jobId, "job id", 256))}/complete`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({ revision: bounded(revision, "revision", 128),
        envelopes: envelopes.map(wireResourceLinkEnvelope),
      }),
    }, true));
  }

  async completeEncryptionActionWithResourceKey(
    action: EncryptionAction,
    resourceKey: Uint8Array,
    keyMaterial: import("./key-access.js").DeviceKeyMaterial,
  ): Promise<EncryptionActionMutation> {
    const session = await this.session();
    if (!session.authenticated) throw new LotorBrowserError("Lotor request requires authentication", 401, "unauthenticated");
    const { createResourceEnvelope } = await import("./key-access.js");
    const envelopes = await Promise.all(action.keyRequirements.map(async (requirement) => {
      const envelope = await createResourceEnvelope({
        clientId: this.clientId, issuer: session.subject, issuerKeyId: keyMaterial.keyId,
        issuerSigningPrivateKey: keyMaterial.signingPrivateKey, resourceKey,
        member: {
          grantId: requirement.grantId, scope: requirement.keyResource, resource: requirement.resource,
          subject: requirement.recipientSubject, relation: requirement.relation,
          keyResource: requirement.keyResource, keyVersion: Number(requirement.keyVersion),
          recipientKeyId: requirement.recipientKeyId,
          recipientEncryptionPublicKey: requirement.publicKey,
        },
      });
      return {
        manifestItemId: requirement.manifestItemId, encryptionSuite: envelope.encryption_suite,
        ciphertext: envelope.ciphertext, aadHash: envelope.aad_hash, issuer: envelope.issuer,
        issuerKeyId: envelope.issuer_key_id, signature: envelope.signature,
      };
    }));
    return this.completeEncryptionAction(action.id, action.revision, envelopes);
  }

  async searchResourceLinkCandidates(resource: string, input: ResourceLinkCandidateSearchInput): Promise<ResourceLinkCandidateSearchResult> {
    return decode.resourceLinkCandidates(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/link-candidates/search`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({
        query: bounded(input.query, "query", 256), relation: bounded(input.relation, "relation", 128),
        ...(input.kinds === undefined ? {} : { kinds: input.kinds }), ...(input.limit === undefined ? {} : { limit: input.limit }),
        ...(input.cursor === undefined ? {} : { cursor: bounded(input.cursor, "cursor") }),
      }),
    }, true));
  }

  async preflightResourceLinks(resource: string, changes: ResourceLinkChange[]): Promise<ResourceLinkPreflight> {
    const normalizedResource = bounded(resource, "resource", 512);
    const wireChanges = changes.map((change) => ({
      action: change.action, ...(change.linkId === undefined ? {} : { link_id: change.linkId }),
      ...(change.collaborator === undefined ? {} : { collaborator: change.collaborator }),
      ...(change.relation === undefined ? {} : { relation: change.relation }),
      ...(change.subject === undefined ? {} : { subject: change.subject }), ...(change.email === undefined ? {} : { email: change.email }),
      ...(change.subjectResource === undefined ? {} : { subject_resource: change.subjectResource }),
      ...(change.subjectRelation === undefined ? {} : { subject_relation: change.subjectRelation }),
      ...(change.provisioning === undefined ? {} : { provisioning: change.provisioning }),
      ...(change.delivery === undefined ? {} : { delivery: change.delivery }), ...(change.cascade === undefined ? {} : { cascade: change.cascade }),
    }));
    const response = await this.transport.requestWithMetadata<unknown>(`${this.applicationPath}/resources/${encodeURIComponent(normalizedResource)}/links/preflight`, {
      method: "POST", headers: { "X-Lotor-Request": "lotor-js-v1" }, body: JSON.stringify({ changes: wireChanges }),
    }, true);
    const token = response.headers.get("Lotor-Link-Token")?.trim();
    if (!this.sameOrigin && !token) throw new Error("Lotor link preflight response is missing its token");
    return { result: decode.resourceLinkResult(response.body), ...(token ? { token } : {}) };
  }

  async commitResourceLinks(resource: string, preflight: ResourceLinkPreflight, envelopes: ResourceLinkEnvelopeSubmission[] = []): Promise<ResourceLinkResult> {
    const headers: Record<string, string> = { "X-Lotor-Request": "lotor-js-v1" };
    if (!this.sameOrigin) headers["Lotor-Link-Token"] = bounded(preflight.token ?? "", "link token", 512);
    return decode.resourceLinkResult(await this.transport.request(`${this.applicationPath}/resources/${encodeURIComponent(bounded(resource, "resource", 512))}/links/commit`, {
      method: "POST", headers, body: JSON.stringify(envelopes.length === 0 ? {} : { envelopes: envelopes.map(wireResourceLinkEnvelope) }),
    }, true));
  }

  async sendResourceLinks(resource: string, input: ResourceLinkSendInput): Promise<ResourceLinkSendResult> {
    const normalizedResource = bounded(resource, "resource", 512);
    const preflight = await this.preflightResourceLinks(normalizedResource, input.changes);
    if (!preflight.result.committable) throw new LotorBrowserError(
      preflight.result.failureReason ?? "Lotor rejected a collaboration change", 409,
      preflight.result.failureReason ?? "link_denied",
    );
    return { preflight, committed: await this.commitResourceLinks(normalizedResource, preflight) };
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

function wireResourceLinkEnvelope(envelope: ResourceLinkEnvelopeSubmission): Record<string, string> {
  return { manifest_item_id: bounded(envelope.manifestItemId, "manifest item", 256), encryption_suite: envelope.encryptionSuite,
    ciphertext: bounded(envelope.ciphertext, "ciphertext"), aad_hash: bounded(envelope.aadHash, "AAD hash", 128),
    issuer: bounded(envelope.issuer, "issuer", 512), issuer_key_id: bounded(envelope.issuerKeyId, "issuer key", 256),
    signature: bounded(envelope.signature, "signature", 256) };
}
