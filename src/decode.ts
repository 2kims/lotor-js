import type {
  ApplicationSession,
  AuthenticatedSession,
  CheckoutSession,
  CollaborationResource,
  OrganizationSummary,
  PasswordlessChallenge,
  PublicApplicationConfiguration,
  PublicApplicationPricing,
  SubjectKeyMutation,
  ResourceLinkResult,
  ResourceLinkCandidateSearchResult,
  UnlinkResult,
  ResourceCollaborationPolicyMutation,
  ResourceCollaborator,
  ResourceCollaboratorList,
  ResourceSearchList,
  ResourceInvitationMutation,
  OrganizationE2EEPolicy,
  ResourceSessionEnvelope,
  EncryptionAction,
  EncryptionActionMutation,
} from "./types.js";
import { decodeBase64url, type EncryptedResourceEnvelope } from "./key-access.js";
import type { ResourceExecutionAuthorization, ResourceExecutionPreflight } from "./resource-execution.js";

export function resourceExecutionPreflight(value: unknown): ResourceExecutionPreflight {
  const input = record(value, "resource execution preflight");
  const allowed = ["request_fingerprint", "method", "path", "query", "content_type", "request_body_digest", "request_body_size", "resource", "resource_revision", "lifecycle_generation", "catalog_snapshot_id", "catalog_entry_id", "catalog_entry_revision", "policy_revision", "payload_slot", "payload_version", "payload_representation", "execution_mode", "key_resource", "key_version", "response_policy_ref", "request_aad", "expires_at"];
  if (Object.keys(input).some(key => !allowed.includes(key))) throw new Error("unexpected resource execution preflight field");
  const representation = enumString(input.payload_representation, "payload representation", ["raw", "encrypted-envelope-v1"] as const);
  const mode = enumString(input.execution_mode, "execution mode", ["raw", "managed", "customer_box"] as const);
  const result: ResourceExecutionPreflight = {
    requestFingerprint: digest(input.request_fingerprint, "request fingerprint"), resource: string(input.resource, "resource"),
    catalogEntryId: string(input.catalog_entry_id, "catalog entry"), payloadSlot: string(input.payload_slot, "payload slot"),
    payloadVersion: positiveInteger(input.payload_version, "payload version"), payloadRepresentation: representation,
    executionMode: mode, expiresAt: integer(input.expires_at, "execution expiry"), method: string(input.method, "method"),
    path: string(input.path, "path"), query: string(input.query, "query"), contentType: string(input.content_type, "content type"),
    requestBodyDigest: digest(input.request_body_digest, "request body digest"), requestBodySize: integer(input.request_body_size, "request body size"),
  };
  if ((representation === "raw") !== (mode === "raw")) throw new Error("inconsistent resource execution mode");
  if (input.request_aad !== undefined) result.requestAad = string(input.request_aad, "request AAD");
  if (input.response_policy_ref !== undefined) result.responsePolicyRef = enumString(input.response_policy_ref, "response policy", ["encrypt_all"] as const);
  if (input.key_resource !== undefined) result.keyResource = string(input.key_resource, "key resource");
  if (input.key_version !== undefined) result.keyVersion = positiveInteger(input.key_version, "key version");
  if (representation === "encrypted-envelope-v1" && (!result.requestAad || result.responsePolicyRef !== "encrypt_all" || !result.keyResource || result.keyVersion === undefined)) throw new Error("incomplete encrypted execution preflight");
  return result;
}

export function resourceExecutionAuthorization(value: unknown): ResourceExecutionAuthorization {
  const input = record(value, "resource execution authorization");
  const allowed = ["status", "request_fingerprint", "resource", "catalog_entry_id", "payload_slot", "payload_version", "payload_representation", "execution_mode", "provider_status", "protected_response", "expires_at"];
  if (Object.keys(input).some(key => !allowed.includes(key))) throw new Error("unexpected resource execution authorization field");
  const status = enumString(input.status, "execution status", ["authorized", "completed"] as const);
  const result: ResourceExecutionAuthorization = {
    status, requestFingerprint: digest(input.request_fingerprint, "request fingerprint"), resource: string(input.resource, "resource"),
    catalogEntryId: string(input.catalog_entry_id, "catalog entry"), payloadSlot: string(input.payload_slot, "payload slot"),
    payloadVersion: positiveInteger(input.payload_version, "payload version"),
    payloadRepresentation: enumString(input.payload_representation, "payload representation", ["raw", "encrypted-envelope-v1"] as const),
    executionMode: enumString(input.execution_mode, "execution mode", ["raw", "managed", "customer_box"] as const),
    expiresAt: integer(input.expires_at, "execution expiry"),
  };
  if (input.provider_status !== undefined) result.providerStatus = positiveInteger(input.provider_status, "provider status");
  if (input.protected_response !== undefined) result.protectedResponse = string(input.protected_response, "protected response");
  if (status === "completed" && (result.providerStatus === undefined || result.providerStatus > 599 || !result.protectedResponse)) throw new Error("incomplete completed execution");
  if (status === "authorized" && (result.providerStatus !== undefined || result.protectedResponse !== undefined)) throw new Error("invalid raw execution authorization");
  return result;
}

function digest(value: unknown, name: string): string {
  const result = string(value, name);
  if (!/^[a-f0-9]{64}$/u.test(result)) throw new Error(`invalid ${name}`);
  return result;
}

function positiveInteger(value: unknown, name: string): number {
  const result = integer(value, name);
  if (result < 1) throw new Error(`invalid ${name}`);
  return result;
}

export function scimDirectory(value: unknown): import("./types.js").SCIMDirectory {
  const input = record(value, "SCIM directory");
  const fields = ["id", "resource", "organization", "credential_resource", "status", "revision", "base_url"];
  if (Object.keys(input).some(key => !fields.includes(key))) throw new Error("unexpected SCIM directory field");
  for (const key of ["id", "resource", "organization", "credential_resource"]) {
    const text = string(input[key], key);
    if (!text || text.length > 256) throw new Error(`invalid SCIM ${key}`);
  }
  if (input.status !== "disabled" && input.status !== "active") throw new Error("invalid SCIM directory status");
  const revision = integer(input.revision, "SCIM revision");
  if (revision < 1) throw new Error("invalid SCIM revision");
  const baseUrl = string(input.base_url, "SCIM base URL");
  const url = new URL(baseUrl);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("invalid SCIM base URL");
  return { id: input.id as string, resource: input.resource as string, organization: input.organization as string,
    credentialResource: input.credential_resource as string, status: input.status, revision, baseUrl };
}

export function scimDirectoryList(value: unknown): import("./types.js").SCIMDirectoryList {
  const input = record(value, "SCIM directory list");
  if (Object.keys(input).some(key => key !== "directories" && key !== "next_cursor")) throw new Error("unexpected SCIM directory list field");
  const directories = array(input.directories, "SCIM directories").map(scimDirectory);
  if (directories.length > 100) throw new Error("SCIM page exceeds maximum");
  const nextCursor = input.next_cursor === null ? null : string(input.next_cursor, "SCIM cursor");
  if (nextCursor !== null && (!nextCursor || nextCursor.length > 4096)) throw new Error("invalid SCIM cursor");
  return { directories, nextCursor };
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`invalid ${name} response`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`invalid ${name} response`);
  return value;
}

function enumString<const T extends readonly string[]>(value: unknown, name: string, allowed: T): T[number] {
  const decoded = string(value, name);
  if (!(allowed as readonly string[]).includes(decoded)) throw new Error(`invalid ${name} response`);
  return decoded as T[number];
}

function number(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`invalid ${name} response`);
  return value;
}

function integer(value: unknown, name: string): number {
  const decoded = number(value, name);
  if (!Number.isSafeInteger(decoded) || decoded < 0) throw new Error(`invalid ${name} response`);
  return decoded;
}

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") throw new Error(`invalid ${name} response`);
  return value;
}

function array(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`invalid ${name} response`);
  return value;
}

function bytes(value: unknown, name: string): Uint8Array {
  return decodeBase64url(string(value, name));
}

export function resourceLinkResult(value: unknown): ResourceLinkResult {
  const input = record(value, "resource link result");
  const revisions = record(input.revisions, "resource link revisions");
  const capacity = record(input.capacity, "resource link capacity");
  const billing = record(input.billing, "resource link billing");
  const impact = record(input.impact, "resource link impact");
  return {
    resource: string(input.resource, "resource"), status: string(input.status, "link status") as ResourceLinkResult["status"],
    ...(input.failure_reason === undefined ? {} : { failureReason: string(input.failure_reason, "failure reason") }),
    expiresAt: integer(input.expires_at, "link expiry"), idempotent: boolean(input.idempotent, "link idempotent"),
    committable: boolean(input.committable, "link committable"),
    revisions: {
      customer: string(revisions.customer, "customer revision"), graph: string(revisions.graph, "graph revision"),
      policy: string(revisions.policy, "policy revision"), identity: string(revisions.identity, "identity revision"),
      billing: string(revisions.billing, "billing revision"), seat: string(revisions.seat, "seat revision"),
      key: string(revisions.key, "key revision"),
    },
    outcomes: array(input.outcomes, "link outcomes").map((raw) => { const item = record(raw, "link outcome"); return {
      ...(item.link_id === undefined ? {} : { linkId: string(item.link_id, "outcome link id") }),
      resource: string(item.resource, "outcome resource"), subject: string(item.subject, "outcome subject"),
      relation: string(item.relation, "outcome relation"), state: string(item.state, "outcome state") as ResourceLinkResult["outcomes"][number]["state"],
      allowed: boolean(item.allowed, "outcome allowed"), ...(item.reason === undefined ? {} : { reason: string(item.reason, "outcome reason") }),
    }; }),
    capacity: { scope: string(capacity.scope, "capacity scope") as "per_organization" | "per_account",
      before: integer(capacity.before, "capacity before"), after: integer(capacity.after, "capacity after"),
      claim: integer(capacity.claim, "capacity claim"), release: integer(capacity.release, "capacity release") },
    billing: { currentQuantity: integer(billing.current_quantity, "billing current"), nextCycleQuantity: integer(billing.next_cycle_quantity, "billing next"),
      increase: integer(billing.increase, "billing increase"), nextCycleReduction: integer(billing.next_cycle_reduction, "billing reduction") },
    invitationActions: array(input.invitation_actions, "invitation actions").map((raw) => { const item = record(raw, "invitation action"); return {
      invitationId: string(item.invitation_id, "invitation id"), action: string(item.action, "invitation action") as ResourceLinkResult["invitationActions"][number]["action"],
      ...(item.reason === undefined ? {} : { reason: string(item.reason, "invitation reason") }),
    }; }),
    keyRequirements: array(input.key_requirements, "key requirements").map((raw) => { const item = record(raw, "key requirement");
      if (item.encryption_algorithm !== "X25519") throw new Error("invalid key requirement algorithm");
      return { manifestItemId: string(item.manifest_item_id, "manifest item"), grantId: string(item.grant_id, "grant id"),
        resource: string(item.resource, "key resource target"),
        relation: string(item.relation, "key relation"), keyResource: string(item.key_resource, "key resource"), keyVersion: string(item.key_version, "key version"),
        recipientSubject: string(item.recipient_subject, "recipient subject"), recipientKeyId: string(item.recipient_key_id, "recipient key"),
        encryptionAlgorithm: "X25519" as const, publicKey: bytes(item.public_key, "recipient public key"),
        ...(item.invitation_id === undefined ? {} : { invitationId: string(item.invitation_id, "invitation id") }),
        ...(item.activation === undefined ? {} : { activation: enumString(item.activation, "key activation", ["active_access", "pending_invitation"] as const) }) }; }),
    impact: { impactedResources: array(impact.impacted_resources, "impacted resources").map((item) => string(item, "impacted resource")),
      retainedResources: array(impact.retained_resources, "retained resources").map((item) => string(item, "retained resource")),
      rekeyResources: array(impact.rekey_resources, "rekey resources").map((item) => string(item, "rekey resource")) },
  };
}

function keyRequirements(value: unknown): import("./types.js").ResourceLinkKeyRequirement[] {
  return resourceLinkResult({
    resource: "resource:decode", status: "ready", expires_at: 0, idempotent: false, committable: true,
    revisions: { customer: "", graph: "", policy: "", identity: "", billing: "", seat: "", key: "" },
    outcomes: [], capacity: { scope: "per_organization", before: 0, after: 0, claim: 0, release: 0 },
    billing: { current_quantity: 0, next_cycle_quantity: 0, increase: 0, next_cycle_reduction: 0 },
    invitation_actions: [], key_requirements: value,
    impact: { impacted_resources: [], retained_resources: [], rekey_resources: [] },
  }).keyRequirements;
}

export function organizationE2EEPolicy(value: unknown): OrganizationE2EEPolicy {
  const input = record(value, "organization E2EE policy");
  return { organization: string(input.organization, "organization"),
    requiredAccountCustody: string(input.required_account_custody, "required account custody") as OrganizationE2EEPolicy["requiredAccountCustody"],
    resourceKeyExecutor: string(input.resource_key_executor, "resource key executor") as OrganizationE2EEPolicy["resourceKeyExecutor"],
    automationExecutor: string(input.automation_executor, "automation executor") as OrganizationE2EEPolicy["automationExecutor"],
    ...(input.function_binding_id === undefined ? {} : { functionBindingId: string(input.function_binding_id, "function binding") }),
    resourceKeyPolicy: string(input.resource_key_policy, "resource key policy") as OrganizationE2EEPolicy["resourceKeyPolicy"],
    status: string(input.status, "E2EE policy status") as OrganizationE2EEPolicy["status"], revision: integer(input.revision, "E2EE policy revision") };
}

export function organizationFunctionBindingBootstrap(value: unknown): import("./types.js").OrganizationFunctionBindingBootstrap {
  const input = record(value, "organization box bootstrap");
  if (input.status !== "pending" || typeof input.binding_id !== "string" || !/^efb_[A-Za-z0-9_-]+$/.test(input.binding_id) || typeof input.bootstrap_token !== "string" || !input.bootstrap_token.startsWith("e2ee_bootstrap_") || input.bootstrap_token.length <= 15) throw new Error("invalid organization box bootstrap response");
  return { bindingId: input.binding_id, status: "pending", bootstrapToken: input.bootstrap_token };
}

export function organizationFunctionBindingStatus(value: unknown): import("./types.js").OrganizationFunctionBindingStatus {
  const input = record(value, "organization box status");
  if (typeof input.binding_id !== "string" || !/^efb_[A-Za-z0-9_-]+$/.test(input.binding_id) || !["pending", "expired", "active", "revoked"].includes(String(input.status)) || "bootstrap_token" in input || "connector_token" in input || "bootstrap_token_hash" in input || "connector_token_hash" in input) throw new Error("invalid organization box status response");
  return { bindingId: input.binding_id, status: input.status as import("./types.js").OrganizationFunctionBindingStatus["status"],
    challenge: organizationFunctionBindingChallengeStatus(input.challenge),
    ...(input.bootstrap_expires_at === undefined ? {} : { bootstrapExpiresAt: integer(input.bootstrap_expires_at, "bootstrap expiry") }),
    ...(input.last_seen_at === undefined ? {} : { lastSeenAt: integer(input.last_seen_at, "box last seen") }),
    ...(input.box_subject === undefined ? {} : { boxSubject: string(input.box_subject, "box subject") }),
    ...(input.signing_key_id === undefined ? {} : { signingKeyId: string(input.signing_key_id, "box signing key") }),
  };
}

export function organizationFunctionBindingChallengeStatus(value: unknown): import("./types.js").OrganizationFunctionBindingChallengeStatus {
  const input = record(value, "organization box challenge");
  if (!["not_started", "pending", "ready", "expired", "failed", "unavailable"].includes(String(input.status)) || Object.keys(input).some(key => !["status", "expires_at", "challenged_at"].includes(key))) throw new Error("invalid organization box challenge response");
  if ((input.status === "ready" && input.challenged_at === undefined) || (["pending", "expired"].includes(String(input.status)) && input.expires_at === undefined)) throw new Error("missing organization box challenge evidence");
  return { status: input.status as import("./types.js").OrganizationFunctionBindingChallengeStatus["status"],
    ...(input.expires_at === undefined ? {} : { expiresAt: integer(input.expires_at, "challenge expiry") }),
    ...(input.challenged_at === undefined ? {} : { challengedAt: integer(input.challenged_at, "challenge completion") }) };
}

export function resourceSessionEnvelope(value: unknown): ResourceSessionEnvelope {
  const input = record(value, "resource session envelope");
  return { resource: string(input.resource, "resource"), keyResource: string(input.key_resource, "key resource"),
    keyVersion: integer(input.key_version, "key version"), encryptionSuite: string(input.encryption_suite, "encryption suite") as ResourceSessionEnvelope["encryptionSuite"],
    ephemeralPublicKey: string(input.ephemeral_public_key, "ephemeral public key"), nonce: string(input.nonce, "nonce"),
    ciphertext: string(input.ciphertext, "ciphertext"), associatedData: string(input.associated_data, "associated data"),
    aadHash: string(input.aad_hash, "AAD hash"), expiresAt: integer(input.expires_at, "expiry") };
}

export function encryptionActions(value: unknown): EncryptionAction[] {
  const input = record(value, "encryption actions");
  return array(input.actions, "encryption actions").map((raw) => { const action = record(raw, "encryption action"); return {
    id: string(action.id, "action id"), kind: string(action.kind, "action kind") as EncryptionAction["kind"],
    resource: string(action.resource, "action resource"), status: string(action.status, "action status") as "awaiting_browser",
    revision: string(action.revision, "action revision"), keyRequirements: array(action.key_requirements, "key requirements").map((raw) => {
      const item = record(raw, "key requirement");
      const encoded = string(item.associated_data, "associated data");
      if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error("invalid associated data");
      const associatedData = bytes(encoded, "associated data");
      if (associatedData.length === 0) throw new Error("invalid associated data");
      return { ...keyRequirements([item])[0]!, associatedData };
    }),
  }; });
}

export function encryptionActionMutation(value: unknown): EncryptionActionMutation {
  const input = record(value, "encryption action mutation");
  return { id: string(input.id, "action id"), status: string(input.status, "action status") as EncryptionActionMutation["status"],
    idempotent: boolean(input.idempotent, "action idempotent") };
}

export function resourceLinkCandidates(value: unknown): ResourceLinkCandidateSearchResult {
  const input = record(value, "resource link candidates");
  return { candidates: array(input.candidates, "link candidates").map((raw) => { const item = record(raw, "link candidate"); return {
    kind: enumString(item.kind, "candidate kind", ["user", "group", "service_account"] as const), displayName: string(item.display_name, "candidate display name"),
    ...(item.subject === undefined ? {} : { subject: string(item.subject, "candidate subject") }),
    ...(item.resource === undefined ? {} : { resource: string(item.resource, "candidate resource") }),
    ...(item.subject_relation === undefined ? {} : { subjectRelation: string(item.subject_relation, "candidate subject relation") as "member" }),
    ...(item.email === undefined ? {} : { email: string(item.email, "candidate email") }),
    linkState: enumString(item.link_state, "candidate link state", ["available", "linked", "pending_invitation"] as const),
    selectable: boolean(item.selectable, "candidate selectable"), ...(item.reason === undefined ? {} : { reason: string(item.reason, "candidate reason") }),
  }; }), nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "candidate cursor") };
}

export function unlinkResult(value: unknown): UnlinkResult {
  const input = record(value, "unlink");
  if (input.status !== "revoked") throw new Error("invalid unlink status");
  return { id: string(input.id, "link id"), resource: string(input.resource, "resource"), status: "revoked",
    rekeyRequired: boolean(input.rekey_required, "rekey requirement"),
    rekeySubjects: array(input.rekey_subjects, "rekey subjects").map((item) => string(item, "rekey subject")),
    idempotent: boolean(input.idempotent, "unlink idempotency") };
}

export function resourcePolicyMutation(value: unknown): ResourceCollaborationPolicyMutation {
  const input = record(value, "resource collaboration policy");
  const revision = integer(input.revision, "policy revision");
  if (revision < 1) throw new Error("invalid policy revision response");
  return { resource: string(input.resource, "resource"), revision };
}

function resourceCollaborator(raw: unknown): ResourceCollaborator {
  const item = record(raw, "collaborator");
  const access = item.access === undefined ? undefined : record(item.access, "collaborator access");
  const recipient = item.recipient === undefined ? undefined : record(item.recipient, "collaborator recipient");
  return {
    kind: enumString(item.kind, "collaborator kind", ["user", "group", "service_account", "invitation"] as const), id: string(item.id, "collaborator id"),
    ...(item.link_id === undefined ? {} : { linkId: string(item.link_id, "collaborator link id") }),
    ...(item.resource === undefined ? {} : { resource: string(item.resource, "collaborator resource") }),
    ...(item.display_name === undefined ? {} : { displayName: string(item.display_name, "collaborator display name") }),
    ...(item.email === undefined ? {} : { email: string(item.email, "collaborator email") }),
    relations: array(item.relations, "collaborator relations").map(value => string(value, "collaborator relation")), status: string(item.status, "collaborator status"),
    ...(item.subject_relation === undefined ? {} : { subjectRelation: string(item.subject_relation, "collaborator subject relation") }),
    ...(item.member_count === undefined ? {} : { memberCount: integer(item.member_count, "collaborator member count") }),
    ...(access === undefined ? {} : { access: { direct: boolean(access.direct, "direct access"), paths: array(access.paths, "access paths").map(rawPath => { const path = record(rawPath, "access path"); return { type: string(path.type, "access path type") as "direct" | "group", relation: string(path.relation, "access path relation"), ...(path.link_id === undefined ? {} : { linkId: string(path.link_id, "access path link id") }), ...(path.group === undefined ? {} : { group: string(path.group, "access path group") }), ...(path.subject_relation === undefined ? {} : { subjectRelation: string(path.subject_relation, "access path subject relation") }), via: array(path.via, "access path steps").map(rawStep => { const step = record(rawStep, "access path step"); return { resource: string(step.resource, "path resource"), subjectRelation: string(step.subject_relation, "path subject relation") }; }) }; }) } }),
    ...(recipient === undefined ? {} : { recipient: { type: string(recipient.type, "recipient type") as "user" | "email" | "group", ...(recipient.subject === undefined ? {} : { subject: string(recipient.subject, "recipient subject") }), ...(recipient.display === undefined ? {} : { display: string(recipient.display, "recipient display") }) } }),
    ...(item.expires_at === undefined ? {} : { expiresAt: integer(item.expires_at, "collaborator expiry") }),
  };
}

export function collaborators(value: unknown): ResourceCollaboratorList {
  const input = record(value, "collaborators");
  return { resource: string(input.resource, "collaborator resource"),
    collaborators: array(input.collaborators, "collaborators").map(resourceCollaborator),
    nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "collaborator cursor") };
}

export function resourceSearch(value: unknown): ResourceSearchList {
  const input = record(value, "resource search");
  return {
    resources: array(input.resources, "resource search results").map((raw) => {
      const item = record(raw, "resource search result");
      const parent = item.parent === undefined ? undefined : record(item.parent, "resource search parent");
      return {
        resource: string(item.resource, "resource search resource"),
        resourceType: string(item.resource_type, "resource search resource type"),
        displayName: string(item.display_name, "resource search display name"),
        status: string(item.status, "resource search status"),
        ...(parent === undefined ? {} : { parent: {
          resource: string(parent.resource, "resource search parent resource"),
          resourceType: string(parent.resource_type, "resource search parent type"),
          displayName: string(parent.display_name, "resource search parent name"),
        } }),
        ...(item.collaborator_matches === undefined ? {} : {
          collaboratorMatches: array(item.collaborator_matches, "resource collaborator matches").map(resourceCollaborator),
        }),
      };
    }),
    nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "resource search cursor"),
  };
}

export function catalogEntry(value: unknown): import("./types.js").CatalogEntry {
  const item = record(value, "catalog entry");
  return { id: string(item.id, "entry id"), catalogId: string(item.catalog_id, "catalog id"),
    semanticKey: string(item.semantic_key, "semantic key"), entryKind: string(item.entry_kind, "entry kind"),
    revisionId: string(item.revision_id, "revision id"), revisionDigest: string(item.revision_digest, "revision digest"),
    definition: record(item.definition, "entry definition") };
}

export function resourceCredential(value: unknown): import("./types.js").ResourceCredentialMetadata {
  const item = record(value, "resource credential");
  return { id: string(item.id, "credential id"), resource: string(item.resource, "credential resource"),
    issuedTo: string(item.issued_to, "credential subject"), status: string(item.status, "credential status"),
    displayHint: string(item.display_hint, "credential hint"), version: integer(item.version, "credential version"),
    createdAt: integer(item.created_at, "credential creation"),
    ...(item.expires_at == null ? {} : { expiresAt: integer(item.expires_at, "credential expiry") }),
    ...(item.revoke_at == null ? {} : { revokeAt: integer(item.revoke_at, "credential revocation time") }),
    ...(item.revoked_at == null ? {} : { revokedAt: integer(item.revoked_at, "credential revoked time") }),
    ...(item.last_used_at == null ? {} : { lastUsedAt: integer(item.last_used_at, "credential last use") }),
  };
}

export function issuedResourceCredential(value: unknown): import("./types.js").IssuedResourceCredential {
  const item = record(value, "issued credential");
  return { ...resourceCredential(item), credential: string(item.credential, "credential presentation") };
}

export function resourceCredentials(value: unknown): import("./types.js").ResourceCredentialMetadata[] {
  return array(record(value, "resource credentials").items, "resource credentials").map(resourceCredential);
}

export function catalogEntries(value: unknown): import("./types.js").CatalogEntryList {
  const input = record(value, "catalog entries");
  return { items: array(input.items, "catalog entries").map(catalogEntry),
    nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "catalog cursor") };
}

export function discoverableCatalogs(value: unknown): import("./types.js").DiscoverableCatalogList {
  const input = record(value, "discoverable catalogs");
  return { nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "catalog cursor"),
    items: array(input.items, "catalogs").map(raw => {
      const item = record(raw, "catalog");
      if (item.catalog_type !== "api" && item.catalog_type !== "generic") throw new Error("invalid catalog type");
      if (item.visibility !== "application_private" && item.visibility !== "organization_private") throw new Error("invalid catalog visibility");
      if (item.discoverable !== true || item.status !== "active") throw new Error("invalid discoverable catalog");
      return { id: string(item.id, "catalog id"), namespace: string(item.namespace, "catalog namespace"),
        catalogType: item.catalog_type, visibility: item.visibility, publishedSnapshotId: string(item.published_snapshot_id, "published snapshot"),
        createdAt: integer(item.created_at, "catalog creation time"),
        ...(item.organization == null ? {} : { organization: string(item.organization, "catalog organization") }) };
    }) };
}

export function publishedCatalogEntries(value: unknown): import("./types.js").PublishedCatalogEntryList {
  return { ...catalogEntries(value), snapshotId: string(record(value, "published entries").snapshot_id, "published snapshot") };
}

function accountResourceReference(value: unknown, name: string): import("./types.js").AccountResourceReference {
  const input = record(value, name);
  const id = string(input.id, `${name} id`);
  return { id, resource: string(input.resource, `${name} resource`), type: string(input.type, `${name} type`), name: string(input.name, `${name} name`) };
}

export function accountResources(value: unknown): import("./types.js").AccountResourceList {
  const input = record(value, "account resources");
  return {
    resources: array(input.resources, "account resources").map((raw) => {
      const item = record(raw, "account resource");
      const resource = accountResourceReference(item, "account resource");
      const access = record(item.access, "account resource access");
      if (item.access_state !== "active" && item.access_state !== "pending_encryption") throw new Error("invalid account resource access state");
      return {
        ...resource,
        ...(item.parent === undefined ? {} : { parent: accountResourceReference(item.parent, "account resource parent") }),
        relations: array(item.relations, "account resource relations").map(rawRelation => string(rawRelation, "account resource relation")),
        accessState: item.access_state,
        access: {
          direct: boolean(access.direct, "account resource direct access"),
          paths: array(access.paths, "account resource access paths").map((rawPath) => {
            const path = record(rawPath, "account resource access path");
            if (path.type !== "direct" && path.type !== "group") throw new Error("invalid account resource access path type");
            return {
              type: path.type,
              relation: string(path.relation, "account resource access path relation"),
              via: array(path.via, "account resource access path steps").map((rawStep) => {
                const step = record(rawStep, "account resource access path step");
                return { ...accountResourceReference(step, "account resource access path step"), subjectRelation: string(step.subject_relation, "account resource access path subject relation") };
              }),
            };
          }),
        },
      };
    }),
    nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "account resource cursor"),
  };
}

export function accountInvitations(value: unknown): import("./types.js").AccountInvitationList {
  const input = record(value, "account invitations");
  return {
    invitations: array(input.invitations, "account invitations").map((raw) => {
      const item = record(raw, "account invitation");
      const resource = accountResourceReference(item.resource, "account invitation resource");
      if (item.status !== "pending_acceptance" && item.status !== "pending_approval") throw new Error("invalid account invitation status");
      return {
        id: string(item.id, "account invitation id"),
        resource,
        relation: string(item.relation, "account invitation relation"), status: item.status,
        expiresAt: integer(item.expires_at, "account invitation expiry"),
        encryptionRequired: boolean(item.encryption_required, "account invitation encryption requirement"),
      };
    }),
    nextCursor: input.next_cursor === null ? null : string(input.next_cursor, "account invitation cursor"),
  };
}

export function accountInvitationMutation(value: unknown): import("./types.js").AccountInvitationMutation {
  const input = record(value, "account invitation mutation");
  const status = string(input.status, "account invitation status");
  if (status !== "active" && status !== "pending_encryption" && status !== "declined") throw new Error("invalid account invitation mutation status");
  return { id: string(input.id, "account invitation id"), status };
}

export function resourceInvitationMutation(value: unknown): ResourceInvitationMutation {
  const input = record(value, "resource invitation mutation");
  return { id: string(input.id, "invitation id"), resource: string(input.resource, "invitation resource"), relation: string(input.relation, "invitation relation"), status: string(input.status, "invitation status"), idempotent: boolean(input.idempotent, "invitation idempotency") };
}

export function challenge(value: unknown): PasswordlessChallenge {
  const input = record(value, "passwordless challenge");
  if (input.delivery !== "email") throw new Error("invalid passwordless delivery");
  return {
    challenge_id: string(input.challenge_id, "challenge id"),
    delivery: "email",
    expires_at: number(input.expires_at, "challenge expiry"),
  };
}

export function verification(value: unknown): { token: string; session: AuthenticatedSession } {
	const input = record(value, "passwordless verification");
	const e2ee = input.e2ee === undefined ? undefined : record(input.e2ee, "passwordless E2EE");
	return {
    token: string(input.access_token, "access token"),
    session: {
      authenticated: true,
      subject: string(input.subject, "session subject"),
			email: string(input.email, "session email"),
			...(e2ee === undefined ? {} : { e2ee: {
				claimRequired: boolean(e2ee.claim_required, "E2EE claim requirement"),
				...(e2ee.claim_id === undefined ? {} : { claimId: string(e2ee.claim_id, "E2EE claim id") }),
			} }),
    },
  };
}

export function sameOriginVerification(value: unknown): AuthenticatedSession {
	const input = record(value, "same-origin passwordless verification");
	if (input.authenticated !== true) throw new Error("invalid authenticated session");
	const e2ee = input.e2ee === undefined ? undefined : record(input.e2ee, "passwordless E2EE");
	return {
		authenticated: true, subject: string(input.subject, "session subject"),
		...(e2ee === undefined ? {} : { e2ee: {
			claimRequired: boolean(e2ee.claim_required, "E2EE claim requirement"),
			...(e2ee.claim_id === undefined ? {} : { claimId: string(e2ee.claim_id, "E2EE claim id") }),
		} }),
	};
}

export function publicKeyClaim(value: unknown): import("./types.js").PublicKeyClaim {
	const input = record(value, "public key claim");
	const status = string(input.status, "public key claim status");
	if (!["pending", "transferring", "completed", "expired", "cancelled"].includes(status)) throw new Error("invalid public key claim status");
	const encryptionPublicKey = bytes(input.encryption_public_key, "claim encryption public key");
	const signingPublicKey = bytes(input.signing_public_key, "claim signing public key");
	if (encryptionPublicKey.length !== 32 || signingPublicKey.length !== 32) throw new Error("invalid public key claim key length");
	return {
		claimId: string(input.claim_id, "public key claim id"), keyId: string(input.key_id, "public key id"),
		generation: integer(input.generation, "public key generation"), status: status as import("./types.js").PublicKeyClaim["status"],
		encryptionPublicKey, signingPublicKey,
		expiresAt: integer(input.expires_at, "public key claim expiry"),
	};
}

export function publicKeyClaimTransfer(value: unknown, claim: import("./types.js").PublicKeyClaim): import("./types.js").PublicKeyClaimTransfer {
	const input = record(value, "public key claim transfer");
	if (input.encryption_suite !== "X25519-HKDF-SHA256-AES-256-GCM") throw new Error("invalid claim transfer suite");
	if (string(input.claim_id, "claim transfer id") !== claim.claimId || string(input.key_id, "claim transfer key id") !== claim.keyId || integer(input.generation, "claim transfer generation") !== claim.generation || integer(input.expires_at, "claim transfer expiry") !== claim.expiresAt) throw new Error("claim transfer context mismatch");
	const boxPublicKey = bytes(input.box_public_key, "box transfer public key");
	const nonce = bytes(input.nonce, "claim transfer nonce");
	if (boxPublicKey.length !== 32 || nonce.length !== 12) throw new Error("invalid claim transfer key material");
	return {
		...claim, status: "transferring", encryptedPrivateBundle: bytes(input.encrypted_private_bundle, "encrypted private bundle"),
		boxPublicKey, nonce,
		aadHash: string(input.aad_hash, "claim transfer AAD hash"), associatedData: bytes(input.associated_data, "claim transfer associated data"),
		encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM",
	};
}

export function session(value: unknown): ApplicationSession {
  const input = record(value, "session");
  if (input.authenticated !== true) throw new Error("invalid authenticated session");
  const keyAccess = input.key_access === undefined ? undefined : record(input.key_access, "session key access");
  return {
    authenticated: true,
    subject: string(input.subject, "session subject"),
    ...(input.email === undefined ? {} : { email: string(input.email, "session email") }),
    ...(keyAccess === undefined ? {} : { keyAccess: {
      enabled: boolean(keyAccess.enabled, "session key access enabled"),
      requiredBeforeSignupComplete: boolean(keyAccess.required_before_signup_complete, "key enrollment required"),
      enrolled: boolean(keyAccess.enrolled, "key enrollment status"),
      activeKeyIds: array(keyAccess.active_key_ids, "active key ids").map((item) => string(item, "active key id")),
      setupDelivery: string(keyAccess.setup_delivery, "key setup delivery"),
    } }),
  };
}

export function configuration(value: unknown): PublicApplicationConfiguration {
  const input = record(value, "application configuration");
  const application = record(input.application, "application");
  const environment = record(input.environment, "environment");
  const authentication = record(input.authentication, "authentication");
  const e2ee = record(input.e2ee, "E2EE configuration");
  const keyAccess = record(input.key_access ?? { enabled: false, enrollment: { requirement: "", setup_delivery: "", passphrase_source: "", private_key_backup: "", password_kdf: "", recovery_methods: [], setup_link_ttl_seconds: 0 }, resource_types: [] }, "key access configuration");
  const enrollment = record(keyAccess.enrollment, "key access enrollment");
  return {
    clientId: string(input.client_id, "client id"),
    application: { name: string(application.name, "application name") },
    environment: {
      name: string(environment.name, "environment name"),
      isProduction: boolean(environment.is_production, "environment production flag"),
    },
    authentication: {
      methods: array(authentication.methods, "authentication methods").map((item) => string(item, "authentication method")),
    },
    e2ee: {
      enabled: boolean(e2ee.enabled, "E2EE enabled"),
      allowedAccountCustody: array(e2ee.allowed_account_custody, "allowed account custody").map((item) => string(item, "account custody")) as PublicApplicationConfiguration["e2ee"]["allowedAccountCustody"],
      accountBackup: string(e2ee.account_backup, "account backup") as PublicApplicationConfiguration["e2ee"]["accountBackup"],
      defaultResourceKeyExecutor: string(e2ee.default_resource_key_executor, "default resource-key executor") as PublicApplicationConfiguration["e2ee"]["defaultResourceKeyExecutor"],
      browserActionsSupported: boolean(e2ee.browser_actions_supported, "browser actions supported"),
    },
    keyAccess: {
      enabled: boolean(keyAccess.enabled, "key access enabled"),
      enrollment: {
        requirement: string(enrollment.requirement, "key enrollment requirement") as PublicApplicationConfiguration["keyAccess"]["enrollment"]["requirement"],
        setupDelivery: string(enrollment.setup_delivery, "key setup delivery") as PublicApplicationConfiguration["keyAccess"]["enrollment"]["setupDelivery"],
        passphraseSource: string(enrollment.passphrase_source, "passphrase source") as PublicApplicationConfiguration["keyAccess"]["enrollment"]["passphraseSource"],
        privateKeyBackup: string(enrollment.private_key_backup, "private key backup") as PublicApplicationConfiguration["keyAccess"]["enrollment"]["privateKeyBackup"],
        passwordKDF: string(enrollment.password_kdf, "password KDF") as PublicApplicationConfiguration["keyAccess"]["enrollment"]["passwordKDF"],
        recoveryMethods: array(enrollment.recovery_methods, "recovery methods").map((item) => string(item, "recovery method")),
        setupLinkTTLSeconds: integer(enrollment.setup_link_ttl_seconds, "setup link TTL"),
      },
      resourceTypes: array(keyAccess.resource_types, "key access resource types").map((raw) => {
        const resource = record(raw, "key access resource type");
        const payload = record(resource.payload ?? { storage: "none", slots: [] }, "resource payload policy");
        return {
          type: string(resource.type, "resource type"), parentType: string(resource.parent_type, "resource parent type"),
          encryption: { mode: string(resource.mode, "resource encryption mode") as "none" | "optional" | "required" },
          payload: {
            storage: string(payload.storage, "resource payload storage") as import("./types.js").ResourcePayloadTypePolicy["storage"],
            slots: array(payload.slots, "resource payload slots").map((rawSlot) => {
              const slot = record(rawSlot, "resource payload slot");
              return {
                name: string(slot.name, "resource payload slot name"),
                schemaIds: array(slot.schema_ids, "resource payload schema ids").map((value) => string(value, "resource payload schema id")),
                maximumObjectSize: integer(slot.maximum_object_size, "resource payload maximum object size"),
                required: boolean(slot.required, "resource payload required"),
              };
            }),
          },
        };
      }),
    },
  };
}

export function pricing(value: unknown): PublicApplicationPricing {
  const input = record(value, "application pricing");
  return {
    clientId: string(input.client_id, "client id"),
    products: array(input.products, "pricing products").map((raw) => {
      const product = record(raw, "pricing product");
      return {
        id: string(product.id, "product id"),
        name: string(product.name, "product name"),
        ...(typeof product.description === "string" && product.description !== "" ? { description: product.description } : {}),
        type: string(product.type, "product type"),
        tier: string(product.tier, "product tier"),
        defaultCurrency: string(product.default_currency, "product default currency"),
        prices: array(product.prices, "product prices").map((item) => {
          const price = record(item, "price");
          return {
            id: string(price.id, "price id"),
            interval: string(price.interval, "price interval"),
            currency: string(price.currency, "price currency"),
            type: string(price.type, "price type"),
            unitAmount: integer(price.unit_amount, "price unit amount"),
            isDefault: boolean(price.is_default, "price default flag"),
          };
        }),
        features: array(product.features, "product features").map((item) => {
          const feature = record(item, "feature");
          return {
            id: string(feature.id, "feature id"),
            name: string(feature.name, "feature name"),
            type: string(feature.type, "feature type"),
            ...(typeof feature.unit === "string" && feature.unit !== "" ? { unit: feature.unit } : {}),
            ...(typeof feature.usage_interval === "string" && feature.usage_interval !== "" ? { usageInterval: feature.usage_interval } : {}),
            defaultMaxUnit: feature.default_max_unit === null ? null : integer(feature.default_max_unit, "feature default maximum"),
          };
        }),
      };
    }),
  };
}

export function organizations(value: unknown): OrganizationSummary[] {
  return array(value, "organizations").map((raw) => {
    const input = record(raw, "organization");
    return {
      id: string(input.id, "organization id"),
      name: string(input.name, "organization name"),
      currentRole: string(input.current_role, "organization role"),
      memberCount: integer(input.member_count, "organization member count"),
      pendingInvites: integer(input.pending_invites, "organization pending invites"),
    };
  });
}

export function organization(value: unknown): OrganizationSummary {
  return organizations([value])[0]!;
}

export function collaborationResource(value: unknown): CollaborationResource {
	const input = record(value, "collaboration resource");
	if (input.status !== "pending_encryption" && input.status !== "pending_payload" && input.status !== "pending_encryption_payload" && input.status !== "active" && input.status !== "disabled" && input.status !== "deleting" && input.status !== "failed" && input.status !== "deleted") throw new Error("invalid collaboration resource status");
	const encryption = record(input.encryption, "collaboration resource encryption");
	const binding = input.catalog_binding === undefined ? undefined : record(input.catalog_binding, "resource Catalog binding");
	return {
    id: string(input.id, "collaboration resource id"),
    ...(input.link_id === undefined ? {} : { linkId: string(input.link_id, "collaboration resource link id") }),
    ...(input.principal_subject === undefined ? {} : { principalSubject: string(input.principal_subject, "collaboration resource principal subject") }),
    resource: string(input.resource, "collaboration resource reference"),
    resourceType: string(input.resource_type, "collaboration resource type"),
    displayName: string(input.display_name, "collaboration resource name"),
    ...(input.parent === undefined ? {} : { parent: string(input.parent, "collaboration resource parent") }),
    status: input.status,
    revision: integer(input.revision, "collaboration resource revision"),
		lifecycleGeneration: integer(input.lifecycle_generation, "collaboration resource lifecycle generation"),
		...(binding === undefined ? {} : { catalogBinding: {
			resource: string(binding.resource, "resource Catalog binding resource"),
			catalogId: string(binding.catalog_id, "resource Catalog id"), snapshotId: string(binding.snapshot_id, "resource Catalog snapshot id"),
			snapshotDigest: string(binding.snapshot_digest, "resource Catalog snapshot digest"),
			entryKinds: array(binding.entry_kinds, "resource Catalog entry kinds").map(value => string(value, "resource Catalog entry kind")),
			resourceRevision: integer(binding.resource_revision, "resource Catalog revision"),
		} }),
    encryption: {
      required: boolean(encryption.required, "collaboration resource encryption required"),
      status: string(encryption.status, "collaboration resource encryption status") as CollaborationResource["encryption"]["status"],
      ...(encryption.key_scope === undefined ? {} : { keyScope: string(encryption.key_scope, "collaboration resource key scope") as "organization" | "resource" }),
      ...(encryption.effective_key_resource === undefined ? {} : { effectiveKeyResource: string(encryption.effective_key_resource, "collaboration resource effective key resource") }),
      ...(encryption.key_resource === undefined ? {} : { keyResource: string(encryption.key_resource, "collaboration resource key resource") }),
      ...(encryption.key_version === undefined ? {} : { keyVersion: integer(encryption.key_version, "collaboration resource key version") }),
    },
	};
}

export function durableOperation(value: unknown): import("./types.js").DurableOperation {
	const input = record(value, "durable operation");
	const kind = string(input.kind, "durable operation kind") as import("./types.js").DurableOperation["kind"];
	const status = string(input.status, "durable operation status") as import("./types.js").DurableOperation["status"];
	const targetKind = string(input.target_kind, "durable operation target kind") as import("./types.js").DurableOperation["targetKind"];
	if (!["resource_create", "resource_move", "resource_disable", "resource_restore", "resource_delete", "catalog_import", "catalog_publish", "catalog_binding"].includes(kind)) throw new Error("invalid durable operation kind");
	if (!["pending", "running", "succeeded", "failed", "cancelled"].includes(status)) throw new Error("invalid durable operation status");
	if (!["resource", "catalog", "catalog_snapshot"].includes(targetKind)) throw new Error("invalid durable operation target kind");
	return {
		id: string(input.id, "durable operation id"), kind, status, targetKind,
		targetId: string(input.target_id, "durable operation target"), requestHash: string(input.request_hash, "durable operation request hash"),
		...(input.error_code === undefined ? {} : { errorCode: string(input.error_code, "durable operation error code") }),
		createdAt: integer(input.created_at, "durable operation creation time"), updatedAt: integer(input.updated_at, "durable operation update time"),
	};
}

export function resourcePayloadManifest(value: unknown): import("./types.js").ResourcePayloadManifest {
  const input = record(value, "resource payload manifest");
  const representation = string(input.representation, "resource payload representation") as "raw" | "encrypted-envelope-v1";
  const common = {
    resource: string(input.resource, "resource payload resource"), slot: string(input.slot, "resource payload slot"),
    schemaId: string(input.schema_id, "resource payload schema"), payloadVersion: integer(input.payload_version, "resource payload version"),
    objectDigest: string(input.object_digest, "resource payload digest"), objectSize: integer(input.object_size, "resource payload size"),
    resourceRevision: integer(input.resource_revision, "resource payload resource revision"), lifecycleGeneration: integer(input.lifecycle_generation, "resource payload lifecycle generation"),
    state: string(input.state, "resource payload state") as "committed" | "deleting" | "deleted", committedAt: integer(input.committed_at, "resource payload commit time"),
    ...(input.deleted_at === undefined ? {} : { deletedAt: integer(input.deleted_at, "resource payload deletion time") }),
  };
  if (representation === "raw") return { ...common, representation };
  if (representation !== "encrypted-envelope-v1") throw new Error("resource payload representation is invalid");
  return {
    ...common, representation,
    encryptionSuite: string(input.encryption_suite, "resource payload encryption suite") as "AES-256-GCM",
    keyBindingRef: string(input.key_binding_ref, "resource payload key binding reference"), keyVersion: integer(input.key_version, "resource payload key version"),
    wrappedPayloadKey: string(input.wrapped_payload_key, "wrapped payload key"), aadHash: string(input.aad_hash, "resource payload AAD hash"),
    encryptorSubject: string(input.encryptor_subject, "resource payload encryptor subject"), encryptorKeyId: string(input.encryptor_key_id, "resource payload encryptor key"),
  };
}

export function resourcePayloadUploadIntent(value: unknown): import("./types.js").ResourcePayloadUploadIntent {
  const input = record(value, "resource payload upload intent");
  const headers = record(input.required_headers, "resource payload upload headers");
  return {
	resource: string(input.resource, "resource payload resource"), slot: string(input.slot, "resource payload slot"),
	payloadVersion: integer(input.payload_version, "resource payload version"),
	expectedPayloadVersion: integer(input.expected_payload_version, "resource payload expected version"),
	uploadUrl: string(input.upload_url, "resource payload upload URL"),
    uploadMethod: string(input.upload_method, "resource payload upload method") as "PUT",
    requiredHeaders: Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, string(value, `resource payload header ${name}`)])),
    expiresAt: integer(input.expires_at, "resource payload upload expiry"),
  };
}

export function resourcePayloadAccessLease(value: unknown): import("./types.js").ResourcePayloadAccessLease {
  const input = record(value, "resource payload access lease");
  return {
    resource: string(input.resource, "resource payload resource"), slot: string(input.slot, "resource payload slot"), payloadVersion: integer(input.payload_version, "resource payload version"),
    representation: string(input.representation, "resource payload representation") as "raw" | "encrypted-envelope-v1",
    objectDigest: string(input.object_digest, "resource payload digest"), objectSize: integer(input.object_size, "resource payload size"),
    downloadUrl: string(input.download_url, "resource payload download URL"), downloadMethod: string(input.download_method, "resource payload download method") as "GET",
    expiresAt: integer(input.expires_at, "resource payload lease expiry"), audience: string(input.audience, "resource payload audience"),
    resourceRevision: integer(input.resource_revision, "resource payload resource revision"), lifecycleGeneration: integer(input.lifecycle_generation, "resource payload lifecycle generation"),
  };
}

export function resourcePayloadMutation(value: unknown): import("./types.js").ResourcePayloadMutation {
  const input = record(value, "resource payload mutation");
  return { resource: string(input.resource, "resource payload resource"), slot: string(input.slot, "resource payload slot"), payloadVersion: integer(input.payload_version, "resource payload version"), state: string(input.state, "resource payload state") as "deleting" | "deleted", idempotent: boolean(input.idempotent, "resource payload idempotency") };
}

export function resourcePayloadRewrapResult(value: unknown): import("./types.js").ResourcePayloadRewrapResult {
  const input = record(value, "resource payload rewrap result");
  return {
    resource: string(input.resource, "resource payload resource"), slot: string(input.slot, "resource payload slot"),
    payloadVersion: integer(input.payload_version, "resource payload version"), wrapRevision: integer(input.wrap_revision, "resource payload wrap revision"),
    keyBindingRef: string(input.key_binding_ref, "resource payload key binding"), previousKeyVersion: integer(input.previous_key_version, "previous resource key version"),
    keyVersion: integer(input.key_version, "resource key version"), wrappedPayloadKey: string(input.wrapped_payload_key, "wrapped payload key"),
    aadHash: string(input.aad_hash, "resource payload AAD hash"), rewrapperSubject: string(input.rewrapper_subject, "resource payload rewrapper subject"),
    rewrapperKeyId: string(input.rewrapper_key_id, "resource payload rewrapper key"), resourceRevision: integer(input.resource_revision, "resource revision"),
    lifecycleGeneration: integer(input.lifecycle_generation, "resource lifecycle generation"),
  };
}

export function portal(value: unknown): import("./types.js").PortalSession {
  const raw = record(value, "portal session");
  const url = string(raw.url, "portal URL");
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("invalid portal URL");
  return { id: string(raw.id, "portal ID"), url };
}

export function checkout(value: unknown): CheckoutSession {
  const input = record(value, "checkout session");
  const id = string(input.id, "checkout session id");
  if (input.presentation === "hosted") {
    return { id, presentation: "hosted", url: string(input.url, "checkout session URL") };
  }
  if (input.presentation === "custom") {
    return {
      id,
      presentation: "custom",
      clientSecret: string(input.client_secret, "checkout client secret"),
      publishableKey: string(input.publishable_key, "checkout publishable key"),
    };
  }
  throw new Error("invalid checkout session response");
}

export function subjectKeyMutation(value: unknown): SubjectKeyMutation {
  const input = record(value, "subject key mutation");
  return {
    accepted: boolean(input.accepted, "subject key accepted"),
    reason: string(input.reason, "subject key reason"),
    keyId: string(input.key_id, "subject key id"),
    logSeq: integer(input.log_seq, "subject key log sequence"),
  };
}

export function subjectKeys(value: unknown): import("./key-access.js").SubjectKeyRecord[] {
  const input = record(value, "subject keys");
  return array(input.keys, "subject keys").map((raw) => {
    const key = record(raw, "subject key");
    const encryptionAlgorithm = string(key.encryption_algorithm, "subject encryption algorithm");
    const signingAlgorithm = string(key.signing_algorithm, "subject signing algorithm");
    const backupKDF = string(key.backup_kdf, "subject backup KDF");
    const status = string(key.status, "subject key status");
    if (encryptionAlgorithm !== "X25519" || signingAlgorithm !== "Ed25519") throw new Error("unsupported subject key algorithm");
    if (backupKDF !== "" && backupKDF !== "scrypt") throw new Error("unsupported subject key backup KDF");
    if (status !== "active" && status !== "revoked") throw new Error("invalid subject key status");
    return {
      keyId: string(key.key_id, "subject key id"), deviceId: string(key.device_id, "subject device id"),
      encryptionAlgorithm, encryptionPublicKey: bytes(key.encryption_public_key, "subject encryption public key"),
      signingAlgorithm, signingPublicKey: bytes(key.signing_public_key, "subject signing public key"),
      encryptedPrivateKeyBackup: bytes(key.encrypted_private_key_backup, "encrypted private-key backup"),
      backupKDF, backupSalt: bytes(key.backup_salt, "subject backup salt"), backupNonce: bytes(key.backup_nonce, "subject backup nonce"),
      backupFormatVersion: integer(key.backup_format_version, "subject backup format version"), status,
      logSeq: integer(key.log_seq, "subject key log sequence"),
    };
  });
}

export function resourceEnvelope(value: unknown): EncryptedResourceEnvelope {
  const input = record(value, "resource envelope");
  if (input.encryption_suite !== "X25519-HKDF-SHA256-AES-256-GCM") throw new Error("invalid resource envelope suite");
  if (input.issuer_signing_algorithm !== "Ed25519") throw new Error("invalid resource envelope issuer algorithm");
  if (input.issuer_key_status !== "active" && input.issuer_key_status !== "revoked") throw new Error("invalid resource envelope issuer status");
  return { grantId: string(input.grant_id, "grant id"), scope: string(input.scope, "scope"), resource: string(input.resource, "resource"), subject: string(input.recipient_subject, "recipient subject"), relation: string(input.relation, "relation"), keyResource: string(input.key_resource, "key resource"), keyVersion: integer(input.key_version, "key version"), recipientKeyId: string(input.recipient_key_id, "recipient key id"), encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM", ciphertext: bytes(input.ciphertext, "ciphertext"), aadHash: bytes(input.aad_hash, "AAD hash"), issuer: string(input.issuer, "issuer"), issuerKeyId: string(input.issuer_key_id, "issuer key id"), issuerSigningAlgorithm: "Ed25519", issuerSigningPublicKey: bytes(input.issuer_signing_public_key, "issuer signing public key"), issuerKeyStatus: input.issuer_key_status, signature: bytes(input.signature, "signature") };
}
