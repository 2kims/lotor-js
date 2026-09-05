export interface AnonymousSession {
  authenticated: false;
}

export interface AuthenticatedSession {
  authenticated: true;
  subject: string;
  email?: string;
  keyAccess?: { enabled: boolean; requiredBeforeSignupComplete: boolean; enrolled: boolean; activeKeyIds: string[]; setupDelivery: string };
  e2ee?: { claimRequired: boolean; claimId?: string; claimToken?: string };
}

export interface PublicKeyClaim {
  claimId: string;
  keyId: string;
  generation: number;
  status: "pending" | "transferring" | "completed" | "expired" | "cancelled";
  encryptionPublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  expiresAt: number;
}

export interface PublicKeyClaimTransfer extends PublicKeyClaim {
  encryptedPrivateBundle: Uint8Array;
  boxPublicKey: Uint8Array;
  nonce: Uint8Array;
  aadHash: string;
  associatedData: Uint8Array;
  encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
}

export interface ClaimSubjectKeyInput {
  claimId: string;
  passphrase: string;
  claimToken?: string;
}

export interface ClaimedSubjectKey extends SubjectKeyMutation {
  deviceId: string;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

export type ApplicationSession = AnonymousSession | AuthenticatedSession;

export interface PasswordlessChallenge {
  challenge_id: string;
  delivery: "email";
  expires_at: number;
}

export interface PublicApplicationConfiguration {
  clientId: string;
  application: { name: string };
  environment: { name: string; isProduction: boolean };
  authentication: { methods: string[] };
  e2ee: {
    enabled: boolean;
    allowedAccountCustody: Array<"browser_passphrase" | "temporary_box_then_browser" | "enterprise_box">;
    accountBackup: "lotor_opaque" | "customer_box_opaque" | "device_only";
    defaultResourceKeyExecutor: "managed" | "browser";
    browserActionsSupported: boolean;
  };
  keyAccess: {
    enabled: boolean;
    enrollment: {
      requirement: "" | "when_encrypted_resource_accessed" | "before_signup_complete";
      setupDelivery: "" | "email_link" | "in_session";
      passphraseSource: "" | "user_created";
      privateKeyBackup: "" | "disabled" | "lotor_opaque";
      passwordKDF: "" | "argon2id" | "scrypt";
      recoveryMethods: string[];
      setupLinkTTLSeconds: number;
    };
    resourceTypes: Array<{
      type: string;
      parentType: string;
      encryption: { mode: "none" | "optional" | "required" };
      payload: ResourcePayloadTypePolicy;
    }>;
  };
}

export interface PricingFeature {
  id: string;
  name: string;
  type: string;
  unit?: string;
  usageInterval?: string;
  defaultMaxUnit: number | null;
}

export interface PricingPrice {
  id: string;
  interval: string;
  currency: string;
  type: string;
  unitAmount: number;
  isDefault: boolean;
}

export interface PricingProduct {
  id: string;
  name: string;
  description?: string;
  type: string;
  tier: string;
  defaultCurrency: string;
  prices: PricingPrice[];
  features: PricingFeature[];
}

export interface PublicApplicationPricing {
  clientId: string;
  products: PricingProduct[];
}

export interface OrganizationSummary {
  id: string;
  name: string;
  currentRole: string;
  memberCount: number;
  pendingInvites: number;
}

export interface ResourceRegistration {
  resourceType: string;
  displayName?: string;
  parent?: string;
  keyScope?: "organization" | "resource";
}

export interface CollaborationResourceEncryption {
  required: boolean;
  status: "not_required" | "provisioning" | "ready" | "failed";
  keyScope?: "organization" | "resource";
  effectiveKeyResource?: string;
  keyResource?: string;
  keyVersion?: number;
}

export interface CollaborationResource {
  id: string;
  linkId?: string;
  resource: string;
  resourceType: string;
  displayName: string;
  parent?: string;
  status: "pending_encryption" | "pending_payload" | "pending_encryption_payload" | "active" | "disabled" | "deleting" | "failed" | "deleted";
  encryption: CollaborationResourceEncryption;
  catalogBinding?: ResourceCatalogBinding;
  revision: number;
  lifecycleGeneration: number;
}

export interface ResourceCatalogBinding {
  catalogId: string;
  snapshotId: string;
  snapshotDigest: string;
  entryKinds: Array<"api.operation">;
  resourceRevision: number;
}

export interface DurableOperation {
  id: string;
  kind: "resource_create" | "resource_move" | "resource_disable" | "resource_restore" | "resource_delete" | "catalog_import" | "catalog_publish" | "catalog_binding";
  status: "pending" | "running" | "succeeded" | "failed" | "cancelled";
  targetKind: "resource" | "catalog" | "catalog_snapshot";
  targetId: string;
  requestHash: string;
  errorCode?: string;
  createdAt: number;
  updatedAt: number;
}

export interface ResourceLifecycleFence {
  expectedRevision: number;
  expectedLifecycleGeneration: number;
}

export interface ResourceMoveInput extends ResourceLifecycleFence {
  parent: string;
}

export interface ResourceDeleteInput extends ResourceLifecycleFence {
  subtree: boolean;
}

export interface ResourcePayloadSlotPolicy {
  name: string;
  schemaIds: string[];
  maximumObjectSize: number;
  required: boolean;
}

export interface ResourcePayloadTypePolicy {
  storage: "none" | "lotor" | "provider";
  slots: ResourcePayloadSlotPolicy[];
}

interface ResourcePayloadManifestBase {
  resource: string;
  slot: string;
  schemaId: string;
  payloadVersion: number;
  objectDigest: string;
  objectSize: number;
  resourceRevision: number;
  lifecycleGeneration: number;
  state: "committed" | "deleting" | "deleted";
  committedAt: number;
  deletedAt?: number;
}

export interface RawResourcePayloadManifest extends ResourcePayloadManifestBase {
  representation: "raw";
}

export interface EncryptedResourcePayloadManifest extends ResourcePayloadManifestBase {
  representation: "encrypted-envelope-v1";
  encryptionSuite: "AES-256-GCM";
  keyBindingRef: string;
  keyVersion: number;
  wrappedPayloadKey: string;
  aadHash: string;
  encryptorSubject: string;
  encryptorKeyId: string;
}

export type ResourcePayloadManifest = RawResourcePayloadManifest | EncryptedResourcePayloadManifest;

interface ResourcePayloadUploadBase {
  schemaId: string;
  expectedPayloadVersion: number;
  objectDigest: string;
  objectSize: number;
  resourceRevision: number;
  lifecycleGeneration: number;
}

export interface RawResourcePayloadUploadInput extends ResourcePayloadUploadBase {
  representation: "raw";
}

export interface EncryptedResourcePayloadUploadInput extends ResourcePayloadUploadBase {
  representation: "encrypted-envelope-v1";
  encryptionSuite: "AES-256-GCM";
  keyBindingRef: string;
  keyVersion: number;
  wrappedPayloadKey: string;
  aadHash: string;
  /** Required for browser custody; omitted when the selected custody box attests during upload creation. */
  encryptorSubject?: string;
  encryptorKeyId?: string;
  encryptionReceipt?: string;
}

export type ResourcePayloadUploadInput = RawResourcePayloadUploadInput | EncryptedResourcePayloadUploadInput;

export interface ResourcePayloadRewrapInput {
  payloadVersion: number;
  expectedWrapRevision: number;
  keyBindingRef: string;
  previousKeyVersion: number;
  keyVersion: number;
  resourceRevision: number;
  lifecycleGeneration: number;
  /** Browser custody only; omit these four fields for managed/customer-box execution. */
  wrappedPayloadKey?: string;
  rewrapperSubject?: string;
  rewrapperKeyId?: string;
  rewrapReceipt?: string;
}

export interface ResourcePayloadRewrapResult {
  resource: string;
  slot: string;
  keyBindingRef: string;
  wrappedPayloadKey: string;
  aadHash: string;
  rewrapperSubject: string;
  rewrapperKeyId: string;
  payloadVersion: number;
  wrapRevision: number;
  previousKeyVersion: number;
  keyVersion: number;
  resourceRevision: number;
  lifecycleGeneration: number;
}

export interface ResourcePayloadUploadIntent {
  resource: string;
  slot: string;
  payloadVersion: number;
  expectedPayloadVersion: number;
  uploadUrl: string;
  uploadMethod: "PUT";
  requiredHeaders: Record<string, string>;
  expiresAt: number;
  /** Present only in cross-origin public API mode; same-origin mode uses a Strict cookie. */
  token?: string;
}

export interface ResourcePayloadAccessLease {
  resource: string;
  slot: string;
  payloadVersion: number;
  representation: "raw" | "encrypted-envelope-v1";
  objectDigest: string;
  objectSize: number;
  downloadUrl: string;
  downloadMethod: "GET";
  expiresAt: number;
  audience: string;
  resourceRevision: number;
  lifecycleGeneration: number;
}

export interface ResourcePayloadMutation {
  resource: string;
  slot: string;
  payloadVersion: number;
  state: "deleting" | "deleted";
  idempotent: boolean;
}

interface CheckoutSessionInput {
  organizationId: string;
  productId: string;
  priceId: string;
  idempotencyKey: string;
}

export interface CreateHostedCheckoutSessionInput extends CheckoutSessionInput {
  presentation: "hosted";
  successUrl: string;
  cancelUrl: string;
}

export interface CreateCustomCheckoutSessionInput extends CheckoutSessionInput {
  presentation: "custom";
  returnUrl: string;
}

export type CreateCheckoutSessionInput =
  | CreateHostedCheckoutSessionInput
  | CreateCustomCheckoutSessionInput;

export type CheckoutSession =
  | { id: string; presentation: "hosted"; url: string }
  | { id: string; presentation: "custom"; clientSecret: string; publishableKey: string };

export interface TokenStore {
  getToken(): string | null | Promise<string | null>;
  setToken(token: string): void | Promise<void>;
  clearToken(): void | Promise<void>;
}

export interface EnrollSubjectKeyInput {
  passphrase: string;
  deviceId?: string;
  backupPrivateKeys?: boolean;
}

export interface SubjectKeyMutation {
  accepted: boolean;
  reason: string;
  keyId: string;
  logSeq: number;
}

export interface SubjectKeyEnrollment extends SubjectKeyMutation {
  deviceId: string;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

export type { SubjectKeyRecord } from "./key-access.js";

export interface ResourceLinkChange {
  action: "grant" | "revoke";
  linkId?: string; collaborator?: string; relation?: string; subject?: string; email?: string;
  subjectResource?: string; subjectRelation?: string;
  provisioning?: "existing_only" | "create_if_missing";
  delivery?: "email" | "in_app" | "external" | "none" | "notification_only";
  cascade?: boolean;
}
export interface ResourceLinkCandidateSearchInput {
  query: string; relation: string; kinds?: Array<"user" | "group">; limit?: number; cursor?: string;
}
export interface ResourceLinkCandidate {
  kind: "user" | "group"; displayName: string; subject?: string; resource?: string;
  subjectRelation?: "member"; email?: string;
  linkState: "available" | "linked" | "pending_invitation"; selectable: boolean; reason?: string;
}
export interface ResourceLinkCandidateSearchResult { candidates: ResourceLinkCandidate[]; nextCursor: string | null }
export interface ResourceLinkOutcome {
  linkId?: string; resource: string; subject: string; relation: string;
  state: "active" | "pending_acceptance" | "pending_encryption" | "revoked" | "denied";
  allowed: boolean; reason?: string;
}
export interface ResourceLinkKeyRequirement {
  manifestItemId: string; grantId: string; resource: string; relation: string; keyResource: string; keyVersion: string;
  recipientSubject: string; recipientKeyId: string; encryptionAlgorithm: "X25519"; publicKey: Uint8Array;
  invitationId?: string; activation?: "active" | "pending_invitation";
}
export interface ResourceLinkEnvelopeSubmission {
  manifestItemId: string; encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: string; aadHash: string; issuer: string; issuerKeyId: string; signature: string;
}
export interface OrganizationE2EEPolicyInput {
  requiredAccountCustody: "browser_passphrase" | "temporary_box_then_browser" | "enterprise_box";
  resourceKeyExecutor: "managed" | "customer_box" | "browser";
  automationExecutor: "managed" | "customer_box" | "none";
  functionBindingId?: string;
  resourceKeyPolicy: "organization_only" | "organization_default" | "resource_only";
}
export interface OrganizationE2EEPolicy extends OrganizationE2EEPolicyInput {
  organization: string;
  status: "pending" | "ready" | "unavailable"; revision: number;
}
export interface ResourceSessionEnvelope {
  resource: string; keyResource: string; keyVersion: number;
  encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM"; ephemeralPublicKey: string;
  nonce: string; ciphertext: string; associatedData: string; aadHash: string; expiresAt: number;
}
export interface ResourceSession extends ResourceSessionEnvelope {
  resourceKey: Uint8Array;
}
export interface EncryptionAction {
  id: string; kind: "principal_key_enroll" | "resource_key_create" | "envelope_rewrap" | "resource_key_rotate";
  resource: string; status: "awaiting_browser"; revision: string; keyRequirements: ResourceLinkKeyRequirement[];
}
export interface EncryptionActionMutation { id: string; status: "projecting" | "completed"; idempotent: boolean }
export interface ResourceLinkResult {
  resource: string; status: "ready" | "committing" | "pending_acceptance" | "pending_encryption" | "active" | "failed" | "expired";
  failureReason?: string; expiresAt: number; idempotent: boolean; committable: boolean;
  revisions: { customer: string; graph: string; policy: string; identity: string; billing: string; seat: string; key: string };
  outcomes: ResourceLinkOutcome[];
  capacity: { scope: "per_organization" | "per_account"; before: number; after: number; claim: number; release: number };
  billing: { currentQuantity: number; nextCycleQuantity: number; increase: number; nextCycleReduction: number };
  invitationActions: Array<{ invitationId: string; action: "preserve" | "claim" | "activate" | "supersede" | "cancel"; reason?: string }>;
  keyRequirements: ResourceLinkKeyRequirement[];
  impact: { impactedResources: string[]; retainedResources: string[]; rekeyResources: string[] };
}
export interface ResourceLinkPreflight { result: ResourceLinkResult; token?: string }
export interface ResourceLinkSendInput {
  changes: ResourceLinkChange[];
}

export interface ResourceLinkSendResult {
	preflight: ResourceLinkPreflight;
	committed: ResourceLinkResult;
}

export interface UnlinkResult { id: string; resource: string; status: "revoked"; rekeyRequired: boolean; rekeySubjects: string[]; idempotent: boolean }
export interface CollaboratorPath { type: "direct" | "group"; relation: string; linkId?: string; group?: string; subjectRelation?: string; via: Array<{ resource: string; subjectRelation: string }> }
export interface ResourceCollaborator {
  kind: "user" | "group" | "invitation"; id: string; linkId?: string; resource?: string;
  displayName?: string; email?: string; relations: string[]; status: string; subjectRelation?: string;
  memberCount?: number; access?: { direct: boolean; paths: CollaboratorPath[] };
  recipient?: { type: "user" | "email" | "group"; subject?: string; display?: string }; expiresAt?: number;
}
export interface ResourceCollaboratorList { resource: string; collaborators: ResourceCollaborator[]; nextCursor: string | null }
export interface ResourceSearchResourceFilters {
  search?: string; resources?: string[]; types?: string[]; parent?: string; statuses?: string[];
}
export interface ResourceSearchCollaboratorFilters {
  search?: string; email?: string; subjects?: string[]; kinds?: Array<"user" | "group" | "invitation">;
  relations?: string[]; statuses?: string[]; view?: "direct" | "effective"; viaGroups?: string[];
  resourceSubject?: string; direct?: boolean;
}
export interface ResourceSearchInput {
  filters?: { resource?: ResourceSearchResourceFilters; collaborator?: ResourceSearchCollaboratorFilters };
  include?: Array<"parent" | "collaborator_matches">;
  sort?: { field?: "display_name" | "resource_type" | "resource"; direction?: "asc" | "desc" };
  page?: { limit?: number; cursor?: string };
}
export interface ResourceSearchParent { resource: string; resourceType: string; displayName: string }
export interface ResourceSearchResult {
  resource: string; resourceType: string; displayName: string; status: string;
  parent?: ResourceSearchParent; collaboratorMatches?: ResourceCollaborator[];
}
export interface ResourceSearchList { resources: ResourceSearchResult[]; nextCursor: string | null }
export interface AccountResourceReference { id: string; type: string; name: string }
export interface AccountResourcePathStep extends AccountResourceReference { subjectRelation: string }
export interface AccountResourceAccessPath { type: "direct" | "group"; relation: string; via: AccountResourcePathStep[] }
export interface AccountResource {
  id: string; type: string; name: string; parent?: AccountResourceReference; relations: string[];
  accessState: "active" | "pending_encryption";
  access: { direct: boolean; paths: AccountResourceAccessPath[] };
}
export interface AccountResourceList { resources: AccountResource[]; nextCursor: string | null }
export interface AccountResourceGroup { type: string; resources: AccountResource[] }

/** Groups an account resource page without assuming or hard-coding tenant resource types. */
export function groupResourcesByType(resources: readonly AccountResource[]): AccountResourceGroup[] {
  const grouped = new Map<string, AccountResource[]>();
  for (const resource of resources) {
    const items = grouped.get(resource.type);
    if (items) items.push(resource);
    else grouped.set(resource.type, [resource]);
  }
  return [...grouped].map(([type, items]) => ({ type, resources: items }));
}
export interface AccountInvitationResource { id: string; type: string; name: string }
export interface AccountInvitation {
  id: string; resource: AccountInvitationResource; relation: string;
  status: "pending_acceptance" | "pending_approval"; expiresAt: number; encryptionRequired: boolean;
}
export interface AccountInvitationList { invitations: AccountInvitation[]; nextCursor: string | null }
export interface AccountInvitationMutation { id: string; status: "active" | "pending_encryption" | "declined" }
export interface ResourceInvitationMutation { id: string; resource: string; relation: string; status: string; idempotent: boolean }
export interface ResourceCollaborationPolicyOverride { guests: { allowed?: boolean; allowed_domains?: string[] } }
export interface ResourceCollaborationPolicyMutation { resource: string; revision: number }

/** In-memory storage is intentionally non-persistent and is the SDK default. */
export class MemoryTokenStore implements TokenStore {
  private token: string | null = null;

  getToken(): string | null {
    return this.token;
  }

  setToken(token: string): void {
    this.token = token;
  }

  clearToken(): void {
    this.token = null;
  }
}
