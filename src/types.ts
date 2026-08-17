import type { DeviceKeyMaterial } from "./key-access.js";

export interface AnonymousSession {
  authenticated: false;
}

export interface AuthenticatedSession {
  authenticated: true;
  subject: string;
  email: string;
  keyAccess?: { enabled: boolean; requiredBeforeSignupComplete: boolean; enrolled: boolean; activeKeyIds: string[]; setupDelivery: string };
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
    resourceTypes: Array<{ type: string; parentType: string; encryption: { mode: "none" | "optional" | "required"; defaultKeyStrategy: "none" | "resource_key" | "inherited"; allowInherited: boolean } }>;
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
}

export interface CollaborationResource {
  id: string;
  resource: string;
  resourceType: string;
  displayName: string;
  parent?: string;
  status: "active" | "deleted";
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

export interface ResourceMember {
  grantId: string;
  scope: string;
  subject: string;
  relation: string;
  resource: string;
  keyResource: string;
  keyVersion: number;
  recipientKeyId: string;
  invitationId: string;
  status: "pending_provisioning" | "active" | "revoked";
  recipientKeyStatus: "active" | "revoked" | "";
  recipientEncryptionPublicKey: Uint8Array;
  logSeq: number;
}

export interface ResourceGrantMutation {
  accepted: boolean;
  reason: string;
  grantId: string;
  status: string;
  logSeq: number;
}

export interface ResourceKeyVersionInput {
  scope: string;
  keyResource: string;
  version: number;
  algorithm?: "AES-256-GCM";
}

export interface ResourceKeyMutation {
  accepted: boolean;
  reason: string;
  keyResource: string;
  version: number;
  logSeq: number;
}

export interface ResourceGrantInput {
  grantId: string;
  scope: string;
  resource: string;
  subject: string;
  relation: string;
  keyResource: string;
  keyVersion: number;
  recipientKeyId: string;
  invitationId?: string;
}

export interface EncryptedInvitationMutation {
  accepted: boolean;
  reason: string;
  invitationId: string;
  logSeq: number;
}

export interface LinkTargetInput {
  type: "invite" | "direct";
  email?: string;
  subject?: string;
  resource?: string;
  subject_relation?: string;
  provisioning?: "existing_only" | "create_if_missing";
  delivery?: "email" | "in_app" | "external" | "none";
}

export interface LinkRecipientKey {
  subject: string; grantId: string; keyId: string;
  encryptionAlgorithm: "X25519"; publicKey: Uint8Array;
}

export interface LinkTargetDecision {
  id: string; type: "invite" | "direct"; kind: "email" | "user" | "group";
  email?: string; subject?: string; resource?: string; subjectRelation?: string;
  classification: "internal" | "guest" | "group" | "unknown";
  provisioning: "existing_only" | "create_if_missing";
  delivery: "email" | "in_app" | "external" | "none";
  reasonCode: string; message: string; recipientKeys: LinkRecipientKey[];
  acceptanceRequired: boolean; encryptionReady: boolean; allowed: boolean;
}

export interface LinkSourceEnvelope {
  grantId: string; scope: string; resource: string; relation: string;
  keyResource: string; subject: string; recipientKeyId: string;
  encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: Uint8Array; aadHash: Uint8Array; issuer: string;
  issuerKeyId: string; issuerSigningAlgorithm: "Ed25519";
  issuerSigningPublicKey: Uint8Array; issuerKeyStatus: "active" | "revoked";
  signature: Uint8Array; keyVersion: number;
}

export interface LinkPreflight {
  preflightId: string; resource: string; relation: string; policyRevision: string;
  expiresAt: number; targets: LinkTargetDecision[];
  encryption: { required: boolean; keyResource?: string; sourceEnvelope?: LinkSourceEnvelope; ready: boolean };
  ready: boolean; idempotent: boolean;
}

export interface LinkPreflightInput { relation: string; targets: LinkTargetInput[]; ttl_seconds?: number }
export interface LinkEnvelopeInput {
  grant_id: string; recipient_subject: string; recipient_key_id: string;
  encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: string; aad_hash: string; issuer_key_id: string; signature: string;
}
export interface LinkSendInput { preflight_id: string; targets: Array<{ target_id: string; envelopes?: LinkEnvelopeInput[] }> }
export interface LinkMutation { id: string; targetId: string; type: "invite" | "direct"; subject: string; status: string; invitationId?: string; ticket?: string }
export interface LinkSendResult { preflightId: string; resource: string; links: LinkMutation[] }

export type SubjectKeyCredentials =
  | { passphrase: string; keyMaterial?: never }
  | { passphrase?: never; keyMaterial: DeviceKeyMaterial };

export type EnsureEncryptedResourceInput = {
  scope: string;
  resource: string;
  keyResource?: string;
  relation?: string;
  version?: number;
  resourceKey: Uint8Array;
} & SubjectKeyCredentials;

export interface EnsureEncryptedResourceResult {
  created: boolean;
  keyResource: string;
  version: number;
  grantId: string;
}

export type EncryptedResourceLinkInput = {
  relation: string;
  targets: LinkTargetInput[];
  resourceKey: Uint8Array;
  preflightIdempotencyKey: string;
  sendIdempotencyKey?: string;
  ttlSeconds?: number;
} & SubjectKeyCredentials;

export interface EncryptedResourceLinkResult {
  preflight: LinkPreflight;
  sent: LinkSendResult;
}

export interface KeyProvisioningJob {
  grantId: string;
  linkId: string;
  resource: string;
  relation: string;
  keyResource: string;
  keyVersion: number;
  subject: string;
  recipientKeyId: string;
  encryptionAlgorithm: "X25519";
  publicKey: Uint8Array;
  linkStatus: "pending_acceptance" | "pending_encryption" | "active";
}

export interface KeyProvisioningJobList {
  resource: string;
  jobs: KeyProvisioningJob[];
}

export type ProvisionEncryptedResourceLinksInput = {
  resourceKey: Uint8Array;
} & SubjectKeyCredentials;

export interface KeyProvisioningMutation {
  resource: string;
  submitted: number;
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
export interface ResourceCollaboratorMutation {
  resource: string;
  collaborator: string;
  relations: string[];
  status: string;
  force?: boolean;
  cascaded_groups?: string[];
  rekey_required?: boolean;
  rekey_resources?: string[];
}
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
