import type {
  ApplicationSession,
  AuthenticatedSession,
  CheckoutSession,
  OrganizationSummary,
  PasswordlessChallenge,
  PublicApplicationConfiguration,
  PublicApplicationPricing,
  SubjectKeyMutation,
  ResourceGrantMutation,
  ResourceMember,
} from "./types.js";
import { decodeBase64url, type EncryptedResourceEnvelope } from "./key-access.js";

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
  return {
    token: string(input.access_token, "access token"),
    session: {
      authenticated: true,
      subject: string(input.subject, "session subject"),
      email: string(input.email, "session email"),
    },
  };
}

export function session(value: unknown): ApplicationSession {
  const input = record(value, "session");
  if (input.authenticated !== true) throw new Error("invalid authenticated session");
  const keyAccess = input.key_access === undefined ? undefined : record(input.key_access, "session key access");
  return {
    authenticated: true,
    subject: string(input.subject, "session subject"),
    email: string(input.email, "session email"),
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
        return { type: string(resource.type, "resource type"), parentType: string(resource.parent_type, "resource parent type"), encryption: { mode: string(resource.mode, "resource encryption mode") as "none" | "optional" | "required", defaultKeyStrategy: string(resource.default_key_strategy, "resource key strategy") as "none" | "resource_key" | "inherited", allowInherited: boolean(resource.allow_inherited, "allow inherited key") } };
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

export function resourceGrantMutation(value: unknown): ResourceGrantMutation {
  const input = record(value, "resource grant mutation");
  return { accepted: boolean(input.accepted, "resource grant accepted"), reason: string(input.reason, "resource grant reason"), grantId: string(input.grant_id, "resource grant id"), status: string(input.status, "resource grant status"), logSeq: integer(input.log_seq, "resource grant log sequence") };
}

export function encryptedInvitationMutation(value: unknown): import("./types.js").EncryptedInvitationMutation {
  const input = record(value, "encrypted invitation mutation");
  return { accepted: boolean(input.accepted, "invitation accepted"), reason: string(input.reason, "invitation reason"), invitationId: string(input.invitation_id, "invitation id"), logSeq: integer(input.log_seq, "invitation log sequence") };
}

export function resourceMembers(value: unknown, scope: string): ResourceMember[] {
  const input = record(value, "resource members");
  return array(input.members, "resource members").map((raw) => {
    const member = record(raw, "resource member");
    const status = string(member.status, "resource member status");
    if (status !== "pending_provisioning" && status !== "active" && status !== "revoked") throw new Error("invalid resource member status");
    const keyStatus = string(member.recipient_key_status, "recipient key status");
    if (keyStatus !== "" && keyStatus !== "active" && keyStatus !== "revoked") throw new Error("invalid recipient key status");
    return { grantId: string(member.grant_id, "grant id"), subject: string(member.subject, "member subject"), relation: string(member.relation, "member relation"), resource: string(member.resource, "member resource"), keyResource: string(member.key_resource, "key resource"), keyVersion: integer(member.key_version, "key version"), recipientKeyId: string(member.recipient_key_id, "recipient key id"), invitationId: string(member.invitation_id, "invitation id"), status, recipientKeyStatus: keyStatus, recipientEncryptionPublicKey: bytes(member.recipient_encryption_public_key, "recipient public key"), logSeq: integer(member.log_seq, "member log sequence"), scope };
  });
}

export function resourceEnvelope(value: unknown): EncryptedResourceEnvelope {
  const input = record(value, "resource envelope");
  if (input.encryption_suite !== "X25519-HKDF-SHA256-AES-256-GCM") throw new Error("invalid resource envelope suite");
  return { grantId: string(input.grant_id, "grant id"), scope: string(input.scope, "scope"), resource: string(input.resource, "resource"), subject: string(input.recipient_subject, "recipient subject"), relation: string(input.relation, "relation"), keyResource: string(input.key_resource, "key resource"), keyVersion: integer(input.key_version, "key version"), recipientKeyId: string(input.recipient_key_id, "recipient key id"), recipientEncryptionPublicKey: new Uint8Array(), encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM", ciphertext: bytes(input.ciphertext, "ciphertext"), aadHash: bytes(input.aad_hash, "AAD hash"), issuer: string(input.issuer, "issuer"), issuerKeyId: string(input.issuer_key_id, "issuer key id"), signature: bytes(input.signature, "signature") };
}
