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
  ResourceGrantMutation,
  ResourceMember,
  LinkPreflight,
  LinkSendResult,
  UnlinkResult,
  ResourceCollaborationPolicyMutation,
  ResourceCollaborator,
  ResourceCollaboratorList,
  ResourceSearchList,
  ResourceInvitationMutation,
  ResourceCollaboratorMutation,
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

export function linkPreflight(value: unknown): LinkPreflight {
  const input = record(value, "link preflight");
  const encryption = record(input.encryption, "link encryption");
  const source = encryption.source_envelope === undefined ? undefined : record(encryption.source_envelope, "source envelope");
  return {
    preflightId: string(input.preflight_id, "preflight id"), resource: string(input.resource, "resource"),
    relation: string(input.relation, "relation"), policyRevision: string(input.policy_revision, "policy revision"),
    expiresAt: integer(input.expires_at, "preflight expiry"),
    targets: array(input.targets, "link targets").map((item) => {
      const target = record(item, "link target");
      return {
        id: string(target.id, "target id"), type: string(target.type, "link type") as "invite" | "direct",
        kind: string(target.kind, "target kind") as "email" | "user" | "group",
        ...(target.email === undefined ? {} : { email: string(target.email, "target email") }),
        ...(target.subject === undefined ? {} : { subject: string(target.subject, "target subject") }),
        ...(target.resource === undefined ? {} : { resource: string(target.resource, "target resource") }),
        ...(target.subject_relation === undefined ? {} : { subjectRelation: string(target.subject_relation, "subject relation") }),
        classification: string(target.classification, "classification") as "internal" | "guest" | "group" | "unknown",
        provisioning: string(target.provisioning, "provisioning") as "existing_only" | "create_if_missing",
        delivery: string(target.delivery, "delivery") as "email" | "in_app" | "external" | "none",
        reasonCode: string(target.reason_code, "reason code"), message: string(target.message, "message"),
        recipientKeys: array(target.recipient_keys, "recipient keys").map((item) => {
          const key = record(item, "recipient key");
          if (key.encryption_algorithm !== "X25519") throw new Error("invalid recipient key algorithm");
          return { subject: string(key.subject, "recipient subject"), grantId: string(key.grant_id, "grant id"),
            keyId: string(key.key_id, "recipient key id"), encryptionAlgorithm: "X25519" as const,
            publicKey: bytes(key.public_key, "recipient public key") };
        }),
        acceptanceRequired: boolean(target.acceptance_required, "acceptance requirement"),
        encryptionReady: boolean(target.encryption_ready, "encryption readiness"), allowed: boolean(target.allowed, "target decision"),
      };
    }),
    encryption: {
      required: boolean(encryption.required, "encryption required"), ready: boolean(encryption.ready, "encryption ready"),
      ...(encryption.key_resource === undefined ? {} : { keyResource: string(encryption.key_resource, "key resource") }),
      ...(source === undefined ? {} : { sourceEnvelope: {
        grantId: string(source.grant_id, "source grant"), scope: string(source.scope, "source scope"),
        resource: string(source.resource, "source resource"), relation: string(source.relation, "source relation"),
        keyResource: string(source.key_resource, "source key resource"),
        subject: string(source.recipient_subject, "source recipient subject"),
        recipientKeyId: string(source.recipient_key_id, "source recipient key"),
        encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM" as const,
        ciphertext: bytes(source.ciphertext, "source ciphertext"),
        aadHash: bytes(source.aad_hash, "source aad hash"), issuer: string(source.issuer, "source issuer"),
        issuerKeyId: string(source.issuer_key_id, "source issuer key"),
        issuerSigningAlgorithm: (() => {
          if (source.issuer_signing_algorithm !== "Ed25519") throw new Error("invalid source issuer signing algorithm");
          return "Ed25519" as const;
        })(),
        issuerSigningPublicKey: bytes(source.issuer_signing_public_key, "source issuer signing public key"),
        issuerKeyStatus: (() => {
          if (source.issuer_key_status !== "active" && source.issuer_key_status !== "revoked") throw new Error("invalid source issuer key status");
          return source.issuer_key_status;
        })(),
        signature: bytes(source.signature, "source signature"),
        keyVersion: integer(source.key_version, "source key version"),
      } }),
    },
    ready: boolean(input.ready, "preflight readiness"), idempotent: boolean(input.idempotent, "preflight idempotency"),
  };
}

export function linkSendResult(value: unknown): LinkSendResult {
  const input = record(value, "link send");
  return { preflightId: string(input.preflight_id, "preflight id"), resource: string(input.resource, "resource"),
    links: array(input.links, "links").map((item) => {
      const link = record(item, "link");
      return { id: string(link.id, "link id"), targetId: string(link.target_id, "target id"),
        type: string(link.type, "link type") as "invite" | "direct", subject: string(link.subject, "link subject"),
        status: string(link.status, "link status"),
        ...(link.invitation_id === undefined ? {} : { invitationId: string(link.invitation_id, "invitation id") }),
        ...(link.ticket === undefined ? {} : { ticket: string(link.ticket, "invitation ticket") }) };
    }) };
}

export function keyProvisioningJobs(value: unknown): import("./types.js").KeyProvisioningJobList {
  const input = record(value, "key provisioning jobs");
  return {
    resource: string(input.resource, "key provisioning resource"),
    jobs: array(input.jobs, "key provisioning jobs").map((raw) => {
      const job = record(raw, "key provisioning job");
      if (job.encryption_algorithm !== "X25519") throw new Error("invalid provisioning encryption algorithm");
      if (job.link_status !== "pending_acceptance" && job.link_status !== "pending_encryption" && job.link_status !== "active") {
        throw new Error("invalid provisioning link status");
      }
      return {
        grantId: string(job.grant_id, "provisioning grant id"),
        linkId: string(job.link_id, "provisioning link id"),
        resource: string(job.resource, "provisioning resource"),
        relation: string(job.relation, "provisioning relation"),
        keyResource: string(job.key_resource, "provisioning key resource"),
        keyVersion: integer(job.key_version, "provisioning key version"),
        subject: string(job.subject, "provisioning subject"),
        recipientKeyId: string(job.recipient_key_id, "provisioning recipient key id"),
        encryptionAlgorithm: "X25519" as const,
        publicKey: bytes(job.public_key, "provisioning public key"),
        linkStatus: job.link_status,
      };
    }),
  };
}

export function keyProvisioningMutation(value: unknown): import("./types.js").KeyProvisioningMutation {
  const input = record(value, "key provisioning mutation");
  return {
    resource: string(input.resource, "key provisioning resource"),
    submitted: integer(input.submitted, "submitted envelope count"),
  };
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
  return { resource: string(input.resource, "resource"), revision: integer(input.revision, "policy revision") };
}

function resourceCollaborator(raw: unknown): ResourceCollaborator {
  const item = record(raw, "collaborator");
  const access = item.access === undefined ? undefined : record(item.access, "collaborator access");
  const recipient = item.recipient === undefined ? undefined : record(item.recipient, "collaborator recipient");
  return {
    kind: string(item.kind, "collaborator kind") as "user" | "group" | "invitation", id: string(item.id, "collaborator id"),
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

function accountResourceReference(value: unknown, name: string): import("./types.js").AccountResourceReference {
  const input = record(value, name);
  const id = string(input.id, `${name} id`);
  if (id.includes(":")) throw new Error(`${name} exposed an internal resource reference`);
  return { id, type: string(input.type, `${name} type`), name: string(input.name, `${name} name`) };
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
      const resource = record(item.resource, "account invitation resource");
      const resourceId = string(resource.id, "account invitation resource id");
      if (resourceId.includes(":")) throw new Error("account invitation exposed an internal resource reference");
      if (item.status !== "pending_acceptance" && item.status !== "pending_approval") throw new Error("invalid account invitation status");
      return {
        id: string(item.id, "account invitation id"),
        resource: { id: resourceId, type: string(resource.type, "account invitation resource type"), name: string(resource.name, "account invitation resource name") },
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

export function collaboratorMutation(value: unknown): ResourceCollaboratorMutation {
  const input = record(value, "collaborator mutation");
  return {
    resource: string(input.resource, "collaborator resource"),
    collaborator: string(input.collaborator, "collaborator id"),
    relations: array(input.relations, "collaborator relations").map(value => string(value, "collaborator relation")),
    status: string(input.status, "collaborator status"),
    ...(input.force === undefined ? {} : { force: boolean(input.force, "collaborator force") }),
    ...(input.cascaded_groups === undefined ? {} : { cascaded_groups: array(input.cascaded_groups, "cascaded groups").map(value => string(value, "cascaded group")) }),
    ...(input.rekey_required === undefined ? {} : { rekey_required: boolean(input.rekey_required, "rekey required") }),
    ...(input.rekey_resources === undefined ? {} : { rekey_resources: array(input.rekey_resources, "rekey resources").map(value => string(value, "rekey resource")) }),
  };
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

export function organization(value: unknown): OrganizationSummary {
  return organizations([value])[0]!;
}

export function collaborationResource(value: unknown): CollaborationResource {
  const input = record(value, "collaboration resource");
  if (input.status !== "active" && input.status !== "deleted") throw new Error("invalid collaboration resource status");
  return {
    id: string(input.id, "collaboration resource id"),
    resource: string(input.resource, "collaboration resource reference"),
    resourceType: string(input.resource_type, "collaboration resource type"),
    displayName: string(input.display_name, "collaboration resource name"),
    ...(input.parent === undefined ? {} : { parent: string(input.parent, "collaboration resource parent") }),
    status: input.status,
  };
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

export function resourceKeyMutation(value: unknown): import("./types.js").ResourceKeyMutation {
  const input = record(value, "resource key mutation");
  return {
    accepted: boolean(input.accepted, "resource key accepted"),
    reason: string(input.reason, "resource key reason"),
    keyResource: string(input.key_resource, "key resource"),
    version: integer(input.version, "resource key version"),
    logSeq: integer(input.log_seq, "resource key log sequence"),
  };
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
  if (input.issuer_signing_algorithm !== "Ed25519") throw new Error("invalid resource envelope issuer algorithm");
  if (input.issuer_key_status !== "active" && input.issuer_key_status !== "revoked") throw new Error("invalid resource envelope issuer status");
  return { grantId: string(input.grant_id, "grant id"), scope: string(input.scope, "scope"), resource: string(input.resource, "resource"), subject: string(input.recipient_subject, "recipient subject"), relation: string(input.relation, "relation"), keyResource: string(input.key_resource, "key resource"), keyVersion: integer(input.key_version, "key version"), recipientKeyId: string(input.recipient_key_id, "recipient key id"), encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM", ciphertext: bytes(input.ciphertext, "ciphertext"), aadHash: bytes(input.aad_hash, "AAD hash"), issuer: string(input.issuer, "issuer"), issuerKeyId: string(input.issuer_key_id, "issuer key id"), issuerSigningAlgorithm: "Ed25519", issuerSigningPublicKey: bytes(input.issuer_signing_public_key, "issuer signing public key"), issuerKeyStatus: input.issuer_key_status, signature: bytes(input.signature, "signature") };
}
