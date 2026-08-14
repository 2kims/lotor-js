export interface AnonymousSession {
    authenticated: false;
}
export interface AuthenticatedSession {
    authenticated: true;
    subject: string;
    email: string;
    keyAccess?: {
        enabled: boolean;
        requiredBeforeSignupComplete: boolean;
        enrolled: boolean;
        activeKeyIds: string[];
        setupDelivery: string;
    };
}
export type ApplicationSession = AnonymousSession | AuthenticatedSession;
export interface PasswordlessChallenge {
    challenge_id: string;
    delivery: "email";
    expires_at: number;
}
export interface PublicApplicationConfiguration {
    clientId: string;
    application: {
        name: string;
    };
    environment: {
        name: string;
        isProduction: boolean;
    };
    authentication: {
        methods: string[];
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
            encryption: {
                mode: "none" | "optional" | "required";
                defaultKeyStrategy: "none" | "resource_key" | "inherited";
                allowInherited: boolean;
            };
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
export type CreateCheckoutSessionInput = CreateHostedCheckoutSessionInput | CreateCustomCheckoutSessionInput;
export type CheckoutSession = {
    id: string;
    presentation: "hosted";
    url: string;
} | {
    id: string;
    presentation: "custom";
    clientSecret: string;
    publishableKey: string;
};
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
export interface EncryptedInvitationMutation {
    accepted: boolean;
    reason: string;
    invitationId: string;
    logSeq: number;
}
/** In-memory storage is intentionally non-persistent and is the SDK default. */
export declare class MemoryTokenStore implements TokenStore {
    private token;
    getToken(): string | null;
    setToken(token: string): void;
    clearToken(): void;
}
