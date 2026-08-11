export interface AnonymousSession {
    authenticated: false;
}
export interface AuthenticatedSession {
    authenticated: true;
    subject: string;
    email: string;
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
/** In-memory storage is intentionally non-persistent and is the SDK default. */
export declare class MemoryTokenStore implements TokenStore {
    private token;
    getToken(): string | null;
    setToken(token: string): void;
    clearToken(): void;
}
export {};
