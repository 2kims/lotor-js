import { type BrowserFetch } from "./transport.js";
import { type ApplicationSession, type AuthenticatedSession, type CheckoutSession, type CreateCheckoutSessionInput, type OrganizationSummary, type PasswordlessChallenge, type PublicApplicationConfiguration, type PublicApplicationPricing, type TokenStore } from "./types.js";
export interface LotorBrowserOptions {
    /** Absolute Lotor public API origin, for example https://api.example.com. */
    baseUrl: string;
    clientId: string;
    tokenStore?: TokenStore;
    /** Allows HTTP only for localhost, 127.0.0.0/8, or ::1 development endpoints. */
    allowInsecureLoopback?: boolean;
    fetch?: BrowserFetch;
}
export declare class LotorBrowserClient {
    readonly clientId: string;
    readonly billing: {
        createCheckoutSession: (input: CreateCheckoutSessionInput) => Promise<CheckoutSession>;
    };
    private readonly transport;
    private readonly tokenStore;
    private readonly applicationPath;
    constructor(options: LotorBrowserOptions);
    configuration(): Promise<PublicApplicationConfiguration>;
    pricing(): Promise<PublicApplicationPricing>;
    startPasswordless(email: string): Promise<PasswordlessChallenge>;
    verifyPasswordless(challengeId: string, code: string): Promise<AuthenticatedSession>;
    session(): Promise<ApplicationSession>;
    logout(): Promise<void>;
    organizations(): Promise<OrganizationSummary[]>;
    private createCheckoutSession;
}
