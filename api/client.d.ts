import { type BrowserFetch } from "./transport.js";
import { type ApplicationSession, type AuthenticatedSession, type CheckoutSession, type CreateCheckoutSessionInput, type OrganizationSummary, type PasswordlessChallenge, type PublicApplicationConfiguration, type PublicApplicationPricing, type TokenStore, type EnrollSubjectKeyInput, type SubjectKeyEnrollment, type SubjectKeyMutation, type SubjectKeyRecord, type ResourceGrantMutation, type ResourceMember, type EncryptedInvitationMutation } from "./types.js";
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
    enrollSubjectKey(input: EnrollSubjectKeyInput): Promise<SubjectKeyEnrollment>;
    subjectKeys(): Promise<SubjectKeyRecord[]>;
    revokeSubjectKey(keyId: string): Promise<SubjectKeyMutation>;
    resourceMembers(scope: string, resource: string): Promise<ResourceMember[]>;
    submitResourceEnvelope(input: import("./key-access.js").ResourceEnvelopeRequest): Promise<ResourceGrantMutation>;
    resourceEnvelope(resource: string): Promise<import("./key-access.js").EncryptedResourceEnvelope>;
    acceptEncryptedInvitation(ticket: string, recipientKeyId: string, idempotencyKey: string): Promise<EncryptedInvitationMutation>;
    private createCheckoutSession;
}
