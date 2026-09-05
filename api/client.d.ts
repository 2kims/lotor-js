import { type BrowserFetch, type CSRFTokenProvider } from "./transport.js";
import { type ApplicationSession, type AuthenticatedSession, type CheckoutSession, type CreateCheckoutSessionInput, type OrganizationSummary, type PasswordlessChallenge, type PublicApplicationConfiguration, type PublicApplicationPricing, type TokenStore, type EnrollSubjectKeyInput, type SubjectKeyEnrollment, type SubjectKeyMutation, type SubjectKeyRecord, type ResourceLinkChange, type ResourceLinkCandidateSearchInput, type ResourceLinkCandidateSearchResult, type ResourceLinkPreflight, type ResourceLinkSendInput, type ResourceLinkSendResult, type ResourceLinkResult, type UnlinkResult, type ResourceCollaborationPolicyOverride, type ResourceCollaborationPolicyMutation, type ResourceCollaboratorList, type ResourceSearchInput, type ResourceSearchList, type AccountInvitationList, type AccountInvitationMutation, type AccountResourceList, type ResourceInvitationMutation, type ClaimSubjectKeyInput, type ClaimedSubjectKey, type ResourceLinkEnvelopeSubmission, type OrganizationE2EEPolicy, type ResourceSessionEnvelope, type EncryptionAction, type EncryptionActionMutation, type ResourcePayloadAccessLease, type ResourcePayloadManifest, type ResourcePayloadMutation, type ResourcePayloadUploadInput, type ResourcePayloadUploadIntent, type DurableOperation, type ResourceLifecycleFence, type ResourceMoveInput, type ResourceDeleteInput } from "./types.js";
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
export declare class LotorBrowserClient {
    readonly clientId: string;
    readonly publishableKey: string;
    readonly billing: {
        createCheckoutSession: (input: CreateCheckoutSessionInput) => Promise<CheckoutSession>;
    };
    private readonly transport;
    private readonly tokenStore;
    private readonly applicationPath;
    private readonly sameOrigin;
    private readonly fetcher;
    constructor(options: LotorBrowserOptions);
    configuration(): Promise<PublicApplicationConfiguration>;
    pricing(): Promise<PublicApplicationPricing>;
    startPasswordless(email: string): Promise<PasswordlessChallenge>;
    verifyPasswordless(challengeId: string, code: string): Promise<AuthenticatedSession>;
    session(): Promise<ApplicationSession>;
    logout(): Promise<void>;
    organizations(): Promise<OrganizationSummary[]>;
    createOrganization(name: string, idempotencyKey: string): Promise<OrganizationSummary>;
    putResource(resource: string, input: import("./types.js").ResourceRegistration): Promise<import("./types.js").CollaborationResource>;
    resource(resource: string): Promise<import("./types.js").CollaborationResource>;
    moveResource(resource: string, input: ResourceMoveInput, idempotencyKey: string): Promise<DurableOperation>;
    disableResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation>;
    restoreResource(resource: string, input: ResourceLifecycleFence, idempotencyKey: string): Promise<DurableOperation>;
    deleteResource(resource: string, input: ResourceDeleteInput, idempotencyKey: string): Promise<DurableOperation>;
    operation(operationId: string): Promise<DurableOperation>;
    private resourceLifecycleOperation;
    resourcePayload(resource: string, slot: string): Promise<ResourcePayloadManifest>;
    createResourcePayloadUpload(resource: string, slot: string, input: ResourcePayloadUploadInput): Promise<ResourcePayloadUploadIntent>;
    commitResourcePayload(resource: string, slot: string, intent: ResourcePayloadUploadIntent): Promise<ResourcePayloadManifest>;
    uploadResourcePayloadObject(intent: ResourcePayloadUploadIntent, object: Uint8Array): Promise<void>;
    accessResourcePayload(resource: string, slot: string, payloadVersion?: number): Promise<ResourcePayloadAccessLease>;
    rewrapResourcePayload(resource: string, slot: string, input: import("./types.js").ResourcePayloadRewrapInput): Promise<import("./types.js").ResourcePayloadRewrapResult>;
    deleteResourcePayload(resource: string, slot: string, idempotencyKey: string): Promise<ResourcePayloadMutation>;
    private resourcePayloadPath;
    enrollSubjectKey(input: EnrollSubjectKeyInput): Promise<SubjectKeyEnrollment>;
    subjectKeys(): Promise<SubjectKeyRecord[]>;
    revokeSubjectKey(keyId: string): Promise<SubjectKeyMutation>;
    claimSubjectKey(input: ClaimSubjectKeyInput): Promise<ClaimedSubjectKey>;
    resourceEnvelope(resource: string): Promise<import("./key-access.js").EncryptedResourceEnvelope>;
    resourceSessionEnvelope(resource: string, sessionPublicKey: string, clientNonce: string): Promise<ResourceSessionEnvelope>;
    resourceSession(resource: string): Promise<import("./types.js").ResourceSession>;
    organizationE2EEPolicy(organization: string): Promise<OrganizationE2EEPolicy>;
    configureOrganizationE2EE(organization: string, input: import("./types.js").OrganizationE2EEPolicyInput): Promise<OrganizationE2EEPolicy>;
    encryptionActions(): Promise<EncryptionAction[]>;
    completeEncryptionAction(jobId: string, revision: string, envelopes: ResourceLinkEnvelopeSubmission[]): Promise<EncryptionActionMutation>;
    completeEncryptionActionWithResourceKey(action: EncryptionAction, resourceKey: Uint8Array, keyMaterial: import("./key-access.js").DeviceKeyMaterial): Promise<EncryptionActionMutation>;
    searchResourceLinkCandidates(resource: string, input: ResourceLinkCandidateSearchInput): Promise<ResourceLinkCandidateSearchResult>;
    preflightResourceLinks(resource: string, changes: ResourceLinkChange[]): Promise<ResourceLinkPreflight>;
    commitResourceLinks(resource: string, preflight: ResourceLinkPreflight, envelopes?: ResourceLinkEnvelopeSubmission[]): Promise<ResourceLinkResult>;
    sendResourceLinks(resource: string, input: ResourceLinkSendInput): Promise<ResourceLinkSendResult>;
    unlinkResource(resource: string, linkId: string, idempotencyKey?: string): Promise<UnlinkResult>;
    resourceCollaborators(resource: string, options?: {
        view?: "direct" | "effective";
        search?: string;
        email?: string;
        subject?: string;
        resourceSubject?: string;
        viaGroup?: string;
        direct?: boolean;
        kind?: "user" | "group" | "invitation";
        kinds?: Array<"user" | "group" | "invitation">;
        status?: string;
        statuses?: string[];
        relations?: string[];
        cursor?: string;
        limit?: number;
    }): Promise<ResourceCollaboratorList>;
    searchResources(input?: ResourceSearchInput): Promise<ResourceSearchList>;
    accountInvitations(options?: {
        cursor?: string;
        limit?: number;
    }): Promise<AccountInvitationList>;
    accountResources(options?: {
        types?: string[];
        accessStates?: Array<"active" | "pending_encryption">;
        cursor?: string;
        limit?: number;
    }): Promise<AccountResourceList>;
    acceptAccountInvitation(invitationId: string): Promise<AccountInvitationMutation>;
    declineAccountInvitation(invitationId: string): Promise<AccountInvitationMutation>;
    acceptResourceInvitation(ticket: string): Promise<ResourceInvitationMutation>;
    setResourceCollaborationPolicy(resource: string, input: ResourceCollaborationPolicyOverride): Promise<ResourceCollaborationPolicyMutation>;
    private createCheckoutSession;
}
export {};
