import { type BrowserFetch } from "./transport.js";
import { type ApplicationSession, type AuthenticatedSession, type CheckoutSession, type CreateCheckoutSessionInput, type OrganizationSummary, type PasswordlessChallenge, type PublicApplicationConfiguration, type PublicApplicationPricing, type TokenStore, type EnrollSubjectKeyInput, type SubjectKeyEnrollment, type SubjectKeyMutation, type SubjectKeyRecord, type ResourceGrantMutation, type ResourceGrantInput, type ResourceKeyMutation, type ResourceKeyVersionInput, type ResourceMember, type EncryptedInvitationMutation, type LinkPreflightInput, type LinkPreflight, type LinkSendInput, type LinkSendResult, type EnsureEncryptedResourceInput, type EnsureEncryptedResourceResult, type EncryptedResourceLinkInput, type EncryptedResourceLinkResult, type KeyProvisioningJobList, type ProvisionEncryptedResourceLinksInput, type KeyProvisioningMutation, type UnlinkResult, type ResourceCollaborationPolicyOverride, type ResourceCollaborationPolicyMutation, type ResourceCollaboratorList, type ResourceSearchInput, type ResourceSearchList, type AccountInvitationList, type AccountInvitationMutation, type AccountResourceList, type ResourceInvitationMutation, type ResourceCollaboratorMutation } from "./types.js";
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
    createOrganization(name: string, idempotencyKey: string): Promise<OrganizationSummary>;
    putResource(resource: string, input: import("./types.js").ResourceRegistration): Promise<import("./types.js").CollaborationResource>;
    enrollSubjectKey(input: EnrollSubjectKeyInput): Promise<SubjectKeyEnrollment>;
    subjectKeys(): Promise<SubjectKeyRecord[]>;
    revokeSubjectKey(keyId: string): Promise<SubjectKeyMutation>;
    resourceMembers(scope: string, resource: string): Promise<ResourceMember[]>;
    createResourceKeyVersion(input: ResourceKeyVersionInput): Promise<ResourceKeyMutation>;
    prepareResourceGrant(input: ResourceGrantInput): Promise<ResourceGrantMutation>;
    submitResourceEnvelope(input: import("./key-access.js").ResourceEnvelopeRequest): Promise<ResourceGrantMutation>;
    resourceEnvelope(resource: string): Promise<import("./key-access.js").EncryptedResourceEnvelope>;
    acceptEncryptedInvitation(ticket: string, recipientKeyId: string, idempotencyKey: string): Promise<EncryptedInvitationMutation>;
    preflightResourceLinks(resource: string, input: LinkPreflightInput, idempotencyKey: string): Promise<LinkPreflight>;
    sendResourceLinks(resource: string, input: LinkSendInput, idempotencyKey?: string): Promise<LinkSendResult>;
    ensureEncryptedResource(input: EnsureEncryptedResourceInput): Promise<EnsureEncryptedResourceResult>;
    sendEncryptedResourceLinks(resource: string, input: EncryptedResourceLinkInput): Promise<EncryptedResourceLinkResult>;
    keyProvisioningJobs(resource: string): Promise<KeyProvisioningJobList>;
    provisionEncryptedResourceLinks(resource: string, input: ProvisionEncryptedResourceLinksInput): Promise<KeyProvisioningMutation>;
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
    updateResourceCollaborator(resource: string, collaborator: string, relation: string): Promise<ResourceCollaboratorMutation>;
    deleteResourceCollaborator(resource: string, collaborator: string, options?: {
        force?: boolean;
    }): Promise<ResourceCollaboratorMutation>;
    setResourceCollaborationPolicy(resource: string, input: ResourceCollaborationPolicyOverride): Promise<ResourceCollaborationPolicyMutation>;
    private createCheckoutSession;
}
