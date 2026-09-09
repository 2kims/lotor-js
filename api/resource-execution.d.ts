export interface ResourceExecutionPreflight {
    requestFingerprint: string;
    resource: string;
    catalogEntryId: string;
    payloadSlot: string;
    payloadVersion: number;
    payloadRepresentation: "raw" | "encrypted-envelope-v1";
    executionMode: "raw" | "managed" | "customer_box";
    expiresAt: number;
    method: string;
    path: string;
    query: string;
    contentType: string;
    requestBodyDigest: string;
    requestBodySize: number;
    requestAad?: string;
    keyResource?: string;
    keyVersion?: number;
    responsePolicyRef?: "encrypt_all";
}
export interface ResourceExecutionAuthorization {
    status: "authorized" | "completed";
    requestFingerprint: string;
    resource: string;
    catalogEntryId: string;
    payloadSlot: string;
    payloadVersion: number;
    payloadRepresentation: "raw" | "encrypted-envelope-v1";
    executionMode: "raw" | "managed" | "customer_box";
    expiresAt: number;
    providerStatus?: number;
    protectedResponse?: string;
}
export interface ProviderPlainRequest {
    method: string;
    path: string;
    query: string;
    contentType: string;
    headers?: Record<string, string>;
    body: Uint8Array;
}
export interface ProviderProtectedResponse {
    headers: Record<string, string>;
    body: Uint8Array;
    status: number;
}
export declare function canonicalProviderQuery(input: URLSearchParams): string;
export declare function protectProviderRequest(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, input: ProviderPlainRequest): Promise<string>;
export declare function openProviderResponse(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, authorization: ResourceExecutionAuthorization): Promise<ProviderProtectedResponse>;
