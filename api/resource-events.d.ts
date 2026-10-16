import type { BrowserRequestTransport } from "./transport.js";
export interface ResourceEventStreamInput {
    allowCredentialAppend?: boolean;
    attributeKeys: readonly string[];
    retentionDays: number;
}
export interface ResourceEventInput {
    id: string;
    occurredAt: string;
    attributes: Record<string, string>;
    representation: "raw" | "encrypted";
    /** Opaque base64 bytes. This client never decrypts or indexes the body. */
    bodyBase64: string;
}
export interface ResourceEventMetadata {
    producerSubject: string;
    recordedAt: string;
    id: string;
    occurredAt: string;
    attributes: Record<string, string>;
    representation: "raw" | "encrypted";
}
export interface ResourceEventDetail extends ResourceEventMetadata {
    bodyBase64: string;
}
export interface ResourceEventQueryInput {
    /** Narrow a snapshot without changing its filters, watermark or expiry. */
    parentQueryId?: string;
    from: string;
    to: string;
    filters: Record<string, readonly string[]>;
}
export interface ResourceEventQuery {
    id: string;
    from: string;
    to: string;
    expiresAt: string;
}
export interface ResourceEventPage {
    items: ResourceEventMetadata[];
    nextCursor: string | null;
}
export interface ResourceEventBucket {
    start: string;
    end: string;
    counts: Record<string, number>;
}
/** Resource-owned storage queries. No retries, fallback, body search or decryption. */
export declare class ResourceEventStreamClient {
    private readonly transport;
    private readonly path;
    constructor(transport: BrowserRequestTransport, path: string);
    configure(input: ResourceEventStreamInput): Promise<void>;
    append(input: ResourceEventInput): Promise<void>;
    createQuery(input: ResourceEventQueryInput): Promise<ResourceEventQuery>;
    events(queryId: string, options?: {
        cursor?: string;
        limit?: number;
    }): Promise<ResourceEventPage>;
    histogram(queryId: string, options: {
        groupBy: string;
        intervalSeconds: number;
    }): Promise<ResourceEventBucket[]>;
    event(eventId: string): Promise<ResourceEventDetail>;
}
