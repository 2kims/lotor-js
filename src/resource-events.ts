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
export interface ResourceEventDetail extends ResourceEventMetadata { bodyBase64: string; }
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

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid resource event response");
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) throw new Error("invalid resource event response");
  return value;
}
function timestamp(value: unknown): string {
  const result = text(value, 64);
  if (!Number.isFinite(Date.parse(result))) throw new Error("invalid resource event timestamp");
  return result;
}
function segment(value: string): string {
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(value)) throw new Error("invalid resource event identity");
  return encodeURIComponent(value);
}
function metadata(value: unknown): ResourceEventMetadata {
  const row = object(value);
  if (row.representation !== "raw" && row.representation !== "encrypted") throw new Error("invalid event representation");
  const attributes = object(row.attributes);
  if (Object.keys(attributes).length > 16 || Object.values(attributes).some(value => typeof value !== "string" || value.length > 256)) throw new Error("invalid event attributes");
  return { id: text(row.id), producerSubject:text(row.producer_subject), recordedAt:timestamp(row.recorded_at), occurredAt: timestamp(row.occurred_at), attributes: attributes as Record<string, string>, representation: row.representation };
}

/** Resource-owned storage queries. No retries, fallback, body search or decryption. */
export class ResourceEventStreamClient {
  constructor(private readonly transport: BrowserRequestTransport, private readonly path: string) {}

  async configure(input: ResourceEventStreamInput): Promise<void> {
    await this.transport.request(this.path, { method: "PUT", body: JSON.stringify({ attribute_keys: input.attributeKeys, retention_days: input.retentionDays, allow_credential_append: input.allowCredentialAppend ?? false }) }, true);
  }
  async append(input: ResourceEventInput): Promise<void> {
    segment(input.id);
    if (input.bodyBase64.length > 5592408) throw new Error("event body exceeds four MiB");
    await this.transport.request(`${this.path}/events`, { method: "POST", body: JSON.stringify({ id: input.id, occurred_at: input.occurredAt, attributes: input.attributes, representation: input.representation, body: input.bodyBase64 }) }, true);
  }
  async createQuery(input: ResourceEventQueryInput): Promise<ResourceEventQuery> {
    if (input.parentQueryId !== undefined) segment(input.parentQueryId);
    const row = object(await this.transport.request(`${this.path}/queries`, { method: "POST", body: JSON.stringify({ from: input.from, to: input.to, filters: input.filters, parent_query_id: input.parentQueryId }) }, true));
    return { id: text(row.id), from: timestamp(row.from), to: timestamp(row.to), expiresAt: timestamp(row.expires_at) };
  }
  async events(queryId: string, options: { cursor?: string; limit?: number } = {}): Promise<ResourceEventPage> {
    const limit = options.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || (options.cursor?.length ?? 0) > 2048) throw new Error("invalid event pagination");
    const parameters = new URLSearchParams({ limit: String(limit) });
    if (options.cursor) parameters.set("cursor", options.cursor);
    const row = object(await this.transport.request(`${this.path}/queries/${segment(queryId)}/events?${parameters}`, {}, true));
    if (!Array.isArray(row.items) || row.items.length > limit || (row.next_cursor !== null && typeof row.next_cursor !== "string")) throw new Error("invalid event page");
    return { items: row.items.map(metadata), nextCursor: row.next_cursor as string | null };
  }
  async histogram(queryId: string, options: { groupBy: string; intervalSeconds: number }): Promise<ResourceEventBucket[]> {
    if (!Number.isSafeInteger(options.intervalSeconds) || options.intervalSeconds < 1 || options.intervalSeconds > 2592000) throw new Error("invalid event histogram interval");
    const parameters = new URLSearchParams({ group_by: options.groupBy, interval_seconds: String(options.intervalSeconds) });
    const rows = await this.transport.request(`${this.path}/queries/${segment(queryId)}/histogram?${parameters}`, {}, true);
    if (!Array.isArray(rows) || rows.length > 720) throw new Error("invalid event histogram");
    return rows.map(value => {
      const row = object(value), counts = object(row.counts);
      if (Object.keys(counts).length > 64 || Object.values(counts).some(count => !Number.isSafeInteger(count) || Number(count) < 0)) throw new Error("invalid event histogram counts");
      return { start: timestamp(row.start), end: timestamp(row.end), counts: counts as Record<string, number> };
    });
  }
  async event(eventId: string): Promise<ResourceEventDetail> {
    const row = object(await this.transport.request(`${this.path}/events/${segment(eventId)}`, {}, true));
    if (typeof row.body !== "string" || row.body.length > 5592408) throw new Error("invalid event body");
    return { ...metadata(row), bodyBase64: row.body };
  }
}
