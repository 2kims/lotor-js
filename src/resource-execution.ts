const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface ResourceExecutionPreflight {
  requestFingerprint: string; resource: string; catalogEntryId: string; payloadSlot: string;
  payloadVersion: number; payloadRepresentation: "raw" | "encrypted-envelope-v1";
  executionMode: "raw" | "managed" | "customer_box"; expiresAt: number;
  method: string; path: string; query: string; contentType: string;
  requestBodyDigest: string; requestBodySize: number; requestAad?: string;
  keyResource?: string; keyVersion?: number;
  responsePolicyRef?: "encrypt_all";
}

export interface ResourceExecutionAuthorization {
  status: "authorized" | "completed"; requestFingerprint: string; resource: string;
  catalogEntryId: string; payloadSlot: string; payloadVersion: number;
  payloadRepresentation: "raw" | "encrypted-envelope-v1";
  executionMode: "raw" | "managed" | "customer_box"; expiresAt: number;
  providerStatus?: number; protectedResponse?: string;
}

export interface ProviderPlainRequest { method: string; path: string; query: string; contentType: string; headers?: Record<string, string>; body: Uint8Array }
export interface ProviderProtectedResponse { headers: Record<string, string>; body: Uint8Array; status: number }

export function canonicalProviderQuery(input: URLSearchParams): string {
  const query = new URLSearchParams(input);
  query.sort();
  return query.toString();
}

export async function protectProviderRequest(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, input: ProviderPlainRequest): Promise<string> {
  if (resourceKey.length !== 32 || input.body.length > 1 << 20) throw new Error("invalid provider request encryption input");
  if (preflight.payloadRepresentation !== "encrypted-envelope-v1" || preflight.responsePolicyRef !== "encrypt_all" || !preflight.requestAad) throw new Error("execution preflight is not encrypted");
  if (input.method !== preflight.method || input.path !== preflight.path || input.query !== preflight.query || input.contentType !== preflight.contentType) throw new Error("provider request metadata does not match execution preflight");
  const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(input.body))));
  if (input.body.length !== preflight.requestBodySize || digest !== preflight.requestBodyDigest) throw new Error("provider request body does not match execution preflight");
  const headers: Record<string, string> = { "Content-Type": preflight.contentType };
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    if (value.length > 8192 || /[\r\n]/u.test(value)) throw new Error("provider request contains invalid header value");
    if (name.toLowerCase() === "accept") headers.Accept = value;
    else if (name.toLowerCase() !== "content-type") throw new Error("provider request contains unsupported header");
  }
  const plaintext = encoder.encode(JSON.stringify({ headers, body: base64url(input.body) }));
  try { return await seal(resourceKey, plaintext, fromBase64url(preflight.requestAad)); }
  finally { plaintext.fill(0); }
}

export async function openProviderResponse(resourceKey: Uint8Array, preflight: ResourceExecutionPreflight, authorization: ResourceExecutionAuthorization): Promise<ProviderProtectedResponse> {
  if (resourceKey.length !== 32 || authorization.status !== "completed" || authorization.providerStatus === undefined || authorization.providerStatus < 100 || authorization.providerStatus > 599 || !authorization.protectedResponse) throw new Error("execution did not return a protected provider response");
  const pairs: Array<[unknown, unknown]> = [[authorization.requestFingerprint, preflight.requestFingerprint], [authorization.resource, preflight.resource], [authorization.catalogEntryId, preflight.catalogEntryId], [authorization.payloadSlot, preflight.payloadSlot], [authorization.payloadVersion, preflight.payloadVersion], [authorization.payloadRepresentation, preflight.payloadRepresentation], [authorization.executionMode, preflight.executionMode], [authorization.expiresAt, preflight.expiresAt]];
  if (pairs.some(([actual, expected]) => actual !== expected)) throw new Error("execution response does not match preflight");
  if (!preflight.requestAad) throw new Error("invalid execution request AAD");
  const requestHash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(fromBase64url(preflight.requestAad))));
  const responseAad = encoder.encode(`lotor-provider-response-v1\0${hex(requestHash)}\0${authorization.providerStatus}`);
  const plaintext = await open(resourceKey, authorization.protectedResponse, responseAad);
  let decoded: { status?: unknown; headers?: unknown; body?: unknown };
  try { decoded = JSON.parse(decoder.decode(plaintext)); } catch { throw new Error("invalid protected provider response"); }
  finally { plaintext.fill(0); }
  if (decoded.status !== authorization.providerStatus || typeof decoded.body !== "string" || !decoded.headers || Array.isArray(decoded.headers) || typeof decoded.headers !== "object") throw new Error("invalid protected provider response");
  const body = fromBase64url(decoded.body);
  const allowedHeaders = new Set(["content-type", "etag", "retry-after"]);
  if (body.length > 1 << 20 || !Object.entries(decoded.headers).every(([name, value]) => allowedHeaders.has(name.toLowerCase()) && typeof value === "string" && value.length <= 8192 && !/[\r\n]/u.test(value))) throw new Error("invalid protected provider response");
  return { status: decoded.status as number, headers: decoded.headers as Record<string, string>, body };
}

async function seal(keyBytes: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", bytes(keyBytes), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(nonce), additionalData: bytes(aad) }, key, bytes(plaintext)));
  const aadHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(aad))));
  return base64url(encoder.encode(JSON.stringify({ nonce: base64url(nonce), ciphertext: base64url(ciphertext), aad_hash: aadHash })));
}

async function open(keyBytes: Uint8Array, encoded: string, aad: Uint8Array): Promise<Uint8Array> {
  let envelope: { nonce?: unknown; ciphertext?: unknown; aad_hash?: unknown };
  try { envelope = JSON.parse(decoder.decode(fromBase64url(encoded))); } catch { throw new Error("invalid protected provider response"); }
  const expected = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(aad))));
  if (typeof envelope.nonce !== "string" || typeof envelope.ciphertext !== "string" || envelope.aad_hash !== expected) throw new Error("invalid protected provider response");
  const nonce = fromBase64url(envelope.nonce);
  if (nonce.length !== 12) throw new Error("invalid protected provider response");
  const key = await crypto.subtle.importKey("raw", bytes(keyBytes), "AES-GCM", false, ["decrypt"]);
  try { return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(nonce), additionalData: bytes(aad) }, key, bytes(fromBase64url(envelope.ciphertext)))); } catch { throw new Error("invalid protected provider response"); }
}

function bytes(value: Uint8Array): ArrayBuffer { return value.slice().buffer; }
function hex(value: Uint8Array): string { return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }
function base64url(value: Uint8Array): string { let binary = ""; for (const byte of value) binary += String.fromCharCode(byte); return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, ""); }
function fromBase64url(value: string): Uint8Array { const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4); try { return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0)); } catch { throw new Error("invalid base64url"); } }
