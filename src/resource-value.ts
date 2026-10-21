/** Generic value format emitted inside a selected custody runtime. No provider
 * credentials, account private keys, or passphrases belong in this contract. */
export interface ResourceKeyBinding {
  scope: { tenant_id: string; application_id: string; environment_id: string; owner_resource: string };
  client_id: string;
  resource: string;
  slot: string;
  key_resource: string;
  custody_owner: string;
  key_version: number;
  resource_revision: number;
  lifecycle_generation: number;
  payload_version: number;
  object_digest: string;
  invocation_id: string;
  binding_id: string;
  binding_revision: number;
  principal: string;
  policy_digest: string;
  expires_at: number;
}

export interface ResourceValueContext { binding: ResourceKeyBinding; path: string }
export interface ResourceValue {
  format: "lotor.resource-value.v1";
  context: ResourceValueContext;
  nonce: string;
  ciphertext: string;
}

const format = "lotor.resource-value.v1";
const encoder = new TextEncoder();
const maximumPlaintextBytes = 4 << 20;
const failure = () => new Error("Invalid encrypted resource value");

function object(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw failure();
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== names.length || keys.some(key => !names.includes(key))) throw failure();
  return record;
}
function identifier(value: unknown, maximum = 256): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || !/^[\x21-\x7e]+$/.test(value)) throw failure();
  return value;
}
function version(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw failure();
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw failure();
  return value;
}

// The fixed order matches bridge.ResourceKeyBinding, including nested scope.
// Do not serialize arbitrary caller object order as cryptographic context.
function context(value: unknown): ResourceValueContext {
  const outer = object(value, ["binding", "path"]);
  const b = object(outer.binding, ["scope", "client_id", "resource", "slot", "key_resource", "custody_owner", "key_version", "resource_revision", "lifecycle_generation", "payload_version", "object_digest", "invocation_id", "binding_id", "binding_revision", "principal", "policy_digest", "expires_at"]);
  const scope = object(b.scope, ["tenant_id", "application_id", "environment_id", "owner_resource"]);
  const path = outer.path;
  if (typeof path !== "string" || !path.length || encoder.encode(path).length > 1024 || /[\x00\r\n]/.test(path) ||
      [...path].some(character => { const point = character.codePointAt(0)!; return point >= 0xd800 && point <= 0xdfff; })) throw failure();
  return {
    binding: {
      scope: { tenant_id: identifier(scope.tenant_id), application_id: identifier(scope.application_id), environment_id: identifier(scope.environment_id), owner_resource: identifier(scope.owner_resource) },
      client_id: identifier(b.client_id), resource: identifier(b.resource), slot: identifier(b.slot, 128), key_resource: identifier(b.key_resource), custody_owner: digest(b.custody_owner), key_version: version(b.key_version),
      resource_revision: version(b.resource_revision), lifecycle_generation: version(b.lifecycle_generation), payload_version: version(b.payload_version), object_digest: digest(b.object_digest),
      invocation_id: identifier(b.invocation_id), binding_id: identifier(b.binding_id), binding_revision: version(b.binding_revision), principal: identifier(b.principal), policy_digest: digest(b.policy_digest), expires_at: version(b.expires_at),
    },
    path,
  };
}

function canonical(value: unknown): string {
  // Go's JSON encoder escapes these two Unicode separators even with HTML
  // escaping disabled. Everything else uses ordinary fixed-order JSON.
  return JSON.stringify(value).replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
function decode(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw failure();
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  if (btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_") !== value) throw failure();
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

/** Recipient-side decryption, not an authorization check or runtime key lease.
 * Derive expected context from the authorized execution/result, not an arbitrary
 * ciphertext's claimed resource. Historical ciphertext remains readable after
 * the invocation expires. The unlocked resource key stays in this process. */
export async function decryptResourceValue(resourceKey: Uint8Array, value: ResourceValue, expected: ResourceValueContext): Promise<Uint8Array> {
  try {
    const wire = object(value, ["format", "context", "nonce", "ciphertext"]);
    if (wire.format !== format || !(resourceKey instanceof Uint8Array) || resourceKey.length !== 32 ||
        typeof wire.ciphertext !== "string" || wire.ciphertext.length > Math.ceil((maximumPlaintextBytes + 16) * 4 / 3) ||
        typeof wire.nonce !== "string" || wire.nonce.length !== 16) throw failure();
    const actual = context(wire.context), required = context(expected);
    if (canonical(actual) !== canonical(required)) throw failure();
    const nonce = decode(wire.nonce), ciphertext = decode(wire.ciphertext);
    if (nonce.length !== 12 || ciphertext.length < 16) throw failure();
    const keyBytes = new Uint8Array(resourceKey);
    let key: CryptoKey;
    try { key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]); }
    finally { keyBytes.fill(0); }
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(canonical({ format, context: required })) }, key, ciphertext);
    return new Uint8Array(plaintext);
  } catch { throw failure(); }
}
