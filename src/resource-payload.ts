import type { EncryptedResourcePayloadUploadInput } from "./types.js";

const encoder = new TextEncoder();

export interface PrepareManagedResourcePayloadInput {
  clientId: string;
  resource: string;
  slot: string;
  schemaId: string;
  plaintext: Uint8Array;
  resourceKey: Uint8Array;
  resourceKeyRef: string;
  resourceKeyVersion: number;
  expectedPayloadVersion: number;
  resourceRevision: number;
  lifecycleGeneration: number;
}

export interface PrepareBrowserResourcePayloadInput extends PrepareManagedResourcePayloadInput {
  signingPrivateKey: CryptoKey;
  encryptorSubject: string;
  encryptorKeyId: string;
}

export interface PreparedBrowserResourcePayload {
  ciphertext: Uint8Array;
  upload: EncryptedResourcePayloadUploadInput;
}

export interface BrowserResourcePayloadCryptographicMetadata {
  clientId: string;
  resource: string;
  slot: string;
  schemaId: string;
  payloadVersion: number;
  objectDigest: string;
  objectSize: number;
	keyBindingRef: string;
  wrappedPayloadKey: string;
  aadHash: string;
  resourceRevision: number;
  lifecycleGeneration: number;
}

export interface PrepareBrowserResourcePayloadRewrapInput extends BrowserResourcePayloadCryptographicMetadata {
  expectedWrapRevision: number;
  previousResourceKey: Uint8Array;
  resourceKey: Uint8Array;
  previousResourceKeyVersion: number;
  resourceKeyVersion: number;
  signingPrivateKey: CryptoKey;
  rewrapperSubject: string;
  rewrapperKeyId: string;
}

export async function prepareBrowserResourcePayloadRewrap(input: PrepareBrowserResourcePayloadRewrapInput): Promise<import("./types.js").ResourcePayloadRewrapInput> {
  if (input.previousResourceKey.length !== 32 || input.resourceKey.length !== 32 || input.expectedWrapRevision < 0 ||
      input.previousResourceKeyVersion < 1 || input.resourceKeyVersion <= input.previousResourceKeyVersion) {
    throw new Error("invalid resource payload rewrap context");
  }
  const previous = fromBase64url(input.wrappedPayloadKey);
  const aad = fromBase64url(input.aadHash);
  if (previous.length !== 61 || previous[0] !== 1 || aad.length !== 32) throw new Error("invalid wrapped resource payload key");
  const previousKey = await crypto.subtle.importKey("raw", bytes(input.previousResourceKey), "AES-GCM", false, ["decrypt"]);
  const dataKey = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(previous.subarray(1, 13)), additionalData: bytes(aad) }, previousKey, bytes(previous.subarray(13))));
  try {
    const nextKey = await crypto.subtle.importKey("raw", bytes(input.resourceKey), "AES-GCM", false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(nonce), additionalData: bytes(aad) }, nextKey, bytes(dataKey)));
    const wrappedPayloadKey = base64url(join(new Uint8Array([1]), nonce, wrapped));
    const receipt = {
      client_id: input.clientId, resource: input.resource, slot: input.slot, schema_id: input.schemaId,
	      object_digest: input.objectDigest, key_binding_ref: input.keyBindingRef,
      previous_wrapped_payload_key: input.wrappedPayloadKey, wrapped_payload_key: wrappedPayloadKey, aad_hash: input.aadHash,
      rewrapper_subject: input.rewrapperSubject, rewrapper_key_id: input.rewrapperKeyId,
      payload_version: input.payloadVersion, expected_wrap_revision: input.expectedWrapRevision,
      previous_key_version: input.previousResourceKeyVersion, key_version: input.resourceKeyVersion,
      resource_revision: input.resourceRevision, lifecycle_generation: input.lifecycleGeneration,
    };
    const rewrapReceipt = base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", input.signingPrivateKey, bytes(canonicalJSON(receipt)))));
    return {
	      payloadVersion: input.payloadVersion, expectedWrapRevision: input.expectedWrapRevision, keyBindingRef: input.keyBindingRef,
      previousKeyVersion: input.previousResourceKeyVersion, keyVersion: input.resourceKeyVersion,
      wrappedPayloadKey, rewrapperSubject: input.rewrapperSubject, rewrapperKeyId: input.rewrapperKeyId, rewrapReceipt,
      resourceRevision: input.resourceRevision, lifecycleGeneration: input.lifecycleGeneration,
    };
  } finally {
    dataKey.fill(0);
  }
}

export async function prepareBrowserResourcePayload(input: PrepareBrowserResourcePayloadInput): Promise<PreparedBrowserResourcePayload> {
	return prepareResourcePayload(input);
}

/** Encrypt with a short-lived managed/customer-box resource session. Lotor asks
 * that box to attest the ciphertext context when the upload is reserved. */
export async function prepareManagedResourcePayload(input: PrepareManagedResourcePayloadInput): Promise<PreparedBrowserResourcePayload> {
	return prepareResourcePayload(input);
}

async function prepareResourcePayload(input: PrepareManagedResourcePayloadInput | PrepareBrowserResourcePayloadInput): Promise<PreparedBrowserResourcePayload> {
  if (input.plaintext.length === 0) throw new Error("resource payload plaintext must not be empty");
  if (input.resourceKey.length !== 32) throw new Error("resourceKey must contain 32 bytes");
  if (input.expectedPayloadVersion < 0 || input.resourceKeyVersion < 1 || input.resourceRevision < 1 || input.lifecycleGeneration < 1) throw new Error("invalid resource payload version context");
  const aadContext = {
    client_id: input.clientId, resource: input.resource, slot: input.slot, schema_id: input.schemaId,
    resource_revision: input.resourceRevision, lifecycle_generation: input.lifecycleGeneration,
  };
  const aadHash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(canonicalJSON(aadContext))));
  const dataKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  try {
    const dataKey = await crypto.subtle.importKey("raw", bytes(dataKeyBytes), "AES-GCM", false, ["encrypt"]);
    const payloadNonce = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(payloadNonce), additionalData: bytes(aadHash) }, dataKey, bytes(input.plaintext)));
    const ciphertext = join(new Uint8Array([1]), payloadNonce, encrypted);

    const wrappingKey = await crypto.subtle.importKey("raw", bytes(input.resourceKey), "AES-GCM", false, ["encrypt"]);
    const wrappingNonce = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(wrappingNonce), additionalData: bytes(aadHash) }, wrappingKey, bytes(dataKeyBytes)));
    const wrappedPayloadKey = base64url(join(new Uint8Array([1]), wrappingNonce, wrapped));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(ciphertext)));
    const objectDigest = hex(digest);
    const aadHashEncoded = base64url(aadHash);
    const receipt = {
      client_id: input.clientId, resource: input.resource, slot: input.slot, schema_id: input.schemaId,
      representation: "encrypted-envelope-v1", object_digest: objectDigest, encryption_suite: "AES-256-GCM",
      key_binding_ref: input.resourceKeyRef, wrapped_payload_key: wrappedPayloadKey, aad_hash: aadHashEncoded,
	  encryptor_subject: "signingPrivateKey" in input ? input.encryptorSubject : "",
	  encryptor_key_id: "signingPrivateKey" in input ? input.encryptorKeyId : "",
	  expected_payload_version: input.expectedPayloadVersion,
      object_size: ciphertext.length, key_version: input.resourceKeyVersion, resource_revision: input.resourceRevision,
      lifecycle_generation: input.lifecycleGeneration,
    };
	const signature = "signingPrivateKey" in input
	  ? base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", input.signingPrivateKey, bytes(canonicalJSON(receipt)))))
	  : undefined;
    return {
      ciphertext,
      upload: {
        schemaId: input.schemaId, expectedPayloadVersion: input.expectedPayloadVersion,
        representation: "encrypted-envelope-v1", objectDigest, objectSize: ciphertext.length, encryptionSuite: "AES-256-GCM",
        keyBindingRef: input.resourceKeyRef, keyVersion: input.resourceKeyVersion,
		wrappedPayloadKey, aadHash: aadHashEncoded,
		...(signature === undefined ? {} : {
		  encryptorSubject: (input as PrepareBrowserResourcePayloadInput).encryptorSubject,
		  encryptorKeyId: (input as PrepareBrowserResourcePayloadInput).encryptorKeyId,
		  encryptionReceipt: signature,
		}),
        resourceRevision: input.resourceRevision, lifecycleGeneration: input.lifecycleGeneration,
      },
    };
  } finally {
    dataKeyBytes.fill(0);
  }
}

export async function decryptBrowserResourcePayload(
  ciphertext: Uint8Array,
  metadata: BrowserResourcePayloadCryptographicMetadata,
  resourceKey: Uint8Array,
): Promise<Uint8Array> {
  if (resourceKey.length !== 32 || ciphertext.length < 30 || ciphertext[0] !== 1) throw new Error("invalid encrypted resource payload");
  const actualDigest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(ciphertext))));
  if (actualDigest !== metadata.objectDigest || ciphertext.length !== metadata.objectSize) throw new Error("resource payload ciphertext does not match its manifest");
  const aadContext = {
    client_id: metadata.clientId, resource: metadata.resource, slot: metadata.slot, schema_id: metadata.schemaId,
    resource_revision: metadata.resourceRevision, lifecycle_generation: metadata.lifecycleGeneration,
  };
  const aadHash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(canonicalJSON(aadContext))));
  if (base64url(aadHash) !== metadata.aadHash) throw new Error("resource payload authenticated context does not match");
  const wrapped = fromBase64url(metadata.wrappedPayloadKey);
  if (wrapped.length !== 61 || wrapped[0] !== 1) throw new Error("invalid wrapped resource payload key");
  const wrappingKey = await crypto.subtle.importKey("raw", bytes(resourceKey), "AES-GCM", false, ["decrypt"]);
  const dataKeyBytes = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(wrapped.subarray(1, 13)), additionalData: bytes(aadHash) }, wrappingKey, bytes(wrapped.subarray(13))));
  try {
    const dataKey = await crypto.subtle.importKey("raw", bytes(dataKeyBytes), "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(ciphertext.subarray(1, 13)), additionalData: bytes(aadHash) }, dataKey, bytes(ciphertext.subarray(13))));
  } finally {
    dataKeyBytes.fill(0);
  }
}

function canonicalJSON(value: object): Uint8Array {
  return encoder.encode(JSON.stringify(value).replace(/[<>&]/gu, (character) => ({ "<": "\\u003c", ">": "\\u003e", "&": "\\u0026" })[character]!));
}

function bytes(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function join(...values: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.length; }
  return output;
}

function base64url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function fromBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
