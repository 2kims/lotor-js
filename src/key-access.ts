import { scryptAsync } from "@noble/hashes/scrypt.js";

const encoder = new TextEncoder();

function webCrypto(): Crypto {
  if (globalThis.crypto?.subtle === undefined) throw new Error("Web Crypto is required for Lotor key enrollment");
  return globalThis.crypto;
}

function base64url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function uint32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function uint64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid key backup format version");
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), false);
  return output;
}

function concat(values: Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.length; }
  return output;
}

function buffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.length);
  copy.set(value);
  return copy.buffer;
}

function proofMessage(fields: Uint8Array[], backupFormatVersion: number): Uint8Array {
  return concat([...fields.flatMap((field) => [uint32(field.length), field]), uint64(backupFormatVersion)]);
}

function randomID(prefix: string): string {
  return `${prefix}_${base64url(webCrypto().getRandomValues(new Uint8Array(18)))}`;
}

export interface CreateSubjectKeyRegistrationInput {
  clientId: string;
  subject: string;
  passphrase: string;
  deviceId?: string;
  backupPrivateKeys?: boolean;
}

export interface SubjectKeyRegistrationRequest {
  key_id: string;
  device_id: string;
  encryption_algorithm: "X25519";
  encryption_public_key: string;
  signing_algorithm: "Ed25519";
  signing_public_key: string;
  encrypted_private_key_backup?: string;
  backup_kdf?: "scrypt";
  backup_salt?: string;
  backup_nonce?: string;
  backup_format_version?: 1;
  proof: string;
}

export interface DeviceKeyMaterial {
  keyId: string;
  deviceId: string;
  encryptionPrivateKey: CryptoKey;
  signingPrivateKey: CryptoKey;
}

export interface SubjectKeyRecord {
  keyId: string;
  deviceId: string;
  encryptionAlgorithm: "X25519";
  encryptionPublicKey: Uint8Array;
  signingAlgorithm: "Ed25519";
  signingPublicKey: Uint8Array;
  encryptedPrivateKeyBackup: Uint8Array;
  backupKDF: "scrypt" | "";
  backupSalt: Uint8Array;
  backupNonce: Uint8Array;
  backupFormatVersion: number;
  status: "active" | "revoked";
  logSeq: number;
}

export async function createSubjectKeyRegistration(input: CreateSubjectKeyRegistrationInput): Promise<{
  request: SubjectKeyRegistrationRequest;
  keys: DeviceKeyMaterial;
}> {
  const crypto = webCrypto();
  const clientId = input.clientId.trim();
  const subject = input.subject.trim();
  const passphrase = input.passphrase;
  if (clientId === "" || subject === "" || passphrase.length < 12) {
    throw new Error("clientId, subject, and a passphrase of at least 12 characters are required");
  }
  const keyId = randomID("key");
  const deviceId = input.deviceId?.trim() || randomID("device");
  const encryptionKeys = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const signingKeys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const encryptionPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", encryptionKeys.publicKey));
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", signingKeys.publicKey));

  let encryptedBackup = new Uint8Array();
  let backupSalt = new Uint8Array();
  let backupNonce = new Uint8Array();
  let backupKDF: "scrypt" | undefined;
  let backupFormatVersion: 1 | undefined;
  if (input.backupPrivateKeys !== false) {
    backupSalt = crypto.getRandomValues(new Uint8Array(16));
    backupNonce = crypto.getRandomValues(new Uint8Array(12));
    const derived = await scryptAsync(encoder.encode(passphrase), backupSalt, { N: 65536, r: 8, p: 1, dkLen: 32 });
    try {
      const wrappingKey = await crypto.subtle.importKey("raw", buffer(derived), "AES-GCM", false, ["encrypt"]);
      const backupPayload = encoder.encode(JSON.stringify({
        version: 1,
        key_id: keyId,
        device_id: deviceId,
        encryption_public_key: base64url(encryptionPublicKey),
        signing_public_key: base64url(signingPublicKey),
        encryption_private_key: base64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", encryptionKeys.privateKey))),
        signing_private_key: base64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", signingKeys.privateKey))),
      }));
      encryptedBackup = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: backupNonce }, wrappingKey, backupPayload));
    } finally {
      derived.fill(0);
    }
    backupKDF = "scrypt";
    backupFormatVersion = 1;
  }

  const backupHash = new Uint8Array(await crypto.subtle.digest("SHA-256", encryptedBackup));
  const message = proofMessage([
    encoder.encode("lotor-account-key-v1"), encoder.encode(subject),
    encoder.encode(keyId), encoder.encode(deviceId), encoder.encode("X25519"), encryptionPublicKey,
    encoder.encode("Ed25519"), signingPublicKey, encoder.encode(backupKDF ?? ""), backupSalt,
    backupNonce, backupHash,
  ], backupFormatVersion ?? 0);
  const proof = new Uint8Array(await crypto.subtle.sign("Ed25519", signingKeys.privateKey, buffer(message)));
  return {
    request: {
      key_id: keyId, device_id: deviceId, encryption_algorithm: "X25519",
      encryption_public_key: base64url(encryptionPublicKey), signing_algorithm: "Ed25519",
      signing_public_key: base64url(signingPublicKey),
      ...(backupKDF === undefined ? {} : {
        encrypted_private_key_backup: base64url(encryptedBackup), backup_kdf: backupKDF,
        backup_salt: base64url(backupSalt), backup_nonce: base64url(backupNonce),
        backup_format_version: backupFormatVersion,
      }),
      proof: base64url(proof),
    },
    keys: { keyId, deviceId, encryptionPrivateKey: encryptionKeys.privateKey, signingPrivateKey: signingKeys.privateKey },
  };
}

export async function unlockSubjectKeyBackup(record: SubjectKeyRecord, passphrase: string): Promise<DeviceKeyMaterial> {
  const crypto = webCrypto();
  if (record.backupKDF !== "scrypt" || record.backupFormatVersion !== 1 || record.encryptedPrivateKeyBackup.length === 0 || record.backupSalt.length < 16 || record.backupNonce.length !== 12) {
    throw new Error("subject key does not contain a supported private-key backup");
  }
  if (passphrase.length < 12) throw new Error("a passphrase of at least 12 characters is required");
  const derived = await scryptAsync(encoder.encode(passphrase), record.backupSalt, { N: 65536, r: 8, p: 1, dkLen: 32 });
  try {
    const wrappingKey = await crypto.subtle.importKey("raw", buffer(derived), "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(record.backupNonce) }, wrappingKey, buffer(record.encryptedPrivateKeyBackup));
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    if (payload.version !== 1 || payload.key_id !== record.keyId || payload.device_id !== record.deviceId ||
      payload.encryption_public_key !== base64url(record.encryptionPublicKey) || payload.signing_public_key !== base64url(record.signingPublicKey) ||
      typeof payload.encryption_private_key !== "string" || typeof payload.signing_private_key !== "string") {
      throw new Error("subject key backup does not match the selected key record");
    }
    const encryptionPrivateKey = await crypto.subtle.importKey("pkcs8", buffer(decodeBase64url(payload.encryption_private_key)), { name: "X25519" }, false, ["deriveBits"]);
    const signingPrivateKey = await crypto.subtle.importKey("pkcs8", buffer(decodeBase64url(payload.signing_private_key)), { name: "Ed25519" }, false, ["sign"]);
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign("Ed25519", signingPrivateKey, buffer(challenge));
    const signingPublicKey = await crypto.subtle.importKey("raw", buffer(record.signingPublicKey), { name: "Ed25519" }, false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", signingPublicKey, signature, buffer(challenge))) throw new Error("subject key backup signing key does not match");
    return { keyId: record.keyId, deviceId: record.deviceId, encryptionPrivateKey, signingPrivateKey };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("subject key backup")) throw error;
    throw new Error("could not unlock subject key backup");
  } finally {
    derived.fill(0);
  }
}

export interface ClaimTransferMaterial {
  encryptedPrivateBundle: Uint8Array;
  boxPublicKey: Uint8Array;
  nonce: Uint8Array;
  aadHash: string;
  associatedData: Uint8Array;
  encryptionPublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  keyId: string;
}

export async function createClaimTransferKey(): Promise<{ publicKey: string; privateKey: CryptoKey }> {
  const pair = await webCrypto().subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  return {
    publicKey: base64url(new Uint8Array(await webCrypto().subtle.exportKey("raw", pair.publicKey))),
    privateKey: pair.privateKey,
  };
}

export async function claimTransferredSubjectKey(input: {
  clientId: string;
  subject: string;
  claimId: string;
  passphrase: string;
  transferPrivateKey: CryptoKey;
  transfer: ClaimTransferMaterial;
}): Promise<{ request: SubjectKeyRegistrationRequest; keys: DeviceKeyMaterial }> {
  const crypto = webCrypto();
  if (input.passphrase.length < 12) throw new Error("a passphrase of at least 12 characters is required");
  if (input.transfer.boxPublicKey.length !== 32 || input.transfer.nonce.length !== 12 || input.transfer.encryptionPublicKey.length !== 32 || input.transfer.signingPublicKey.length !== 32) {
    throw new Error("invalid key claim transfer material");
  }
  const aadDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(input.transfer.associatedData)));
  const expectedAADHash = Array.from(aadDigest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (expectedAADHash !== input.transfer.aadHash) throw new Error("key claim transfer context mismatch");
  const boxPublicKey = await crypto.subtle.importKey("raw", buffer(input.transfer.boxPublicKey), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: boxPublicKey }, input.transferPrivateKey, 256));
  let encryptionPrivateRaw = new Uint8Array();
  let signingSeed = new Uint8Array();
  try {
    const sharedKey = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: buffer(input.transfer.associatedData) }, sharedKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(input.transfer.nonce), additionalData: buffer(input.transfer.associatedData) }, wrappingKey, buffer(input.transfer.encryptedPrivateBundle));
    const bundle = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    if (typeof bundle.encryption_private_key !== "string" || typeof bundle.signing_private_seed !== "string") throw new Error("invalid private key claim bundle");
    encryptionPrivateRaw = new Uint8Array(decodeBase64url(bundle.encryption_private_key));
    signingSeed = new Uint8Array(decodeBase64url(bundle.signing_private_seed));
    if (encryptionPrivateRaw.length !== 32 || signingSeed.length !== 32) throw new Error("invalid private key claim bundle");
    const encryptionPrivateKey = await crypto.subtle.importKey("jwk", {
      kty: "OKP", crv: "X25519", d: base64url(encryptionPrivateRaw), x: base64url(input.transfer.encryptionPublicKey),
      ext: true, key_ops: ["deriveBits"],
    }, { name: "X25519" }, true, ["deriveBits"]);
    const signingPrivateKey = await crypto.subtle.importKey("jwk", {
      kty: "OKP", crv: "Ed25519", d: base64url(signingSeed), x: base64url(input.transfer.signingPublicKey),
      ext: true, key_ops: ["sign"],
    }, { name: "Ed25519" }, true, ["sign"]);
    const backupSalt = crypto.getRandomValues(new Uint8Array(16));
    const backupNonce = crypto.getRandomValues(new Uint8Array(12));
    const derived = await scryptAsync(encoder.encode(input.passphrase), backupSalt, { N: 65536, r: 8, p: 1, dkLen: 32 });
    let encryptedBackup: Uint8Array;
    try {
      const backupKey = await crypto.subtle.importKey("raw", buffer(derived), "AES-GCM", false, ["encrypt"]);
      const backupPayload = encoder.encode(JSON.stringify({
        version: 1, key_id: input.transfer.keyId, device_id: `claim:${input.claimId}`,
        encryption_public_key: base64url(input.transfer.encryptionPublicKey), signing_public_key: base64url(input.transfer.signingPublicKey),
        encryption_private_key: base64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", encryptionPrivateKey))),
        signing_private_key: base64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", signingPrivateKey))),
      }));
      encryptedBackup = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: backupNonce }, backupKey, backupPayload));
    } finally {
      derived.fill(0);
    }
    const backupHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(encryptedBackup)));
    const message = proofMessage([
      encoder.encode("lotor-account-key-v1"), encoder.encode(input.subject),
      encoder.encode(input.transfer.keyId), encoder.encode(`claim:${input.claimId}`), encoder.encode("X25519"), input.transfer.encryptionPublicKey,
      encoder.encode("Ed25519"), input.transfer.signingPublicKey, encoder.encode("scrypt"), backupSalt, backupNonce, backupHash,
    ], 1);
    const proof = new Uint8Array(await crypto.subtle.sign("Ed25519", signingPrivateKey, buffer(message)));
    return {
      request: {
        key_id: input.transfer.keyId, device_id: `claim:${input.claimId}`, encryption_algorithm: "X25519",
        encryption_public_key: base64url(input.transfer.encryptionPublicKey), signing_algorithm: "Ed25519",
        signing_public_key: base64url(input.transfer.signingPublicKey), encrypted_private_key_backup: base64url(encryptedBackup),
        backup_kdf: "scrypt", backup_salt: base64url(backupSalt), backup_nonce: base64url(backupNonce), backup_format_version: 1,
        proof: base64url(proof),
      },
      keys: { keyId: input.transfer.keyId, deviceId: `claim:${input.claimId}`, encryptionPrivateKey, signingPrivateKey },
    };
  } finally {
    shared.fill(0);
    encryptionPrivateRaw.fill(0);
    signingSeed.fill(0);
  }
}

export interface ResourceProvisioningMember {
  grantId: string;
  scope: string;
  resource: string;
  subject: string;
  relation: string;
  keyResource: string;
  keyVersion: number;
  recipientKeyId: string;
  recipientEncryptionPublicKey: Uint8Array;
}

export interface CreateResourceEnvelopeInput {
  clientId: string;
  issuer: string;
  issuerKeyId: string;
  issuerSigningPrivateKey: CryptoKey;
  member: ResourceProvisioningMember;
  resourceKey: Uint8Array;
  associatedData: Uint8Array;
}

export interface ResourceEnvelopeRequest {
  scope: string;
  grant_id: string;
  key_resource: string;
  key_version: number;
  recipient_subject: string;
  recipient_key_id: string;
  encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: string;
  aad_hash: string;
  issuer: string;
  issuer_key_id: string;
  signature: string;
}

function validateResourceAAD(aad: Uint8Array, member: Pick<ResourceProvisioningMember, "keyResource" | "keyVersion" | "subject" | "recipientKeyId">): void {
  const fields = new TextDecoder("utf-8", { fatal: true }).decode(aad).split("\0");
  if (fields.length !== 13 || fields[0] !== "lotor-resource-envelope-v1" ||
      fields.slice(1, 4).some((field) => field.length === 0) ||
      fields[4] !== member.keyResource || fields[5] !== String(member.keyVersion) ||
      fields[6] !== member.subject || fields[7] !== member.recipientKeyId ||
      fields.slice(8).some((field) => !/^(0|[1-9][0-9]*)$/.test(field))) {
    throw new Error("resource envelope context mismatch");
  }
}

export async function createResourceEnvelope(input: CreateResourceEnvelopeInput): Promise<ResourceEnvelopeRequest> {
  const crypto = webCrypto();
  if (input.resourceKey.length !== 32) throw new Error("resourceKey must contain 32 bytes");
  if (input.member.recipientEncryptionPublicKey.length !== 32) throw new Error("recipient public key must contain 32 bytes");
  validateResourceAAD(input.associatedData, input.member);
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const recipient = await crypto.subtle.importKey("raw", buffer(input.member.recipientEncryptionPublicKey), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, ephemeral.privateKey, 256));
  const aad = input.associatedData;
  const aadHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(aad)));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const sharedKey = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: buffer(aad) }, sharedKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: buffer(aad) }, wrappingKey, buffer(input.resourceKey)));
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
    const ciphertext = encoder.encode(JSON.stringify({ version: 1, actor: input.issuer,
      ephemeral_public_key: base64url(ephemeralPublic), nonce: base64url(nonce), ciphertext: base64url(encrypted),
      aad: base64url(aad), aad_hash: Array.from(aadHash, (byte) => byte.toString(16).padStart(2, "0")).join(""),
    }));
    const ciphertextHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(ciphertext)));
    const signatureMessage = proofMessage([
      encoder.encode("lotor-resource-envelope-v1"), encoder.encode(input.clientId), encoder.encode(input.issuer),
      encoder.encode(input.member.scope), encoder.encode(input.member.grantId), encoder.encode(input.member.keyResource),
      encoder.encode(input.member.subject), encoder.encode(input.member.recipientKeyId),
      encoder.encode("X25519-HKDF-SHA256-AES-256-GCM"), ciphertextHash, aadHash, encoder.encode(input.issuerKeyId),
    ], input.member.keyVersion);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", input.issuerSigningPrivateKey, buffer(signatureMessage)));
    return {
      scope: input.member.scope, grant_id: input.member.grantId, key_resource: input.member.keyResource,
      key_version: input.member.keyVersion, recipient_subject: input.member.subject,
      recipient_key_id: input.member.recipientKeyId, encryption_suite: "X25519-HKDF-SHA256-AES-256-GCM",
      ciphertext: base64url(ciphertext), aad_hash: base64url(aadHash), issuer: input.issuer,
      issuer_key_id: input.issuerKeyId, signature: base64url(signature),
    };
  } finally {
    shared.fill(0);
  }
}

export interface EncryptedResourceEnvelope {
  grantId: string;
  scope: string;
  resource: string;
  subject: string;
  relation: string;
  keyResource: string;
  keyVersion: number;
  recipientKeyId: string;
  encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
  ciphertext: Uint8Array;
  aadHash: Uint8Array;
  issuer: string;
  issuerKeyId: string;
  issuerSigningAlgorithm: "Ed25519";
  issuerSigningPublicKey: Uint8Array;
  issuerKeyStatus: "active" | "revoked";
  signature: Uint8Array;
}

export interface ResourceSessionKeyRequest {
  publicKey: string;
  clientNonce: string;
  privateKey: CryptoKey;
}

export async function createResourceSessionKeyRequest(): Promise<ResourceSessionKeyRequest> {
  const crypto = webCrypto();
  const keys = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  return {
    publicKey: base64url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey))),
    clientNonce: base64url(crypto.getRandomValues(new Uint8Array(24))),
    privateKey: keys.privateKey,
  };
}

export async function unwrapResourceSessionEnvelope(
  envelope: import("./types.js").ResourceSessionEnvelope,
  request: ResourceSessionKeyRequest,
  expectedResource: string,
  now = Date.now(),
): Promise<Uint8Array> {
  const crypto = webCrypto();
  if (envelope.resource !== expectedResource) {
    throw new Error("resource session envelope resource does not match request");
  }
  if (envelope.expiresAt <= now * 1_000) {
    throw new Error("resource session envelope has expired");
  }
  const aad = decodeBase64url(envelope.associatedData);
  const expectedHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(aad)));
  const actualHash = envelope.aadHash.toLowerCase();
  if (actualHash !== [...expectedHash].map((value) => value.toString(16).padStart(2, "0")).join("")) {
    throw new Error("resource session envelope AAD hash does not match");
  }
  const fields = new TextDecoder().decode(aad).split("\x00");
  const bindingInput = new TextEncoder().encode(`${expectedResource}\x00${request.publicKey}\x00${request.clientNonce}\x00${envelope.expiresAt}`);
  const bindingHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(bindingInput)));
  const expectedKeyId = `session:${[...bindingHash].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
  if (fields.length !== 13 || fields[0] !== "lotor-resource-envelope-v1" || fields[4] !== envelope.keyResource ||
      Number(fields[5]) !== envelope.keyVersion || fields[7] !== expectedKeyId) {
    throw new Error("resource session envelope is not bound to this request");
  }
  const ephemeral = await crypto.subtle.importKey("raw", buffer(decodeBase64url(envelope.ephemeralPublicKey)), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, request.privateKey, 256));
  try {
    const sharedKey = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: buffer(new Uint8Array()), info: buffer(aad) },
      sharedKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(decodeBase64url(envelope.nonce)), additionalData: buffer(aad) },
      wrappingKey,
      buffer(decodeBase64url(envelope.ciphertext)),
    ));
    if (plaintext.length !== 32) {
      plaintext.fill(0);
      throw new Error("resource session envelope did not contain a 32-byte key");
    }
    return plaintext;
  } finally {
    shared.fill(0);
  }
}

export async function unwrapResourceEnvelope(clientId: string, envelope: EncryptedResourceEnvelope, privateKey: CryptoKey): Promise<Uint8Array> {
  const crypto = webCrypto();
  if (envelope.ciphertext.length > 16384 || envelope.encryptionSuite !== "X25519-HKDF-SHA256-AES-256-GCM") throw new Error("invalid resource envelope format");
  const wire: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(envelope.ciphertext));
  if (wire === null || typeof wire !== "object" || Array.isArray(wire)) throw new Error("invalid resource envelope format");
  const fields = wire as Record<string, unknown>;
  if (fields.version !== 1 || typeof fields.actor !== "string" || fields.actor.length === 0 ||
      Object.keys(fields).sort().join(",") !== "aad,aad_hash,actor,ciphertext,ephemeral_public_key,nonce,version") throw new Error("invalid resource envelope format");
  const wireBytes = (name: string): Uint8Array => {
    const value = fields[name];
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid resource envelope format");
    const decoded = decodeBase64url(value);
    if (base64url(decoded) !== value) throw new Error("invalid resource envelope format");
    return decoded;
  };
  const ephemeralBytes = wireBytes("ephemeral_public_key"), nonce = wireBytes("nonce"), encrypted = wireBytes("ciphertext"), aad = wireBytes("aad");
  if (ephemeralBytes.length !== 32 || nonce.length !== 12 || encrypted.length !== 48) throw new Error("invalid resource envelope format");
  validateResourceAAD(aad, envelope);
  if (envelope.issuerKeyStatus !== "active" || envelope.issuerSigningAlgorithm !== "Ed25519" || envelope.issuerSigningPublicKey.length !== 32 || envelope.signature.length !== 64) {
    throw new Error("invalid resource envelope issuer key");
  }
  const ciphertextHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(envelope.ciphertext)));
  const signatureMessage = proofMessage([
    encoder.encode("lotor-resource-envelope-v1"), encoder.encode(clientId), encoder.encode(fields.actor),
    encoder.encode(envelope.scope), encoder.encode(envelope.grantId), encoder.encode(envelope.keyResource),
    encoder.encode(envelope.subject), encoder.encode(envelope.recipientKeyId),
    encoder.encode(envelope.encryptionSuite), ciphertextHash, envelope.aadHash, encoder.encode(envelope.issuerKeyId),
  ], envelope.keyVersion);
  const issuerSigningPublicKey = await crypto.subtle.importKey("raw", buffer(envelope.issuerSigningPublicKey), { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", issuerSigningPublicKey, buffer(envelope.signature), buffer(signatureMessage))) {
    throw new Error("invalid resource envelope signature");
  }
  const ephemeralPublic = await crypto.subtle.importKey("raw", buffer(ephemeralBytes), { name: "X25519" }, false, []);
  const aadHash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(aad)));
  if (fields.aad_hash !== Array.from(aadHash, (byte) => byte.toString(16).padStart(2, "0")).join("") || aadHash.length !== envelope.aadHash.length || !aadHash.every((byte, index) => byte === envelope.aadHash[index])) throw new Error("resource envelope context mismatch");
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeralPublic }, privateKey, 256));
  try {
    const sharedKey = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: buffer(aad) }, sharedKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(aad) }, wrappingKey, buffer(encrypted)));
  } finally {
    shared.fill(0);
  }
}
