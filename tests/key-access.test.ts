import assert from "node:assert/strict";
import test from "node:test";
import { claimTransferredSubjectKey, createClaimTransferKey, createResourceEnvelope, createResourceSessionKeyRequest, createSubjectKeyRegistration, decodeBase64url, unlockSubjectKeyBackup, unwrapResourceEnvelope, unwrapResourceSessionEnvelope } from "../src/key-access.js";

function base64url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

test("generates client-owned subject keys without a server passphrase", async () => {
  const registration = await createSubjectKeyRegistration({ clientId: "avault_web", subject: "user:kim", passphrase: "a sufficiently long passphrase", backupPrivateKeys: false });
  assert.equal(registration.request.encryption_algorithm, "X25519");
  assert.equal(registration.request.signing_algorithm, "Ed25519");
  assert.equal(registration.request.encrypted_private_key_backup, undefined);
  assert.equal(decodeBase64url(registration.request.proof).length, 64);
});

test("claims a box-generated key using only WebCrypto and a user passphrase", async () => {
  const crypto = globalThis.crypto;
  const transferKey = await createClaimTransferKey();
  const browserPublic = await crypto.subtle.importKey("raw", new Uint8Array(decodeBase64url(transferKey.publicKey)).buffer, { name: "X25519" }, false, []);
  const boxKey = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const subjectEncryption = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const subjectSigning = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const encryptionJWK = await crypto.subtle.exportKey("jwk", subjectEncryption.privateKey);
  const signingJWK = await crypto.subtle.exportKey("jwk", subjectSigning.privateKey);
  const encryptionPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", subjectEncryption.publicKey));
  const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", subjectSigning.publicKey));
  const aad = new TextEncoder().encode(["lotor-principal-transfer-v1", "tenant", "app", "env", "user:alice", "1", "key_1", "clm_1", "123"].join("\0"));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: browserPublic }, boxKey.privateKey, 256));
  const sharedKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const wrappingKey = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: aad }, sharedKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const bundle = new TextEncoder().encode(JSON.stringify({ encryption_private_key: encryptionJWK.d, signing_private_seed: signingJWK.d }));
  const encryptedPrivateBundle = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, wrappingKey, bundle));
  const aadHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", aad)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const material = await claimTransferredSubjectKey({
    clientId: "client", subject: "user:alice", claimId: "clm_1", passphrase: "correct horse battery staple",
    transferPrivateKey: transferKey.privateKey,
    transfer: {
      encryptedPrivateBundle, boxPublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", boxKey.publicKey)), nonce,
      aadHash, associatedData: aad, encryptionPublicKey, signingPublicKey, keyId: "key_1",
    },
  });
  const restored = await unlockSubjectKeyBackup({
    keyId: "key_1", deviceId: "claim:clm_1", encryptionAlgorithm: "X25519", encryptionPublicKey,
    signingAlgorithm: "Ed25519", signingPublicKey,
    encryptedPrivateKeyBackup: decodeBase64url(material.request.encrypted_private_key_backup!), backupKDF: "scrypt",
    backupSalt: decodeBase64url(material.request.backup_salt!), backupNonce: decodeBase64url(material.request.backup_nonce!),
    backupFormatVersion: 1, status: "active", logSeq: 1,
  }, "correct horse battery staple");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign("Ed25519", restored.signingPrivateKey, challenge);
  assert.equal(await crypto.subtle.verify("Ed25519", subjectSigning.publicKey, signature, challenge), true);
});

test("restores a passphrase-protected device backup and rejects the wrong passphrase", async () => {
  const enrolled = await createSubjectKeyRegistration({ clientId: "avault_web", subject: "user:kim", passphrase: "correct horse battery staple" });
  const request = enrolled.request;
  const record = {
    keyId: request.key_id, deviceId: request.device_id, encryptionAlgorithm: request.encryption_algorithm,
    encryptionPublicKey: decodeBase64url(request.encryption_public_key), signingAlgorithm: request.signing_algorithm,
    signingPublicKey: decodeBase64url(request.signing_public_key), encryptedPrivateKeyBackup: decodeBase64url(request.encrypted_private_key_backup!),
    backupKDF: request.backup_kdf!, backupSalt: decodeBase64url(request.backup_salt!), backupNonce: decodeBase64url(request.backup_nonce!),
    backupFormatVersion: request.backup_format_version!, status: "active" as const, logSeq: 1,
  };
  const restored = await unlockSubjectKeyBackup(record, "correct horse battery staple");
  assert.equal(restored.keyId, request.key_id);
  await assert.rejects(() => unlockSubjectKeyBackup(record, "incorrect passphrase"), /could not unlock/);
});

test("wraps and unwraps a resource key with bound grant context", async () => {
  const recipient = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const issuer = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const member = {
    grantId: "grant_1", scope: "organization:acme", resource: "vault:vault-a",
    subject: "user:alice", relation: "editor", keyResource: "vault:vault-a", keyVersion: 1,
    recipientKeyId: "alice_key_1",
    recipientEncryptionPublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey)),
  };
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  const request = await createResourceEnvelope({ clientId: "avault_web", issuer: "user:owner", issuerKeyId: "owner_key_1", issuerSigningPrivateKey: issuer.privateKey, member, resourceKey });
  const envelope = {
    ...member, encryptionSuite: request.encryption_suite, ciphertext: decodeBase64url(request.ciphertext),
    aadHash: decodeBase64url(request.aad_hash), issuer: request.issuer, issuerKeyId: request.issuer_key_id,
    issuerSigningAlgorithm: "Ed25519" as const,
    issuerSigningPublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", issuer.publicKey)),
    issuerKeyStatus: "active" as const, signature: decodeBase64url(request.signature),
  };
  assert.deepEqual(await unwrapResourceEnvelope("avault_web", envelope, recipient.privateKey), resourceKey);
  await assert.rejects(() => unwrapResourceEnvelope("another_client", envelope, recipient.privateKey), /signature|context mismatch/u);
  const forged = { ...envelope, signature: new Uint8Array(envelope.signature) };
  forged.signature[0] ^= 1;
  await assert.rejects(() => unwrapResourceEnvelope("avault_web", forged, recipient.privateKey), /signature/u);
});

test("opens a short-lived managed resource session without an account passphrase", async () => {
  const request = await createResourceSessionKeyRequest();
  const browserPublicBytes = decodeBase64url(request.publicKey);
  const browserPublicKey = await crypto.subtle.importKey("raw", browserPublicBytes.buffer.slice(browserPublicBytes.byteOffset, browserPublicBytes.byteOffset + browserPublicBytes.byteLength) as ArrayBuffer, { name: "X25519" }, false, []);
  const boxKeys = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: browserPublicKey }, boxKeys.privateKey, 256));
  const expiresAt = (Date.now() + 60_000) * 1_000;
  const bindingInput = new TextEncoder().encode(`project:one\x00${request.publicKey}\x00${request.clientNonce}\x00${expiresAt}`);
  const binding = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bindingInput)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const aad = new TextEncoder().encode(`lotor-resource-envelope-v1\x00tenant\x00app\x00env\x00project:one\x001\x00user:alice\x00session:${binding}\x000\x000\x000\x000\x001`);
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const sharedKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: aad }, sharedKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, wrappingKey, resourceKey));
    const aadHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", aad)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const envelope = {
      resource: "project:one", keyResource: "project:one", keyVersion: 1,
      encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM",
      ephemeralPublicKey: base64url(new Uint8Array(await crypto.subtle.exportKey("raw", boxKeys.publicKey))),
      nonce: base64url(nonce), ciphertext: base64url(ciphertext), associatedData: base64url(aad), aadHash, expiresAt,
    } as const;
    const opened = await unwrapResourceSessionEnvelope(envelope, request, "project:one");
    assert.deepEqual(opened, resourceKey);
    await assert.rejects(() => unwrapResourceSessionEnvelope(envelope, request, "project:other"), /resource does not match/u);
    await assert.rejects(() => unwrapResourceSessionEnvelope(envelope, request, "project:one", expiresAt / 1_000), /expired/u);
    const anotherRequest = { ...request, clientNonce: `${request.clientNonce}x` };
    await assert.rejects(() => unwrapResourceSessionEnvelope(envelope, anotherRequest, "project:one"), /not bound/u);
  } finally {
    shared.fill(0);
    resourceKey.fill(0);
  }
});
