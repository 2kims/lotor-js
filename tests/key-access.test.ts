import assert from "node:assert/strict";
import test from "node:test";
import { createResourceEnvelope, createSubjectKeyRegistration, decodeBase64url, unlockSubjectKeyBackup, unwrapResourceEnvelope } from "../src/key-access.js";

test("generates client-owned subject keys without a server passphrase", async () => {
  const registration = await createSubjectKeyRegistration({ clientId: "avault_web", subject: "user:kim", passphrase: "a sufficiently long passphrase", backupPrivateKeys: false });
  assert.equal(registration.request.encryption_algorithm, "X25519");
  assert.equal(registration.request.signing_algorithm, "Ed25519");
  assert.equal(registration.request.encrypted_private_key_backup, undefined);
  assert.equal(decodeBase64url(registration.request.proof).length, 64);
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
