import assert from "node:assert/strict";
import test from "node:test";

import { decryptBrowserResourcePayload, prepareBrowserResourcePayload, prepareBrowserResourcePayloadRewrap, prepareManagedResourcePayload } from "../src/index.js";

test("encrypts and decrypts a browser resource payload without a Lotor plaintext boundary", async () => {
  const signing = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = new TextEncoder().encode('{"token":"slack-secret"}');
  const prepared = await prepareBrowserResourcePayload({
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    plaintext, resourceKey, resourceKeyRef: "organization:acme", resourceKeyVersion: 2,
    signingPrivateKey: signing.privateKey, encryptorSubject: "user:alice", encryptorKeyId: "key_alice",
    expectedPayloadVersion: 0, resourceRevision: 4, lifecycleGeneration: 1,
  });
  assert.equal(new TextDecoder().decode(prepared.ciphertext).includes("slack-secret"), false);
  assert.equal(prepared.upload.objectSize, prepared.ciphertext.length);
  assert.equal(prepared.upload.representation, "encrypted-envelope-v1");
  const decrypted = await decryptBrowserResourcePayload(prepared.ciphertext, {
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    payloadVersion: 1, objectDigest: prepared.upload.objectDigest, objectSize: prepared.upload.objectSize,
	keyBindingRef: "organization:acme", wrappedPayloadKey: prepared.upload.wrappedPayloadKey, aadHash: prepared.upload.aadHash,
    resourceRevision: 4, lifecycleGeneration: 1,
  }, resourceKey);
  assert.deepEqual(decrypted, plaintext);
  const recreated = await decryptBrowserResourcePayload(prepared.ciphertext, {
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    payloadVersion: 37, objectDigest: prepared.upload.objectDigest, objectSize: prepared.upload.objectSize,
	keyBindingRef: "organization:acme", wrappedPayloadKey: prepared.upload.wrappedPayloadKey, aadHash: prepared.upload.aadHash,
    resourceRevision: 4, lifecycleGeneration: 1,
  }, resourceKey);
  assert.deepEqual(recreated, plaintext);
});

test("prepares managed-custody ciphertext without requiring a browser signing key", async () => {
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  const prepared = await prepareManagedResourcePayload({
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    plaintext: new TextEncoder().encode('{"token":"managed-secret"}'), resourceKey,
    resourceKeyRef: "organization:acme", resourceKeyVersion: 2, expectedPayloadVersion: 4,
    resourceRevision: 6, lifecycleGeneration: 1,
  });
  assert.equal(prepared.upload.encryptionReceipt, undefined);
  assert.equal(prepared.upload.encryptorSubject, undefined);
  assert.equal(new TextDecoder().decode(prepared.ciphertext).includes("managed-secret"), false);
});

test("rejects browser payload ciphertext and lifecycle context tampering", async () => {
  const signing = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const resourceKey = crypto.getRandomValues(new Uint8Array(32));
  const prepared = await prepareBrowserResourcePayload({
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    plaintext: new Uint8Array([1, 2, 3]), resourceKey, resourceKeyRef: "organization:acme", resourceKeyVersion: 1,
    signingPrivateKey: signing.privateKey, encryptorSubject: "user:alice", encryptorKeyId: "key_alice",
    expectedPayloadVersion: 0, resourceRevision: 1, lifecycleGeneration: 1,
  });
	const metadata = { clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1", payloadVersion: 1, objectDigest: prepared.upload.objectDigest, objectSize: prepared.upload.objectSize, keyBindingRef: "organization:acme", wrappedPayloadKey: prepared.upload.wrappedPayloadKey, aadHash: prepared.upload.aadHash, resourceRevision: 1, lifecycleGeneration: 1 };
  const tampered = prepared.ciphertext.slice();
  tampered[20] ^= 1;
  await assert.rejects(() => decryptBrowserResourcePayload(tampered, metadata, resourceKey), /does not match/u);
  await assert.rejects(() => decryptBrowserResourcePayload(prepared.ciphertext, { ...metadata, lifecycleGeneration: 2 }, resourceKey), /context does not match/u);
});

test("rewraps only the payload data key for browser custody", async () => {
  const signing = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const oldResourceKey = crypto.getRandomValues(new Uint8Array(32));
  const newResourceKey = crypto.getRandomValues(new Uint8Array(32));
  const plaintext = new TextEncoder().encode('{"token":"still-the-same"}');
  const prepared = await prepareBrowserResourcePayload({
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    plaintext, resourceKey: oldResourceKey, resourceKeyRef: "organization:acme", resourceKeyVersion: 2,
    signingPrivateKey: signing.privateKey, encryptorSubject: "user:alice", encryptorKeyId: "key_alice",
    expectedPayloadVersion: 0, resourceRevision: 4, lifecycleGeneration: 1,
  });
  const metadata = {
    clientId: "avault_web", resource: "credential:slack", slot: "provider_credential", schemaId: "avault.credential.v1",
    payloadVersion: 1, objectDigest: prepared.upload.objectDigest, objectSize: prepared.upload.objectSize,
    keyBindingRef: "organization:acme", wrappedPayloadKey: prepared.upload.wrappedPayloadKey, aadHash: prepared.upload.aadHash,
    resourceRevision: 4, lifecycleGeneration: 1,
  };
  const rewrap = await prepareBrowserResourcePayloadRewrap({
    ...metadata, expectedWrapRevision: 0, previousResourceKey: oldResourceKey, resourceKey: newResourceKey,
    previousResourceKeyVersion: 2, resourceKeyVersion: 3, signingPrivateKey: signing.privateKey,
    rewrapperSubject: "user:alice", rewrapperKeyId: "key_alice",
  });
  assert.notEqual(rewrap.wrappedPayloadKey, prepared.upload.wrappedPayloadKey);
  const decrypted = await decryptBrowserResourcePayload(prepared.ciphertext, {
    ...metadata, wrappedPayloadKey: rewrap.wrappedPayloadKey!,
  }, newResourceKey);
  assert.deepEqual(decrypted, plaintext);
  await assert.rejects(() => decryptBrowserResourcePayload(prepared.ciphertext, {
    ...metadata, wrappedPayloadKey: rewrap.wrappedPayloadKey!,
  }, oldResourceKey));
});
