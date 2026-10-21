import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { decryptResourceValue, type ResourceValue, type ResourceValueContext } from "../src/index.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/resource-value-v1.json", import.meta.url), "utf8")) as { key: string; plaintext: string; value: ResourceValue };
const key = () => Uint8Array.from(Buffer.from(fixture.key, "base64url"));

test("decrypts the Go/Node AES-GCM vector with local resource key only, including after invocation expiry", async () => {
  const original = key();
  const plain = await decryptResourceValue(original, fixture.value, fixture.value.context);
  assert.equal(new TextDecoder().decode(plain), fixture.plaintext);
  assert.deepEqual(original, key());
});

test("rejects substitution of every authenticated context component", async () => {
  for (const field of Object.keys(fixture.value.context.binding)) {
    const expected = structuredClone(fixture.value.context);
    const binding = expected.binding as unknown as Record<string, unknown>;
    if (field === "scope") expected.binding.scope.environment_id = "foreign";
    else if (typeof binding[field] === "number") binding[field] = Number(binding[field]) + 1;
    else binding[field] = `${String(binding[field])}-changed`;
    await assert.rejects(decryptResourceValue(key(), fixture.value, expected), /Invalid encrypted resource value/, field);
    await assert.rejects(decryptResourceValue(key(), { ...fixture.value, context: expected }, expected), /Invalid encrypted resource value/, field);
  }
  const expected = { ...fixture.value.context, path: "users.password" };
  await assert.rejects(decryptResourceValue(key(), fixture.value, expected));
  await assert.rejects(decryptResourceValue(key(), { ...fixture.value, context: expected }, expected));
});

test("fails closed for wrong keys, ciphertext, malformed metadata and non-canonical base64", async () => {
  await assert.rejects(decryptResourceValue(new Uint8Array(32).fill(8), fixture.value, fixture.value.context));
  await assert.rejects(decryptResourceValue(key(), { ...fixture.value, ciphertext: "AAAA" }, fixture.value.context));
  await assert.rejects(decryptResourceValue(key(), { ...fixture.value, nonce: `${fixture.value.nonce}=` }, fixture.value.context));
  for (const inserted of ["\r", "\n", "\r\n", " ", "\t", "="]) {
    const ciphertext = fixture.value.ciphertext.slice(0, 4) + inserted + fixture.value.ciphertext.slice(4);
    await assert.rejects(decryptResourceValue(key(), { ...fixture.value, ciphertext }, fixture.value.context));
  }
  const unknown = { ...fixture.value.context, unexpected: true } as ResourceValueContext;
  await assert.rejects(decryptResourceValue(key(), fixture.value, unknown));
  const unsafe = structuredClone(fixture.value.context);
  unsafe.binding.key_version = Number.MAX_SAFE_INTEGER + 1;
  await assert.rejects(decryptResourceValue(key(), { ...fixture.value, context: unsafe }, unsafe));
  const surrogate = structuredClone(fixture.value.context);
  surrogate.path = "\ud800";
  await assert.rejects(decryptResourceValue(key(), { ...fixture.value, context: surrogate }, surrogate));
});
