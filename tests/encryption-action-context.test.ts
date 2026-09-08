import assert from "node:assert/strict";
import test from "node:test";
import { encryptionActions } from "../src/decode.js";

function action(associatedData: unknown) {
  return { actions: [{ id: "rkj_context", kind: "resource_key_create", resource: "vault:one",
    status: "awaiting_browser", revision: "a".repeat(64), key_requirements: [{
      manifest_item_id: "grant_one", grant_id: "grant_one", resource: "vault:one", relation: "owner",
      key_resource: "vault:one", key_version: "1", recipient_subject: "user:alice", recipient_key_id: "alice_key",
      encryption_algorithm: "X25519", public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      associated_data: associatedData,
    }] }] };
}

test("action context preserves exact bytes including revision delimiters", () => {
  const context = new TextEncoder().encode([
    "lotor-resource-envelope-v1", "tenant", "app", "sandbox", "vault:one", "1",
    "user:alice", "alice_key", "1", "2", "3", "4", "5",
  ].join("\0"));
  const result = encryptionActions(action(Buffer.from(context).toString("base64url")));
  assert.deepEqual(result[0]?.keyRequirements[0]?.associatedData, context);
});

test("action context rejects missing or malformed data instead of reconstructing it", () => {
  for (const invalid of [undefined, null, 0, [], "", "YQ==", " YQ", "Y+Q", "Y/Q", "a"]) {
    assert.throws(() => encryptionActions(action(invalid)), `accepted ${JSON.stringify(invalid)}`);
  }
});
