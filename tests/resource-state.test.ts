import assert from "node:assert/strict";
import test from "node:test";
import { LotorBrowserClient } from "../src/index.js";

test("browser resource reads preserve global principal and canonical binding without inventing defaults", async () => {
  const wire = { id: "row", resource: "service_account:worker", principal_subject: "resource_principal:global", resource_type: "service_account", display_name: "Worker", status: "active", revision: 2, lifecycle_generation: 1,
    encryption: { required: true, status: "ready", key_scope: "organization", effective_key_resource: "organization:acme", key_resource: "organization:acme", key_version: 3 },
    catalog_binding: { resource: "service_account:worker", catalog_id: "cat", snapshot_id: "snap", snapshot_digest: "digest", entry_kinds: ["api.operation"], resource_revision: 2 },
  };
  let response: unknown = wire;
  const client = new LotorBrowserClient({ mode: "same-origin", clientId: "app", publishableKey: "pk_test", fetch: async () => Response.json(response) });
  const resource = await client.resource(wire.resource);
  assert.equal(resource.principalSubject, "resource_principal:global");
  assert.notEqual(resource.principalSubject, resource.resource);
  assert.equal(resource.catalogBinding?.resource, resource.resource);
  assert.equal(resource.encryption.keyVersion, 3);
  response = { ...wire, principal_subject: undefined, catalog_binding: undefined, encryption: { required: false, status: "not_required" } };
  const plain = await client.resource(wire.resource);
  assert.equal(plain.principalSubject, undefined);
  assert.equal(plain.catalogBinding, undefined);
  assert.equal(plain.encryption.keyVersion, undefined);
  response = { ...wire, catalog_binding: { ...wire.catalog_binding, resource: undefined } };
  await assert.rejects(client.resource(wire.resource), /binding resource/);
});
