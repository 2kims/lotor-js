import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemas = await readFile(new URL("../../../docs/openapi-schemas.yaml", import.meta.url), "utf8");

function schemaBlock(name, nextName) {
  const start = schemas.indexOf(`    ${name}:`);
  const end = schemas.indexOf(`    ${nextName}:`, start + 1);
  assert.notEqual(start, -1, `${name} schema is missing`);
  assert.notEqual(end, -1, `${nextName} schema boundary is missing`);
  return schemas.slice(start, end);
}

test("browser E2EE policy wire fields stay aligned with OpenAPI", () => {
  const policy = schemaBlock("OrganizationE2EEPolicyInput", "OrganizationE2EEPolicy");
  assert.match(policy, /required: \[required_account_custody, resource_key_executor, automation_executor, resource_key_policy\]/u);
  for (const field of ["required_account_custody", "resource_key_executor", "automation_executor", "function_binding_id", "resource_key_policy"]) {
    assert.match(policy, new RegExp(`^        ${field}:`, "mu"));
  }
  assert.doesNotMatch(policy, /^        (mode|automation):/mu);
});

test("browser resource decoder states stay aligned with OpenAPI", () => {
  const resource = schemaBlock("CollaborationResource", "SystemResourceCreation");
  assert.match(resource, /required: \[id, resource, resource_type, display_name, status, encryption, revision, lifecycle_generation\]/u);
  assert.match(resource, /status: \{ type: string, enum: \[pending_encryption, pending_payload, pending_encryption_payload, active, disabled, deleting, failed, deleted\] \}/u);
  assert.match(resource, /status: \{ type: string, enum: \[not_required, provisioning, ready, failed\] \}/u);
  assert.match(resource, /key_scope: \{ type: string, enum: \[organization, resource\] \}/u);
});
