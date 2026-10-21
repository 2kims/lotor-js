/** Generic value format emitted inside a selected custody runtime. No provider
 * credentials, account private keys, or passphrases belong in this contract. */
export interface ResourceKeyBinding {
    scope: {
        tenant_id: string;
        application_id: string;
        environment_id: string;
        owner_resource: string;
    };
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
export interface ResourceValueContext {
    binding: ResourceKeyBinding;
    path: string;
}
export interface ResourceValue {
    format: "lotor.resource-value.v1";
    context: ResourceValueContext;
    nonce: string;
    ciphertext: string;
}
/** Recipient-side decryption, not an authorization check or runtime key lease.
 * Derive expected context from the authorized execution/result, not an arbitrary
 * ciphertext's claimed resource. Historical ciphertext remains readable after
 * the invocation expires. The unlocked resource key stays in this process. */
export declare function decryptResourceValue(resourceKey: Uint8Array, value: ResourceValue, expected: ResourceValueContext): Promise<Uint8Array>;
