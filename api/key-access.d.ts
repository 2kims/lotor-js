export declare function decodeBase64url(value: string): Uint8Array;
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
export declare function createSubjectKeyRegistration(input: CreateSubjectKeyRegistrationInput): Promise<{
    request: SubjectKeyRegistrationRequest;
    keys: DeviceKeyMaterial;
}>;
export declare function unlockSubjectKeyBackup(record: SubjectKeyRecord, passphrase: string): Promise<DeviceKeyMaterial>;
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
export declare function createResourceEnvelope(input: CreateResourceEnvelopeInput): Promise<ResourceEnvelopeRequest>;
export interface EncryptedResourceEnvelope extends ResourceProvisioningMember {
    encryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM";
    ciphertext: Uint8Array;
    aadHash: Uint8Array;
    issuer: string;
    issuerKeyId: string;
    signature: Uint8Array;
}
export declare function unwrapResourceEnvelope(clientId: string, envelope: EncryptedResourceEnvelope, privateKey: CryptoKey): Promise<Uint8Array>;
