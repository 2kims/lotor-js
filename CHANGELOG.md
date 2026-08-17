# Changelog

## Unreleased

## 0.1.0-rc.5

- Add headless encrypted-resource bootstrap using an application-provided symmetric key.
- Add an encrypted link workflow that performs preflight, wraps the application key for Lotor-owned recipient keys, signs the envelopes, and sends the links without exposing plaintext key material to Lotor.
- Add post-enrollment provisioning jobs and atomic envelope commit so encrypted invitations to newly created users can become active after they register a device key.

## 0.1.0-rc.4

- Add resource collaborator listing, exact managed link identity, invitation acceptance, and collaborator mutation methods.
- Add generic link preflight/send orchestration with Lotor-owned recipient keys and source resource envelopes.
- Add resource registration, account resource discovery, bidirectional resource search, and cascading collaborator removal.
- Add encrypted-resource bootstrap methods for resource-key versions and owner grants.

All notable public API and compatibility changes are documented here. This
project follows Semantic Versioning; breaking changes during `0.x` releases are
called out explicitly.

## 0.1.0-rc.3

- Add client-owned X25519/Ed25519 device enrollment with passphrase-protected
  opaque backup and cross-device recovery.
- Add encrypted resource member aggregation, signed envelope provisioning,
  recipient-only envelope reads, and encrypted invitation acceptance.
- Expose published key-access policy and enrollment state through the public
  application client.

## 0.1.0-rc.2

- Keep the npm package page intentionally free of repository README content.

## 0.1.0-rc.1

- Add the ESM-only `@lotor.dev/lotor-js` package.
- Add direct public application configuration and pricing reads.
- Add passwordless authentication with explicit, non-persistent token storage.
- Add authenticated session, organization, logout, hosted checkout, and custom
  checkout operations.
- License the public distribution under Apache-2.0.
