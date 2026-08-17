# Changelog

## Unreleased

## [0.1.1-rc.6](https://github.com/2kims/lotor-js/compare/v0.1.0-rc.6...v0.1.1-rc.6) (2026-08-17)


### Miscellaneous Chores

* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#3](https://github.com/2kims/lotor-js/issues/3)) ([8964b28](https://github.com/2kims/lotor-js/commit/8964b283814483419a9a7a31349be3b3f2310259))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#7](https://github.com/2kims/lotor-js/issues/7)) ([2dc099a](https://github.com/2kims/lotor-js/commit/2dc099aeb473b00b91fe9e19f47a4a1e5e6464a2))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#8](https://github.com/2kims/lotor-js/issues/8)) ([8c2874f](https://github.com/2kims/lotor-js/commit/8c2874fffc38969df8e5e41a28191553b17b7c1b))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#9](https://github.com/2kims/lotor-js/issues/9)) ([0006eee](https://github.com/2kims/lotor-js/commit/0006eee273e83c8756323b9552542f23607a2660))

## 0.1.0-rc.6

- Allow encrypted-resource bootstrap, encrypted link sending, and deferred
  provisioning to use an already-unlocked, active subject device key in
  headless runtimes without requiring a passphrase-backed browser key.

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
