# Changelog

## Unreleased

- Add browser-user provider execution preflight/commit, browser-only request
  protection and response opening helpers, and canonical query construction.
  Same-origin gateways retain the 30-second execution capability in a scoped
  HttpOnly cookie; application backends never receive E2EE plaintext.

## [0.2.2-rc.1](https://github.com/2kims/lotor-js/compare/v0.2.1-rc.1...v0.2.2-rc.1) (2026-09-09)


### Miscellaneous Chores

* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#19](https://github.com/2kims/lotor-js/issues/19)) ([7b91f93](https://github.com/2kims/lotor-js/commit/7b91f93709c6dbd0a84306739f2f9a50ebbacdeb))

## [0.2.1-rc.1](https://github.com/2kims/lotor-js/compare/v0.2.0-rc.1...v0.2.1-rc.1) (2026-09-08)

### Miscellaneous Chores

* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([9634657](https://github.com/2kims/lotor-js/commit/9634657ae10c48d61ae8cfe307a61cd545e6abfd))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#11](https://github.com/2kims/lotor-js/issues/11)) ([17cc8b4](https://github.com/2kims/lotor-js/commit/17cc8b42a9ad8518c47e6e7a1d1c99e9e0e3e4b4))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#13](https://github.com/2kims/lotor-js/issues/13)) ([a300084](https://github.com/2kims/lotor-js/commit/a3000849aed2ed1ab47ac16d61b55623072d04d9))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#17](https://github.com/2kims/lotor-js/issues/17)) ([bcdbfdd](https://github.com/2kims/lotor-js/commit/bcdbfdd64b551b0c934e0165ebb991a7e5ec2b45))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#3](https://github.com/2kims/lotor-js/issues/3)) ([8964b28](https://github.com/2kims/lotor-js/commit/8964b283814483419a9a7a31349be3b3f2310259))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#7](https://github.com/2kims/lotor-js/issues/7)) ([2dc099a](https://github.com/2kims/lotor-js/commit/2dc099aeb473b00b91fe9e19f47a4a1e5e6464a2))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#8](https://github.com/2kims/lotor-js/issues/8)) ([8c2874f](https://github.com/2kims/lotor-js/commit/8c2874fffc38969df8e5e41a28191553b17b7c1b))
* sync [@lotor](https://github.com/lotor).dev/lotor-js public export ([#9](https://github.com/2kims/lotor-js/issues/9)) ([0006eee](https://github.com/2kims/lotor-js/commit/0006eee273e83c8756323b9552542f23607a2660))

### 0.2.0-rc.1 candidate (not published)

- Breaking: require canonical resource references in account directories,
  invitation resources and catalog bindings. Missing references are rejected,
  not reconstructed from IDs. Deploy the matching Control API before adoption.
- Add member-facing parent-filtered directories and published Catalog discovery
  and binding, including generic Catalog entry types.
- Add resource credential issue/list/rotate/revoke and organization billing
  portal methods with ordinary user transport and no application secrets.
- Align generic graph discovery with the OpenAPI service-account principal and
  `active_access` key-activation contracts; reject undersized candidate queries
  before transport.
- Normalize resource guest-policy input to public camelCase while preserving the
  OpenAPI wire contract and validating restrictions before transport.
- Add typed system-resource creation and bounded, cancellable pagination and
  durable-operation helpers. Pending encryption is not reported as ready.
- Preserve account principal identity and effective resource-key metadata.
- Add bounded, cancellable payload downloads with size/SHA-256 verification;
  keep decryption explicit and reject credential-bearing storage upload headers.
- Customer-organization SSO/SCIM runtime support is not included in this candidate.

## 0.1.1-rc.7 (2026-08-31)

- Add cookie-only `same-origin` gateway mode using relative reserved paths,
  same-origin credentials, and double-submit CSRF proof without bearer storage.
- Add `sendResourceLinks`, which lets authoritative preflight policy decide
  whether E2EE material is needed and supports separate keys for manifests
  spanning multiple key resources.
- Align organization E2EE policy and asynchronous resource-state types with the
  OpenAPI contract, and add browser helpers for managed sessions and resumable
  browser resource-key actions.

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
