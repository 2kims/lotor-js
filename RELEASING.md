# Release operations

This repository uses Release Please and npm trusted publishing. Tags, GitHub releases, workflow artifacts, and npm versions are immutable release records; never move or reuse them.

## Security boundaries

`.github/workflows/release-please.yml` denies permissions by default and separates release authority into four jobs:

| Job | Environment | Permissions | Purpose |
| --- | --- | --- | --- |
| `release` | `release-automation` | `contents: read` for `github.token` | Uses the repository's 2K Bot App credentials to create release PRs and releases. |
| `validate` | none | `contents: read` | Verifies the exact tag and `main` ancestry, installs the frozen dependency graph, and runs all SDK and release checks. |
| `package` | none | `contents: read` | Rechecks the exact tag in a fresh runner, builds the SDK, creates one lifecycle-script-disabled tarball, and uploads it by unique artifact ID. |
| `publish` | `npm-publish` | `actions: read`, `id-token: write` | Checks out no source, verifies the exact artifact and package policy independently, rechecks npm state, and publishes through OIDC. |

The GitHub App key and npm OIDC permission never coexist. All four jobs fail closed unless both repository variables equal the exact lowercase value `true`:

- `NPM_TRUSTED_PUBLISHING_READY`
- `RELEASE_AUTOMATION_ENABLED`

Keep both variables absent until the one-time setup is complete.

## One-time setup

1. Create `release-automation` and `npm-publish` GitHub environments. Restrict both to the selected branch `main`.
2. Register the 2K Bot metadata as repository variables:

   ```text
   BOT_2K_APP_ID=4600682
   BOT_2K_CLIENT_ID=Iv23ct8NTwJ8yiM1WYo3
   ```

3. Store the 2K Bot private key as repository secret `BOT_2K_KEY`. The workflow policy permits only the `release` job to reference this secret.
4. Scope the 2K Bot GitHub App installation to this repository with only Contents read/write, Pull requests read/write, and required Metadata read access. It must not bypass branch protection.
5. In npm settings for `@lotor.dev/lotor-js`, configure this trusted publisher exactly:

   ```text
   Owner:       2kims
   Repository:  lotor-js
   Workflow:    release-please.yml
   Environment: npm-publish
   ```

6. Store no secrets in `npm-publish`. Do not configure `NPM_TOKEN` or another token fallback.
7. Protect `main`, require the `Validate PR title` and `Test` checks, enable squash merging and auto-merge, and protect `v*` tags from updates or deletion.
   Keep checkpoint PRs in draft. Once a PR is locally validated and ready for
   review, add the one-shot `ci:run` label. PR checks attempt GitHub-hosted
   runners first and fall back to Blacksmith only if that attempt cannot
   complete successfully. Pushes alone do not run PR CI.
8. Verify the environment, variable, and secret names without printing secret values:

   ```bash
   gh secret list --repo 2kims/lotor-js
   gh variable list --repo 2kims/lotor-js
   gh secret list --repo 2kims/lotor-js --env npm-publish
   gh api repos/2kims/lotor-js/environments/release-automation
   gh api repos/2kims/lotor-js/environments/npm-publish
   npm view @lotor.dev/lotor-js version dist-tags --json
   ```

9. Open the gates in order only after the checks above pass:

   ```bash
   gh variable set NPM_TRUSTED_PUBLISHING_READY --repo 2kims/lotor-js --body true
   gh variable set RELEASE_AUTOMATION_ENABLED --repo 2kims/lotor-js --body true
   ```

Release jobs default to GitHub-hosted runners. If the private-repository minute
allowance is exhausted, first grant the Blacksmith GitHub App access to this
repository, then switch the release pipeline explicitly:

```bash
gh variable set USE_BLACKSMITH --repo 2kims/lotor-js --body true
```

Delete `USE_BLACKSMITH` to restore the GitHub-hosted default. Values other than
the exact lowercase string `true` do not select Blacksmith.

## Normal releases

1. Merge a PR with a conventional squash title.
2. Release Please creates or updates a release PR and enables squash auto-merge.
3. The release PR synchronizes `package.json`, `.release-please-manifest.json`, and `CHANGELOG.md`.
4. Release Please creates the immutable `v<version>` tag and GitHub release.
5. Validation and packaging run against that exact tag.
6. The isolated publisher verifies and publishes the tarball with npm provenance.

Stable versions update `latest`; prereleases update `next`. Publication fails if the exact npm version already exists or the selected dist-tag would not advance.

## Recovery

Recovery is only for an existing non-draft GitHub release whose npm publication did not complete:

```bash
gh workflow run .github/workflows/release-please.yml \
  --repo 2kims/lotor-js \
  --ref main \
  -f tag=v0.1.0
```

Recovery repeats exact-tag validation and publication checks. If npm already contains the version, recovery succeeds as a no-op. Never recover by moving a tag, replacing a release, or manually repacking an artifact.

## Emergency shutdown

Delete the automation gate and cancel active runs:

```bash
gh variable delete RELEASE_AUTOMATION_ENABLED --repo 2kims/lotor-js
```

Also remove `NPM_TRUSTED_PUBLISHING_READY` if npm OIDC configuration is suspect. Restore npm readiness first and release automation last after revalidation.

## Maintenance

- Update action pins and the allowlist in `scripts/verify-workflows.mjs` together.
- Keep package lifecycle scripts forbidden and use `npm pack --ignore-scripts`.
- Update both tarball audits in the release workflow when published files or entry points change.
- Treat moved tags, changed artifact digests, or unexpected npm state as failures to investigate, not checks to bypass.
