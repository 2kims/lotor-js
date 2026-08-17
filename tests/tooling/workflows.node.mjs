import assert from "node:assert/strict";
import * as fs from "node:fs";
import { describe, test } from "node:test";
import { verifyWorkflowSources } from "../../scripts/verify-workflows.mjs";

const pullRequest = fs.readFileSync(".github/workflows/pull-request.yml", "utf8");
const release = fs.readFileSync(".github/workflows/release.yml", "utf8");
const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));

function sources(overrides = {}) {
  const nextPullRequest = overrides.pullRequest ?? pullRequest;
  const nextRelease = overrides.release ?? release;
  return {
    pullRequest: nextPullRequest,
    release: nextRelease,
    packageJson: overrides.packageJson ?? packageJson,
    allWorkflows: overrides.allWorkflows ?? [
      ["pull-request.yml", nextPullRequest],
      ["release.yml", nextRelease],
    ],
  };
}

function replaceOnce(source, before, after) {
  assert.equal(source.split(before).length - 1, 1, `fixture must contain one ${before}`);
  return source.replace(before, after);
}

describe("release workflow trust boundaries", () => {
  test("accepts checked-in workflows", () => {
    assert.doesNotThrow(() => verifyWorkflowSources(sources()));
  });

  test("rejects mutable actions and weakened gates", () => {
    assert.throws(() => verifyWorkflowSources(sources({
      pullRequest: pullRequest.replace("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "actions/checkout@v7"),
    })), /not pinned/);
    assert.throws(() => verifyWorkflowSources(sources({
      release: release.replace("vars.NPM_TRUSTED_PUBLISHING_READY == 'true' && ", ""),
    })), /every release job must use gate/);
    assert.throws(() => verifyWorkflowSources(sources({
      release: release.replace("runs-on: ${{ vars.USE_BLACKSMITH == 'true' && 'blacksmith-2vcpu-ubuntu-2404' || 'ubuntu-latest' }}", "runs-on: unreviewed-runner"),
    })), /release automation, validation, and packaging must default to GitHub/);
  });

  test("rejects source checkout or secrets in the OIDC publisher", () => {
    assert.throws(() => verifyWorkflowSources(sources({
      release: replaceOnce(release, "      - name: Set up Node.js for trusted publishing", "      - name: Check out source\n        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n\n      - name: Set up Node.js for trusted publishing"),
    })), /must not check out/);
    assert.throws(() => verifyWorkflowSources(sources({
      release: replaceOnce(release, "          DOWNLOAD_STEP_PATH: ${{ steps.download.outputs.download_path }}", "          DOWNLOAD_STEP_PATH: ${{ steps.download.outputs.download_path }}\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"),
    })), /only release automation may reference one secret|must not reference secrets/);
    assert.throws(() => verifyWorkflowSources(sources({
      release: replaceOnce(release, "    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    permissions:\n      actions: read", "    runs-on: blacksmith-2vcpu-ubuntu-2404\n    timeout-minutes: 10\n    permissions:\n      actions: read"),
    })), /must use a GitHub-hosted runner/);
  });

  test("rejects an unreviewed workflow", () => {
    assert.throws(() => verifyWorkflowSources(sources({
      allWorkflows: [["pull-request.yml", pullRequest], ["release.yml", release], ["extra.yml", "name: Extra\n"]],
    })), /only reviewed/);
  });
});
