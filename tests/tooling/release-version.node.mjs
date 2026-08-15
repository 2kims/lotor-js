import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, test } from "node:test";
import { verifyRootReleaseVersion } from "../../scripts/verify-release-version.mjs";

const tempDirs = [];

function writeVersionFiles(manifest = "1.2.3", packageVersion = "1.2.3") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lotor-js-release-version-"));
  tempDirs.push(directory);
  fs.writeFileSync(path.join(directory, ".release-please-manifest.json"), JSON.stringify({ ".": manifest }));
  fs.writeFileSync(path.join(directory, "package.json"), JSON.stringify({ version: packageVersion }));
  return directory;
}

afterEach(() => {
  for (const directory of tempDirs.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

describe("root release version", () => {
  test("accepts synchronized metadata", () => {
    assert.equal(verifyRootReleaseVersion(writeVersionFiles()), "1.2.3");
    const packageVersion = JSON.parse(fs.readFileSync("package.json", "utf8")).version;
    assert.equal(verifyRootReleaseVersion(process.cwd()), packageVersion);
  });

  test("rejects mismatches and malformed semantic versions", () => {
    assert.throws(() => verifyRootReleaseVersion(writeVersionFiles("1.2.2")), /mismatch/);
    assert.throws(() => verifyRootReleaseVersion(writeVersionFiles("1.2.3", "1.2.3-01")), /valid semantic version|mismatch/);
  });

  test("binds validation to an expected release version", () => {
    const directory = writeVersionFiles();
    assert.equal(verifyRootReleaseVersion(directory, "1.2.3"), "1.2.3");
    assert.throws(() => verifyRootReleaseVersion(directory, "1.2.4"), /expected release version/);
  });
});
