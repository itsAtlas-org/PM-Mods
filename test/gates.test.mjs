// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { findUses, spdxProblems, trackedFileProblems, usesProblems, workflowProblems } from "../scripts/lib/gates.mjs";

const read = (f) => readFileSync(fileURLToPath(new URL(`../${f}`, import.meta.url)), "utf8");
const publish = read(".github/workflows/publish.yml");
const dryRun = read(".github/workflows/dry-run.yml");

/** Replace `from` (must be present, once) by `to` and return the problems the gate then reports. */
const mutated = (file, text, from, to) => {
  assert.equal(text.split(from).length - 1, 1, `${JSON.stringify(from)} must occur exactly once in ${file}`);
  return workflowProblems(file, text.replace(from, to)).join("\n");
};

test("the shipped workflows pass their own gates", () => {
  assert.deepEqual(workflowProblems("publish.yml", publish), []);
  assert.deepEqual(workflowProblems("dry-run.yml", dryRun), []);
});

test("the pin reader finds every uses: and holds each to a SHA plus a comment", () => {
  const uses = [...findUses(publish), ...findUses(dryRun)];
  assert.ok(uses.length >= 10, `found only ${uses.length}`);
  for (const u of uses) assert.deepEqual(usesProblems(u), [], u.ref);
  const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1";
  assert.match(usesProblems({ ref: "actions/checkout@v4", comment: "# v4" })[0], /tag or branch/);
  assert.match(usesProblems({ ref: `actions/checkout@${sha}`, comment: "" })[0], /comment/);
  assert.match(usesProblems({ ref: "actions/checkout", comment: "# v4" })[0], /no version/);
  assert.match(usesProblems({ ref: `actions/checkout@${sha.slice(1)}`, comment: "# v7" })[0], /tag or branch/);
  assert.deepEqual(usesProblems({ ref: "docker://alpine@sha256:abc", comment: "" }), []);
  assert.match(usesProblems({ ref: "docker://alpine:3", comment: "" })[0], /digest/);
  assert.deepEqual(usesProblems({ ref: "./.github/actions/x", comment: "" }), []);
  // The scanner reads a YAML key, not prose that mentions one.
  assert.deepEqual(findUses("name: the step `uses: foo/bar@v1` is described here\n"), []);
});

const PUBLISH_ENV = "        env:\n          GH_TOKEN: ${{ github.token }}\n        run: node scripts/publish.mjs signed";
const LIVE_ENV = "        env:\n          GH_TOKEN: ${{ github.token }}\n        run: node scripts/live-index.mjs";
const SIGN_USES = "      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2";
const cases = [
  ["a tag instead of a SHA", "publish.yml", publish, "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0", "actions/setup-node@v7", /tag or branch/],
  ["a pin without its version comment", "dry-run.yml", dryRun, "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0", "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", /comment/],
  ["pull_request_target", "dry-run.yml", dryRun, "on:\n  pull_request:\n", "on:\n  pull_request:\n  pull_request_target:\n", /never used here|triggers are/],
  ["workflow_run", "publish.yml", publish, "  workflow_dispatch:\n    inputs:", "  workflow_run:\n  workflow_dispatch:\n    inputs:", /never used here/],
  ["a secret in the dry run", "dry-run.yml", dryRun, "          BASE_SHA: ${{ github.event.pull_request.base.sha }}", "          BASE_SHA: ${{ github.event.pull_request.base.sha }}\n          X: ${{ secrets.ATLAS_MOD_SIGNING_KEY }}", /secrets are referenced only/],
  ["secrets: inherit", "dry-run.yml", dryRun, "    name: Tests and gates\n", "    name: Tests and gates\n    secrets: inherit\n", /secrets are referenced only/],
  ["a third secret in publish.yml", "publish.yml", publish, PUBLISH_ENV, PUBLISH_ENV.replace("${{ github.token }}", "${{ secrets.OTHER }}"), /secrets are referenced only/],
  ["the key in the publish step", "publish.yml", publish, PUBLISH_ENV, PUBLISH_ENV.replace("GH_TOKEN: ${{ github.token }}", "K: ${{ secrets.ATLAS_MOD_SIGNING_KEY }}"), /secrets are referenced only/],
  ["the key in the live-index step", "publish.yml", publish, LIVE_ENV, LIVE_ENV.replace("GH_TOKEN: ${{ github.token }}", "K: ${{ secrets.ATLAS_MOD_SIGNING_KEY_PASSWORD }}"), /secrets are referenced only/],
  ["build artifacts extracted into the checkout", "publish.yml", publish, "path: ${{ runner.temp }}/unsigned", "path: unsigned", /extract under \$\{\{ runner.temp \}\}/],
  ["a download-artifact with no path", "publish.yml", publish, "          path: ${{ runner.temp }}/unsigned\n", "", /extract under/],
  ["another action in the sign job (upload-artifact is the one allowed)", "publish.yml", publish, SIGN_USES, `${SIGN_USES}\n      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0`, /may use only/],
  ["the key in the build job", "publish.yml", publish, "          MOD_ID: ${{ matrix.id }}", "          MOD_ID: ${{ matrix.id }}\n          K: ${{ secrets.ATLAS_MOD_SIGNING_KEY }}", /secrets are referenced only/],
  ["an environment on the build job", "publish.yml", publish, "    # No secret exists in this job, and the token cannot write. It runs code from the pinned source commit.\n", "    environment: mod-signing\n", /only the sign job has an environment/],
  ["an environment in the dry run", "dry-run.yml", dryRun, "  rebuild:\n    name: Rebuild ${{ matrix.id }} ${{ matrix.version }}\n", "  rebuild:\n    name: Rebuild ${{ matrix.id }} ${{ matrix.version }}\n    environment: mod-signing\n", /only the sign job has an environment/],
  ["another environment on the sign job", "publish.yml", publish, "environment: mod-signing", "environment: production", /only the sign job has an environment/],
  ["a write permission on the build job", "publish.yml", publish, "    # No secret exists in this job, and the token cannot write. It runs code from the pinned source commit.\n    permissions:\n      contents: read\n", "    permissions:\n      contents: write\n", /only the sign job may have a write/],
  ["a write permission in the dry run", "dry-run.yml", dryRun, "  zizmor:\n    name: Workflow audit\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n", "  zizmor:\n    name: Workflow audit\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      pull-requests: write\n", /only the sign job may have a write/],
  ["no top-level permissions: {}", "publish.yml", publish, "\npermissions: {}\n", "\npermissions:\n  contents: read\n", /permissions must be/],
  ["a job without its own permissions", "dry-run.yml", dryRun, "    name: Workflow audit\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n", "    name: Workflow audit\n    runs-on: ubuntu-24.04\n", /no permissions block/],
  ["a -latest runner", "dry-run.yml", dryRun, "  zizmor:\n    name: Workflow audit\n    runs-on: ubuntu-24.04", "  zizmor:\n    name: Workflow audit\n    runs-on: ubuntu-latest", /pinned, not -latest/],
  ["an expression inside a run block", "publish.yml", publish, "        run: node scripts/publish.mjs signed", "        run: node scripts/publish.mjs ${{ github.event.head_commit.message }}", /no \$\{\{ \}\} in a run/],
  ["an expression inside a one-line run", "dry-run.yml", dryRun, "        run: pip install zizmor==1.26.1", "        run: pip install ${{ github.head_ref }}", /no \$\{\{ \}\} in a run/],
  ["an expression inside a multi-line run", "publish.yml", publish, '            node scripts/sign.mjs --key-check-only', '            node scripts/sign.mjs --key-check-only ${{ inputs.key_check_only }}', /no \$\{\{ \}\} in a run/],
  ["npm in the sign job", "publish.yml", publish, "        run: node --version && gh --version", "        run: npm ci && node --version", /runs no npm/],
  ["the source checkout in the sign job", "publish.yml", publish, "        run: node scripts/publish.mjs signed", "        run: node src/scripts/pack-mod.mjs", /runs no npm/],
  ["setup-node in the sign job", "publish.yml", publish, SIGN_USES, `${SIGN_USES}\n      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0`, /may use only/],
  ["a repository checkout in the sign job", "publish.yml", publish, "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n      # Outside the checkout", "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          repository: acme/other\n          persist-credentials: false\n      # Outside the checkout", /this repo only/],
  ["a checkout that keeps its credentials", "dry-run.yml", dryRun, "          fetch-depth: 0\n          persist-credentials: false", "          fetch-depth: 0", /persist-credentials/],
  ["a sign job with no main-tip check", "publish.yml", publish, "      - name: Refuse a commit that is not the tip of main\n", "      - name: Something else\n", /must have the step "Refuse a commit/],
  ["a main-tip check that never compares", "publish.yml", publish, '          if [ "$tip" != "$RUN_SHA" ]; then', '          if [ "$tip" = "" ]; then', /must compare github\.sha/],
  ["a main-tip check against another ref", "publish.yml", publish, "git/ref/heads/main", "git/ref/heads/dev", /must compare github\.sha/],
  ["a main-tip check that is conditional", "publish.yml", publish, "      - name: Refuse a commit that is not the tip of main\n", "      - name: Refuse a commit that is not the tip of main\n        if: ${{ !inputs.key_check_only }}\n", /unconditional/],
  ["a main-tip check that may fail quietly", "publish.yml", publish, "      - name: Refuse a commit that is not the tip of main\n", "      - name: Refuse a commit that is not the tip of main\n        continue-on-error: true\n", /unconditional/],
  ["the signed-index upload without overwrite", "publish.yml", publish, "          overwrite: true\n", "", /must set overwrite: true/],
  ["an unnamed upload in the sign job", "publish.yml", publish, "      - name: Keep the signed index pair\n        uses:", "      - uses:", /must be named/],
  ["a different trigger set", "publish.yml", publish, "  schedule:\n    - cron:", "  pull_request:\n  schedule:\n    - cron:", /triggers are/],
  ["a job without a name", "publish.yml", publish, "    name: Plan\n", "", /has no name/],
];
for (const [what, file, text, from, to, expected] of cases) {
  test(`the workflow gate refuses ${what}`, () => assert.match(mutated(file, text, from, to), expected));
}

test("the main-tip check comes before the signing step", () => {
  const text = publish.replace(/      - name: Refuse a commit[\s\S]*?(?=      # The only step with the secrets)/, "");
  const tip = publish.match(/      - name: Refuse a commit[\s\S]*?(?=      # The only step with the secrets)/)[0];
  const moved = text.replace(/(      - uses: actions\/upload-artifact@[\s\S]*?)(?=\n      - name: Create the releases)/, `$1\n${tip.trimEnd()}`);
  assert.match(workflowProblems("publish.yml", moved).join("\n"), /must come before/);
});

test("an unknown workflow file is refused until its triggers are declared", () => {
  assert.match(workflowProblems("other.yml", dryRun).join("\n"), /unknown workflow/);
});

test("tracked-file gate: keys, packages, loose signatures, dependencies and build output", () => {
  assert.deepEqual(trackedFileProblems(["README.md", "scripts/sign.mjs", "test/vectors/throwaway-index.json.minisig", "catalogue.json"]), []);
  for (const f of ["atlas.key", "x/signing.pem", "a.pmmod", "index.json.minisig", "package.json", "sub/package-lock.json", "node_modules/x/y.js", "signed/index.json", "out/a.pmmod", "recovered/index.json"]) {
    assert.equal(trackedFileProblems([f]).length, 1, f);
  }
});

test("SPDX gate: scripts, workflows and docs need the header; data files and vectors don't", () => {
  const header = "// SPDX-FileCopyrightText: 2026 Bobby Yu\n// SPDX-License-Identifier: AGPL-3.0-or-later\n";
  const files = new Map([
    ["a.mjs", `${header}x`],
    ["b.sh", "#!/bin/sh\n# SPDX-FileCopyrightText: 2026 Bobby Yu\n# SPDX-License-Identifier: AGPL-3.0-or-later\n"],
    ["c.mjs", "export {};\n"],
    ["d.yml", "# SPDX-FileCopyrightText: 2026 Bobby Yu\n"],
    ["e.json", "{}"],
    [".gitignore", "x\n"],
    ["f.md", "<!--\nSPDX-FileCopyrightText: 2026 Bobby Yu\nSPDX-License-Identifier: AGPL-3.0-or-later\n-->\n"],
  ]);
  const problems = spdxProblems([...files.keys()], (f) => files.get(f));
  assert.deepEqual(problems.map((p) => p.split(":")[0]).sort(), [".gitignore", "c.mjs", "d.yml"]);
});
