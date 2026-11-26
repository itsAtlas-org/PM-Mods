// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// plan.mjs, publish.mjs, verify-published.mjs's plan check, describe-package.mjs and build-mod.sh's
// input checks. No network and no real gh: publish.mjs is driven with a recording fake, passed in.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { describePackage } from "../scripts/describe-package.mjs";
import { buildIndex, signIndex, validityWindow } from "../scripts/lib/index.mjs";
import { outputsFor, pendingEntries } from "../scripts/plan.mjs";
import { publish } from "../scripts/publish.mjs";
import { planFault, READ_BACK_BUDGET_MS, waitBefore } from "../scripts/verify-published.mjs";
import { ephemeralRing, sha256, unsignedPackage } from "./helpers.mjs";

const dirs = [];
const scratch = () => {
  const d = mkdtempSync(join(tmpdir(), "pm-mods-release-"));
  dirs.push(d);
  return d;
};
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

const SHA = "0123456789abcdef0123456789abcdef01234567";
const REPO = "itsAtlas-org/PM-Mods";

test("plan: pending is what isn't published, and the outputs are two one-line values", async () => {
  const catalogue = [{ id: "a.one", version: "1.0.0" }, { id: "a.one", version: "1.1.0" }, { id: "b.two", version: "2.0.0" }];
  const published = new Set(["a.one-v1.0.0"]);
  const pending = await pendingEntries(catalogue, async (e) => published.has(`${e.id}-v${e.version}`));
  assert.deepEqual(pending.map((e) => e.version), ["1.1.0", "2.0.0"]);
  const out = outputsFor(catalogue, pending);
  assert.equal(out.split("\n").length, 3, "pending= and empty= each on one line");
  assert.match(out, /^pending=\[\{.*\}\]\nempty=false\n$/);
  assert.equal(outputsFor([], []), "pending=[]\nempty=true\n");
});

/** The live index pair at `seq` (a real one, signed by the test ring), or the absence of one for null. */
function liveAt(seq) {
  if (seq === null) return async () => null;
  const { main } = ephemeralRing();
  const built = buildIndex({ ...validityWindow(new Date("2026-12-01T00:00:00Z")), seq, mods: [], blacklist: [] });
  const pair = { json: built.bytes, signature: signIndex(main.key, built.bytes, built.parsed) };
  return async () => pair;
}
const keys = () => ephemeralRing().publicKeys;
const noSleep = async () => {};
/** Publish's inputs for a live index at `liveSeq` (null: none), under the test ring. */
const ctx = (liveSeq = 2) => ({ publicKeys: keys(), sleep: noSleep, live: liveAt(liveSeq) });

/** A folder laid out as sign.mjs writes it, with a fake package and index. */
function signedDir({ fresh = true, seq = 3 } = {}) {
  const dir = scratch();
  const pkg = Buffer.from("signed package bytes");
  const index = Buffer.from('{"index":true}\n');
  writeFileSync(join(dir, "atlas.map-1.1.0.pmmod"), pkg);
  writeFileSync(join(dir, "index.json"), index);
  writeFileSync(join(dir, "index.json.minisig"), "sig");
  const plan = {
    seq,
    expires: "2027-01-01T00:00:00.000Z",
    indexSha256: sha256(index),
    packages: [{ tag: "atlas.map-v1.1.0", asset: "atlas.map-1.1.0.pmmod", fresh, sha256: sha256(pkg) }],
  };
  writeFileSync(join(dir, "plan.json"), JSON.stringify(plan));
  return { dir, pkg, plan };
}

/** A fake gh over a map tag -> asset names; records every call. */
function fakeGh(releases, { viewError } = {}) {
  const calls = [];
  const gh = async (args) => {
    calls.push(args);
    if (args[0] === "release" && args[1] === "view") {
      if (viewError) return { code: 1, stdout: "", stderr: viewError };
      const tag = args[2];
      if (!releases.has(tag)) return { code: 1, stdout: "", stderr: "release not found" };
      return { code: 0, stdout: JSON.stringify({ assets: releases.get(tag).map((name) => ({ name })) }), stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { gh, calls, writes: () => calls.filter((c) => c[1] !== "view") };
}
const never = async () => assert.fail("nothing should have been downloaded");
const quiet = () => {};

test("publish: a first publish creates the package release, then the index release, packages first", async () => {
  const { dir } = signedDir({ seq: 1 });
  const { gh, writes } = fakeGh(new Map());
  await publish({ dir, repo: REPO, sha: SHA, gh, read: never, log: quiet, ...ctx(null) });
  const w = writes();
  assert.equal(w.length, 2);
  assert.deepEqual(w[0].slice(0, 3), ["release", "create", "atlas.map-v1.1.0"]);
  assert.ok(w[0].includes(join(dir, "atlas.map-1.1.0.pmmod")));
  assert.deepEqual(w[1].slice(0, 2), ["release", "create"]);
  assert.equal(w[1][2], "index");
  assert.ok(w[1].includes(join(dir, "index.json")) && w[1].includes(join(dir, "index.json.minisig")));
  for (const c of w) {
    assert.ok(c.includes("--latest=false"));
    assert.equal(c[c.indexOf("--target") + 1], SHA);
    assert.equal(c[c.indexOf("--repo") + 1], REPO);
    assert.ok(!c.includes("--clobber"));
  }
});

test("publish: an existing index release has its assets replaced; a missing package asset is added without --clobber", async () => {
  const { dir } = signedDir();
  const { gh, writes } = fakeGh(new Map([["atlas.map-v1.1.0", []], ["index", ["index.json", "index.json.minisig"]]]));
  await publish({ dir, repo: REPO, sha: SHA, gh, read: never, log: quiet, ...ctx() });
  const [pkg, index] = writes();
  assert.deepEqual(pkg.slice(0, 3), ["release", "upload", "atlas.map-v1.1.0"]);
  assert.ok(!pkg.includes("--clobber"));
  assert.deepEqual(index.slice(0, 3), ["release", "upload", "index"]);
  assert.ok(index.includes("--clobber"));
});

test("publish: a package asset that is already there must be byte-identical, and is never touched", async () => {
  const { dir, pkg } = signedDir();
  const releases = new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]], ["index", ["index.json", "index.json.minisig"]]]);
  const same = fakeGh(releases);
  await publish({ dir, repo: REPO, sha: SHA, gh: same.gh, read: async () => pkg, log: quiet, ...ctx() });
  assert.equal(same.writes().length, 1, "only the index upload");
  assert.equal(same.writes()[0][2], "index");

  const other = fakeGh(releases);
  await assert.rejects(
    publish({ dir, repo: REPO, sha: SHA, gh: other.gh, read: async () => Buffer.from("different"), log: quiet, ...ctx() }),
    /burned/,
  );
  assert.equal(other.writes().length, 0, "nothing was uploaded after the refusal");
  await assert.rejects(publish({ dir, repo: REPO, sha: SHA, gh: fakeGh(releases).gh, read: async () => null, log: quiet, ...ctx() }), /burned/);
});

test("publish: an already-published package is skipped, and only the index goes up", async () => {
  const { dir } = signedDir({ fresh: false });
  const { gh, writes } = fakeGh(new Map([["index", ["index.json", "index.json.minisig"]]]));
  await publish({ dir, repo: REPO, sha: SHA, gh, read: never, log: quiet, ...ctx() });
  assert.equal(writes().length, 1);
});

test("publish: gh failing for any reason but 'not found' stops the run before it writes", async () => {
  const { dir } = signedDir();
  const { gh, writes } = fakeGh(new Map(), { viewError: "HTTP 502: Bad Gateway" });
  await assert.rejects(publish({ dir, repo: REPO, sha: SHA, gh, read: never, log: quiet, ...ctx() }), /failed: HTTP 502/);
  assert.equal(writes().length, 0);
  const failing = async (args) => (args[1] === "view" ? { code: 1, stdout: "", stderr: "release not found" } : { code: 1, stdout: "", stderr: "denied" });
  await assert.rejects(publish({ dir, repo: REPO, sha: SHA, gh: failing, read: never, log: quiet, ...ctx() }), /denied/);
});

test("publish: refuses a plan that doesn't describe the files, and odd names or inputs", async () => {
  const a = signedDir();
  writeFileSync(join(a.dir, "index.json"), "tampered\n");
  await assert.rejects(publish({ dir: a.dir, repo: REPO, sha: SHA, gh: fakeGh(new Map()).gh, read: never, log: quiet, ...ctx() }), /index\.json isn't the one/);
  const b = signedDir();
  writeFileSync(join(b.dir, "atlas.map-1.1.0.pmmod"), "tampered");
  await assert.rejects(publish({ dir: b.dir, repo: REPO, sha: SHA, gh: fakeGh(new Map()).gh, read: never, log: quiet, ...ctx() }), /isn't the one the plan/);
  const c = signedDir();
  const plan = JSON.parse(readFileSync(join(c.dir, "plan.json"), "utf8"));
  plan.packages[0].asset = "../evil.pmmod";
  writeFileSync(join(c.dir, "plan.json"), JSON.stringify(plan));
  await assert.rejects(publish({ dir: c.dir, repo: REPO, sha: SHA, gh: fakeGh(new Map()).gh, read: never, log: quiet, ...ctx() }), /names a release or file it shouldn't/);
  const d = signedDir();
  await assert.rejects(publish({ dir: d.dir, repo: "no-slash", sha: SHA, gh: fakeGh(new Map()).gh, read: never, log: quiet, ...ctx() }), /owner\/repo/);
  await assert.rejects(publish({ dir: d.dir, repo: REPO, sha: "main", gh: fakeGh(new Map()).gh, read: never, log: quiet, ...ctx() }), /commit/);
});

test("publish: the live index must be exactly the seq this run signed on top of, or nothing is replaced", async () => {
  const idx = (gh) => gh.writes().filter((c) => c[2] === "index");
  for (const liveSeq of [null, 1, 3, 4]) {
    const { dir } = signedDir({ seq: 3 });
    const gh = fakeGh(new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]], ["index", ["index.json", "index.json.minisig"]]]));
    await assert.rejects(
      publish({ dir, repo: REPO, sha: SHA, gh: gh.gh, read: async () => Buffer.from("signed package bytes"), log: quiet, ...ctx(liveSeq) }),
      /another publish got there first/,
      `live ${liveSeq}`,
    );
    assert.equal(idx(gh).length, 0, `live ${liveSeq}: the index was left alone`);
  }
  // A live pair that doesn't verify under the pinned keys is not a basis either.
  const { dir } = signedDir({ seq: 3 });
  const gh = fakeGh(new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]], ["index", ["index.json", "index.json.minisig"]]]));
  const bad = { ...ctx(2), live: async () => ({ json: Buffer.from("{}"), signature: Buffer.from("sig") }) };
  await assert.rejects(publish({ dir, repo: REPO, sha: SHA, gh: gh.gh, read: async () => Buffer.from("signed package bytes"), log: quiet, ...bad }), /live index doesn't verify/);
  assert.equal(idx(gh).length, 0);
});

test("publish: the default live read goes through gh (the API), as a pair that verifies", async () => {
  const { dir } = signedDir({ seq: 3 });
  const pair = await liveAt(2)();
  const releases = new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]], ["index", ["index.json", "index.json.minisig"]]]);
  const base = fakeGh(releases);
  const gh = async (args) => {
    if (args[1] === "download") {
      const to = args[args.indexOf("--dir") + 1];
      writeFileSync(join(to, "index.json"), pair.json);
      writeFileSync(join(to, "index.json.minisig"), pair.signature);
      base.calls.push(args);
      return { code: 0, stdout: "", stderr: "" };
    }
    return base.gh(args);
  };
  const { live: _unused, ...rest } = ctx();
  await publish({ dir, repo: REPO, sha: SHA, gh, read: async () => Buffer.from("signed package bytes"), log: quiet, ...rest });
  assert.ok(base.calls.some((c) => c[1] === "download"), "read through gh release download");
  assert.equal(base.writes().filter((c) => c[1] === "upload" && c[2] === "index").length, 1);
});

test("publish: a failed index replacement is retried, and gives up with the recovery pointer", async () => {
  const releases = new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]], ["index", ["index.json", "index.json.minisig"]]]);
  const flaky = (failures) => {
    const base = fakeGh(releases);
    let left = failures;
    const uploads = [];
    const gh = async (args) => {
      if (args[1] === "upload" && args[2] === "index") {
        uploads.push(args);
        if (left-- > 0) return { code: 1, stdout: "", stderr: "HTTP 502: upload interrupted" };
        return { code: 0, stdout: "", stderr: "" };
      }
      return base.gh(args);
    };
    return { gh, uploads };
  };
  const run = (gh) => publish({ dir: signedDir().dir, repo: REPO, sha: SHA, gh, read: async () => Buffer.from("signed package bytes"), log: quiet, ...ctx() });
  const twice = flaky(2);
  await run(twice.gh);
  assert.equal(twice.uploads.length, 3, "two failures, then it went through");
  assert.ok(twice.uploads.every((u) => u.includes("--clobber")));
  const never = flaky(99);
  await assert.rejects(run(never.gh), /could not be written after 3 attempts[\s\S]*incomplete[\s\S]*signed-index/);
  assert.equal(never.uploads.length, 3);
});

test("publish: a first index release that failed half-way is finished by uploading, not by creating again", async () => {
  // The first attempt's `release create` fails after the release exists (gh creates, then uploads assets).
  const releases = new Map([["atlas.map-v1.1.0", ["atlas.map-1.1.0.pmmod"]]]);
  const base = fakeGh(releases);
  const calls = [];
  const gh = async (args) => {
    if (args[0] === "release" && args[1] === "create" && args[2] === "index") {
      calls.push(args[1]);
      releases.set("index", []);
      return { code: 1, stdout: "", stderr: "asset upload failed" };
    }
    if (args[1] === "upload" && args[2] === "index") calls.push(args[1]);
    return base.gh(args);
  };
  await publish({ dir: signedDir({ seq: 1 }).dir, repo: REPO, sha: SHA, gh, read: async () => Buffer.from("signed package bytes"), log: quiet, ...ctx(null) });
  assert.deepEqual(calls, ["create", "upload"]);
});

test("verify-published --plan: the live index must be the one just uploaded", () => {
  const plan = { seq: 3, indexSha256: "a".repeat(64) };
  assert.equal(planFault({ seq: 3, indexSha256: "a".repeat(64) }, plan), null);
  assert.match(planFault({ seq: 2, indexSha256: "a".repeat(64) }, plan), /seq 2/);
  assert.match(planFault({ seq: 3, indexSha256: "b".repeat(64) }, plan), /isn't the one that was just uploaded/);
});

test("describe-package lists each file's size and sha256 in archive order", () => {
  const rows = describePackage(unsignedPackage());
  assert.deepEqual(rows.map((r) => r[0]), ["LICENCE.txt", "NOTICE.txt", "app/index.html", "manifest.json", "pmmod/checksums.json"]);
  for (const [, size, hash] of rows) assert.ok(size > 0 && /^[0-9a-f]{64}$/.test(hash));
});

test("build-mod.sh refuses malformed input before it builds anything", () => {
  const script = fileURLToPath(new URL("../scripts/build-mod.sh", import.meta.url));
  const good = {
    MOD_ID: "atlas.map",
    MOD_VERSION: "1.1.0",
    MOD_PATH: "mods/atlas.map",
    MOD_COMMIT: SHA,
    MOD_SHA256: "a".repeat(64),
  };
  const cwd = scratch(); // no ./tools and no ./src here: a good input stops at the layout check
  mkdirSync(cwd, { recursive: true });
  const run = (over) => spawnSync("sh", [script], { cwd, env: { PATH: process.env.PATH, ...good, ...over }, encoding: "utf8" });
  assert.match(run({}).stderr, /no \.\/tools checkout/);
  for (const [over, why] of [
    [{ MOD_ID: "../x" }, /MOD_ID/],
    [{ MOD_ID: "a b" }, /MOD_ID/],
    [{ MOD_VERSION: "1.0.0;rm" }, /MOD_VERSION/],
    [{ MOD_PATH: "/etc" }, /MOD_PATH/],
    [{ MOD_PATH: "mods/../x" }, /MOD_PATH/],
    [{ MOD_PATH: "mods/a b" }, /MOD_PATH/],
    [{ MOD_COMMIT: "main" }, /MOD_COMMIT/],
    [{ MOD_COMMIT: SHA.slice(1) }, /40 hex/],
    [{ MOD_SHA256: "A".repeat(64) }, /MOD_SHA256/],
    [{ MOD_SHA256: "a".repeat(63) }, /64 hex/],
    [{ MOD_SHA256: "" }, /MOD_SHA256/],
  ]) {
    const r = run(over);
    assert.notEqual(r.status, 0, JSON.stringify(over));
    assert.match(r.stderr, why, JSON.stringify(over));
  }
});

test("verify-published --plan waits long enough for a new release asset to be served", () => {
  // 1.0.1 and 1.0.2 both saw the new .pmmod's download URL answer 404 for over a minute after a good
  // upload. The read-back keeps trying for 10 minutes, starting at 10 s and never waiting over a minute.
  assert.equal(READ_BACK_BUDGET_MS, 10 * 60_000);
  assert.equal(waitBefore(1), 10_000);
  let total = 0;
  let tries = 1;
  for (let attempt = 1; total + waitBefore(attempt) <= READ_BACK_BUDGET_MS; attempt++) {
    assert.ok(waitBefore(attempt) <= 60_000, `wait ${attempt}`);
    assert.ok(waitBefore(attempt) >= waitBefore(Math.max(1, attempt - 1)), `never shorter ${attempt}`);
    total += waitBefore(attempt);
    tries += 1;
  }
  assert.ok(total >= 9 * 60_000, `waits ${total} ms in all`);
  assert.ok(tries >= 12, `${tries} tries`);
});
