// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { signMain } from "../scripts/sign.mjs";
import { serializeCatalogue } from "../scripts/lib/catalogue.mjs";
import { verifyPublished } from "../scripts/lib/published.mjs";
import { NO_INDEX_MARKER } from "../scripts/lib/live.mjs";
import { packageAsset, packageUrl } from "../scripts/lib/rules.mjs";
import { entryFor, ephemeralRing, manifestOf, unsignedPackage } from "./helpers.mjs";

const scripts = fileURLToPath(new URL("../scripts/", import.meta.url));
const dirs = [];
const scratch = () => {
  const d = mkdtempSync(join(tmpdir(), "pm-mods-test-"));
  dirs.push(d);
  return d;
};
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

function fixture() {
  const { main, publicKeys } = ephemeralRing();
  const root = scratch();
  const manifest = manifestOf();
  const bytes = unsignedPackage({ manifest });
  const entry = entryFor(bytes, manifest);
  writeFileSync(join(root, "catalogue.json"), serializeCatalogue([entry]));
  writeFileSync(join(root, "blacklist.json"), '{"format":1,"entries":[]}\n');
  const unsigned = join(root, "unsigned");
  mkdirSync(unsigned);
  writeFileSync(join(unsigned, `${entry.id}-${entry.version}.unsigned.pmmod`), bytes);
  const env = { ATLAS_MOD_SIGNING_KEY: main.generated.secretBase64, ATLAS_MOD_SIGNING_KEY_PASSWORD: "test-password" };
  /** The folder scripts/live-index.mjs leaves: the first-publish marker, or a pair. */
  const live = join(root, "live");
  mkdirSync(live);
  writeFileSync(join(live, NO_INDEX_MARKER), "");
  return { root, unsigned, entry, env, publicKeys, bytes, live };
}

test("sign.mjs --key-check-only: the pinned main key decrypts and signs, nothing is written", async () => {
  const f = fixture();
  const logged = [];
  await signMain(["--key-check-only"], { env: f.env, publicKeys: f.publicKeys, log: (m) => logged.push(m) });
  assert.deepEqual(logged, [`key OK ${f.publicKeys[0].id}`]);
});

test("sign.mjs signs what is pending, writes new files once, and refuses to overwrite", async () => {
  const f = fixture();
  const out = join(f.root, "signed");
  const opts = { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, now: new Date("2026-12-01T00:00:00Z"), log: () => {} };
  const plan = await signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", out], opts);
  assert.equal(plan.seq, 1);
  assert.deepEqual(plan.packages.map((p) => [p.tag, p.fresh]), [["atlas.map-v1.1.0", true]]);
  assert.deepEqual(plan.skipped, []);
  for (const name of ["atlas.map-1.1.0.pmmod", "index.json", "index.json.minisig", "plan.json"]) assert.ok(existsSync(join(out, name)), name);
  // What it wrote reads back under the keys, as the publish step will upload it.
  const read = (n) => readFileSync(join(out, n));
  const result = await verifyPublished({
    getIndex: async () => ({ json: read("index.json"), signature: read("index.json.minisig") }),
    getPackage: async (m) => read(packageAsset(m.id, m.version)),
    publicKeys: f.publicKeys,
  });
  assert.equal(result.seq, 1);
  await assert.rejects(signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", out], opts), /already exists/);
  // The next run, with the package published and the live pair read through the API: seq 2, no new package.
  const live2 = join(f.root, "live2");
  mkdirSync(live2);
  writeFileSync(join(live2, "index.json"), read("index.json"));
  writeFileSync(join(live2, "index.json.minisig"), read("index.json.minisig"));
  const reads = new Map([[packageUrl("atlas.map", "1.1.0"), read("atlas.map-1.1.0.pmmod")]]);
  const out2 = join(f.root, "signed2");
  const plan2 = await signMain(["--unsigned", join(f.root, "none"), "--live", live2, "--out", out2], { ...opts, get: async (url) => reads.get(url) ?? null });
  assert.equal(plan2.seq, 2);
  assert.equal(existsSync(join(out2, "atlas.map-1.1.0.pmmod")), false);
  assert.ok(existsSync(join(out2, "index.json")));
});

test("sign.mjs never reads 'no live index' from anything but the first-publish marker", async () => {
  const f = fixture();
  const opts = { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, now: new Date("2026-12-01T00:00:00Z"), log: () => {} };
  const sign = (live) => signMain(["--unsigned", f.unsigned, "--live", live, "--out", join(f.root, `o-${Math.random()}`)], opts);
  // The read step never ran: an empty folder, or no folder, is not a first publish (seq would reset to 1).
  const empty = join(f.root, "empty");
  mkdirSync(empty);
  await assert.rejects(sign(empty), /neither the live index pair nor the first-publish marker/);
  await assert.rejects(sign(join(f.root, "absent")), /neither the live index pair nor the first-publish marker/);
  // Half a pair, or a pair beside the marker.
  const half = join(f.root, "half");
  mkdirSync(half);
  writeFileSync(join(half, "index.json"), "{}");
  await assert.rejects(sign(half), /neither the live index pair/);
  const both = join(f.root, "both");
  mkdirSync(both);
  for (const n of ["index.json", "index.json.minisig", NO_INDEX_MARKER]) writeFileSync(join(both, n), "x");
  await assert.rejects(sign(both), /neither the live index pair/);
  // A pair that doesn't verify stops the job (it is not a first publish either).
  const bad = join(f.root, "bad");
  mkdirSync(bad);
  for (const n of ["index.json", "index.json.minisig"]) writeFileSync(join(bad, n), "x");
  await assert.rejects(sign(bad), /live index doesn't verify/);
  // And --live is required.
  await assert.rejects(signMain(["--unsigned", f.unsigned, "--out", join(f.root, "o")], opts), /--live DIR/);
});

test("sign.mjs reads only regular files with the catalogue's names from the build folder", async () => {
  const f = fixture();
  const opts = { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, now: new Date("2026-12-01T00:00:00Z"), log: () => {} };
  let n = 0;
  const sign = () => signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", join(f.root, `o${n++}`)], opts);
  // A file the catalogue doesn't name.
  writeFileSync(join(f.unsigned, "evil.mjs"), "process.exit(0)");
  await assert.rejects(sign(), /not the build of a catalogue entry/);
  rmSync(join(f.unsigned, "evil.mjs"));
  // The expected name as a symlink (to the real file, and to something else): never followed.
  const name = `${f.entry.id}-${f.entry.version}.unsigned.pmmod`;
  const real = join(f.root, "elsewhere.pmmod");
  writeFileSync(real, f.bytes);
  rmSync(join(f.unsigned, name));
  symlinkSync(real, join(f.unsigned, name));
  await assert.rejects(sign(), /can't be opened as a plain file/);
  // The expected name as a directory.
  rmSync(join(f.unsigned, name));
  mkdirSync(join(f.unsigned, name));
  await assert.rejects(sign(), /isn't a regular file|can't be opened/);
  // The folder itself a symlink.
  const link = join(f.root, "linked");
  symlinkSync(f.unsigned, link);
  await assert.rejects(signMain(["--unsigned", link, "--live", f.live, "--out", join(f.root, "olink")], opts), /isn't a plain folder/);
});

test("sign.mjs --allow-unbuilt leaves out an entry with no build; without the flag it refuses", async () => {
  const f = fixture();
  // A second entry, pending and never built.
  const manifest2 = manifestOf({ id: "atlas.pin", name: "Pin" });
  const bytes2 = unsignedPackage({ manifest: manifest2 });
  const entry2 = entryFor(bytes2, manifest2);
  writeFileSync(join(f.root, "catalogue.json"), serializeCatalogue([f.entry, entry2]));
  const opts = { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, now: new Date("2026-12-01T00:00:00Z"), log: () => {} };
  await assert.rejects(signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", join(f.root, "a")], opts), /no build of it to sign/);
  const plan = await signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", join(f.root, "b"), "--allow-unbuilt"], opts);
  assert.deepEqual(plan.skipped, ["atlas.pin-v1.1.0"]);
  assert.deepEqual(plan.packages.map((p) => p.tag), ["atlas.map-v1.1.0"]);
  const index = JSON.parse(readFileSync(join(f.root, "b", "index.json"), "utf8"));
  assert.deepEqual(index.mods.map((m) => m.id), ["atlas.map"]);
  // Nothing built and nothing published: no index of nothing.
  const none = join(f.root, "none");
  mkdirSync(none);
  await assert.rejects(signMain(["--unsigned", none, "--live", f.live, "--out", join(f.root, "c"), "--allow-unbuilt"], opts), /nothing to put in an index/);
});

test("sign.mjs refuses without the secrets, with a wrong password, and with a key that isn't the pinned main key", () => {
  const run = (env) => spawnSync(process.execPath, [join(scripts, "sign.mjs"), "--key-check-only"], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
  const none = run({});
  assert.equal(none.status, 1);
  assert.match(none.stderr, /are needed/);
  const { main } = ephemeralRing();
  const wrongPassword = run({ ATLAS_MOD_SIGNING_KEY: main.generated.secretBase64, ATLAS_MOD_SIGNING_KEY_PASSWORD: "nope" });
  assert.equal(wrongPassword.status, 1);
  assert.match(wrongPassword.stderr, /password is wrong/);
  // A well-formed key that is not 95B83457064D517B.
  const notMain = run({ ATLAS_MOD_SIGNING_KEY: main.generated.secretBase64, ATLAS_MOD_SIGNING_KEY_PASSWORD: "test-password" });
  assert.equal(notMain.status, 1);
  assert.match(notMain.stderr, /not the pinned main key 95B83457064D517B/);
});

test("dry-run.mjs signs with a throwaway key it makes itself and reads everything back", () => {
  const f = fixture();
  const out = execFileSync(process.execPath, [join(scripts, "dry-run.mjs"), "--unsigned", f.unsigned, "--catalogue", join(f.root, "catalogue.json"), "--blacklist", join(f.root, "blacklist.json")], { encoding: "utf8" });
  assert.match(out, /dry run OK: index seq 1, 1 mod\(s\)/);
});

test("verify-published.mjs --dir refuses a folder not signed by a pinned key", async () => {
  const f = fixture();
  const out = join(f.root, "signed");
  await signMain(["--unsigned", f.unsigned, "--live", f.live, "--out", out], { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, log: () => {} });
  const r = spawnSync(process.execPath, [join(scripts, "verify-published.mjs"), "--dir", out], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /isn't by a key that is trusted here/);
});
