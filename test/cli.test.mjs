// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { signMain } from "../scripts/sign.mjs";
import { serializeCatalogue } from "../scripts/lib/catalogue.mjs";
import { verifyPublished } from "../scripts/lib/published.mjs";
import { INDEX_SIGNATURE_URL, INDEX_URL, packageAsset, packageUrl } from "../scripts/lib/rules.mjs";
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
  return { root, unsigned, entry, env, publicKeys, bytes };
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
  const plan = await signMain(["--unsigned", f.unsigned, "--out", out], opts);
  assert.equal(plan.seq, 1);
  assert.deepEqual(plan.packages.map((p) => [p.tag, p.fresh]), [["atlas.map-v1.1.0", true]]);
  for (const name of ["atlas.map-1.1.0.pmmod", "index.json", "index.json.minisig", "plan.json"]) assert.ok(existsSync(join(out, name)), name);
  // What it wrote reads back under the keys, as the publish step will upload it.
  const read = (n) => readFileSync(join(out, n));
  const result = await verifyPublished({
    getIndex: async () => ({ json: read("index.json"), signature: read("index.json.minisig") }),
    getPackage: async (m) => read(packageAsset(m.id, m.version)),
    publicKeys: f.publicKeys,
  });
  assert.equal(result.seq, 1);
  await assert.rejects(signMain(["--unsigned", f.unsigned, "--out", out], opts), /already exists/);
  // The next run, with the package and index now published: seq 2, no new package written.
  const pkg = read("atlas.map-1.1.0.pmmod");
  const live = { json: read("index.json"), signature: read("index.json.minisig") };
  const reads = new Map([[packageUrl("atlas.map", "1.1.0"), pkg], [INDEX_URL, live.json], [INDEX_SIGNATURE_URL, live.signature]]);
  const out2 = join(f.root, "signed2");
  const plan2 = await signMain(["--unsigned", join(f.root, "none"), "--out", out2], { ...opts, get: async (url) => reads.get(url) ?? null });
  assert.equal(plan2.seq, 2);
  assert.equal(existsSync(join(out2, "atlas.map-1.1.0.pmmod")), false);
  assert.ok(existsSync(join(out2, "index.json")));
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
  await signMain(["--unsigned", f.unsigned, "--out", out], { env: f.env, publicKeys: f.publicKeys, catalogueDir: f.root, get: async () => null, log: () => {} });
  const r = spawnSync(process.execPath, [join(scripts, "verify-published.mjs"), "--dir", out], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /isn't by a key that is trusted here/);
});
