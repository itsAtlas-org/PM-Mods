// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { test } from "node:test";

import { buildIndex, signIndex, validityWindow, verifyIndex } from "../scripts/lib/index.mjs";
import { generateKey, loadSecretKey } from "../scripts/lib/minisign.mjs";
import { assertMainKey, checkKey, prepareRelease } from "../scripts/lib/pipeline.mjs";
import { verifyPublished } from "../scripts/lib/published.mjs";
import { releaseTag } from "../scripts/lib/rules.mjs";
import { entryFor, ephemeralRing, expectRefusal, manifestOf, sha256, unsignedPackage } from "./helpers.mjs";

const NOW = new Date("2026-12-01T10:00:00Z");

/** A fake world: unsigned builds by tag, what is published by tag, and the live index. */
function world() {
  const { main, rollover, publicKeys } = ephemeralRing();
  const builds = new Map();
  const published = new Map();
  const state = { live: null };
  const catalogue = [];
  const add = (manifestPatch = {}, extra = {}) => {
    const manifest = manifestOf(manifestPatch);
    const bytes = unsignedPackage({ manifest, files: extra });
    const entry = entryFor(bytes, manifest);
    builds.set(releaseTag(entry.id, entry.version), bytes);
    catalogue.push(entry);
    return entry;
  };
  const run = (over = {}) =>
    prepareRelease({
      catalogue: [...catalogue].sort((a, b) => (a.id + a.version < b.id + b.version ? -1 : 1)),
      blacklist: [],
      key: main.key,
      publicKeys,
      now: NOW,
      readUnsigned: async (e) => builds.get(releaseTag(e.id, e.version)) ?? null,
      fetchPackage: async (e) => published.get(releaseTag(e.id, e.version)) ?? null,
      fetchLiveIndex: async () => state.live,
      ...over,
    });
  /** What the publish step would do: store new packages, replace the index. */
  const publish = (result) => {
    for (const p of result.packages) if (!published.has(p.tag)) published.set(p.tag, p.bytes);
    state.live = { json: result.index.bytes, signature: result.index.signature };
  };
  return { main, rollover, publicKeys, builds, published, state, catalogue, add, run, publish };
}

test("the first publish is seq 1, signs the pending package, and everything reads back under the pinned keys", async () => {
  const w = world();
  w.add();
  const r = await w.run();
  assert.equal(r.seq, 1);
  assert.equal(r.packages.length, 1);
  assert.equal(r.packages[0].fresh, true);
  assert.equal(r.index.parsed.mods[0].sha256, r.packages[0].sha256);
  assert.equal(r.index.parsed.mods[0].sha256, sha256(r.packages[0].bytes), "the index's sha256 is the signed file's");
  assert.equal(r.index.comment, "pmindex:1\tseq:1\texpires:2027-01-30T10:00:00Z");
  w.publish(r);
  const out = await verifyPublished({
    getIndex: async () => w.state.live,
    getPackage: async (m) => w.published.get(releaseTag(m.id, m.version)) ?? null,
    publicKeys: w.publicKeys,
  });
  assert.equal(out.seq, 1);
  assert.deepEqual(out.rows.map((x) => x.id), ["atlas.map"]);
});

test("a re-run is idempotent: a published package is re-verified, not re-signed, and seq goes up by one", async () => {
  const w = world();
  w.add();
  const first = await w.run();
  w.publish(first);
  const second = await w.run();
  assert.equal(second.seq, 2);
  assert.equal(second.packages[0].fresh, false);
  assert.ok(second.packages[0].bytes.equals(first.packages[0].bytes));
  // The same inputs on a fresh signer (a half-finished publish re-run) give the same package bytes.
  const again = await w.run({ fetchPackage: async () => null });
  assert.ok(again.packages[0].bytes.equals(first.packages[0].bytes), "signing is deterministic");
});

test("a new version is signed beside the old; the index lists the highest version only", async () => {
  const w = world();
  w.add();
  w.publish(await w.run());
  w.add({ version: "1.2.0" });
  w.add({ id: "atlas.pin", name: "Pin" });
  const r = await w.run();
  assert.deepEqual(r.packages.map((p) => `${p.tag}:${p.fresh}`), ["atlas.map-v1.1.0:false", "atlas.map-v1.2.0:true", "atlas.pin-v1.1.0:true"]);
  assert.deepEqual(r.index.parsed.mods.map((m) => `${m.id}@${m.version}`), ["atlas.map@1.2.0", "atlas.pin@1.1.0"]);
  assert.equal(r.seq, 2);
});

test("an older version is never what the index offers, even when it is the only one pending", async () => {
  const w = world();
  w.add({ version: "1.2.0" });
  w.publish(await w.run());
  w.add({ version: "1.1.0" });
  const r = await w.run();
  assert.equal(r.index.parsed.mods[0].version, "1.2.0");
  assert.equal(r.packages.find((p) => p.tag === "atlas.map-v1.1.0").fresh, true);
});

test("the live index must verify, or the job stops (never a reset to seq 1)", async () => {
  const w = world();
  w.add();
  const good = await w.run();
  w.publish(good);
  const flipped = Buffer.from(w.state.live.json);
  flipped[5] ^= 1;
  w.state.live = { json: flipped, signature: w.state.live.signature };
  await assert.rejects(w.run(), /live index doesn't verify/);
  w.state.live = { json: good.index.bytes, signature: Buffer.from("garbage") };
  await assert.rejects(w.run(), /live index doesn't verify/);
  // An index signed by a key nobody pinned.
  const g = generateKey({ password: "x" });
  const other = loadSecretKey(g.secretBase64, "x");
  w.state.live = { json: good.index.bytes, signature: signIndex(other, good.index.bytes, good.index.parsed) };
  await assert.rejects(w.run(), /live index doesn't verify/);
});

test("a live index that carries a revocation is not replaced by CI", async () => {
  const w = world();
  w.add();
  const first = await w.run();
  const revoking = buildIndex({ ...validityWindow(NOW), seq: 7, mods: first.index.parsed.mods, blacklist: [], revokedKeyIds: [w.main.pub.id] });
  w.state.live = { json: revoking.bytes, signature: signIndex(w.rollover.key, revoking.bytes, revoking.parsed) };
  await assert.rejects(w.run(), /revokes a key/);
});

test("a tampered published package stops the job; so does a catalogue/build mismatch", async () => {
  const w = world();
  w.add();
  w.publish(await w.run());
  const tag = "atlas.map-v1.1.0";
  const bad = Buffer.from(w.published.get(tag));
  bad[bad.length - 100] ^= 1;
  w.published.set(tag, bad);
  await assert.rejects(w.run());
  // Pending, but the build isn't what the catalogue recorded.
  const w2 = world();
  const entry = w2.add();
  w2.builds.set(releaseTag(entry.id, entry.version), unsignedPackage({ manifest: manifestOf(), files: { "NOTICE.txt": "different\n" } }));
  await assert.rejects(w2.run(), /catalogue records/);
  // Pending with no build at all.
  const w3 = world();
  const e3 = w3.add();
  w3.builds.delete(releaseTag(e3.id, e3.version));
  await assert.rejects(w3.run(), /no build of it to sign/);
});

test("the signing key must be the pinned MAIN key", () => {
  const { main, rollover, publicKeys } = ephemeralRing();
  assert.equal(assertMainKey(main.key, publicKeys).id, main.pub.id);
  expectRefusal(() => assertMainKey(rollover.key, publicKeys), /rollover key .* never signs in CI/);
  const g = generateKey({ password: "x" });
  expectRefusal(() => assertMainKey(loadSecretKey(g.secretBase64, "x"), publicKeys), /not the pinned main key/);
  // Same id, different key material: refused on the public half.
  const impostor = generateKey({ password: "x", idBytes: main.key.idBytes });
  expectRefusal(() => assertMainKey(loadSecretKey(impostor.secretBase64, "x"), publicKeys), /not the pinned main key/);
  assert.equal(checkKey(main.key, publicKeys), main.pub.id);
});

test("prepareRelease refuses to run with a key that isn't the main key, before it reads anything", async () => {
  const w = world();
  w.add();
  await assert.rejects(w.run({ key: w.rollover.key, fetchPackage: async () => assert.fail("read") }), /rollover key/);
});

test("the blacklist ships in the same index and is read back", async () => {
  const w = world();
  w.add();
  const blacklist = [{ id: "acme.notes", versions: ">=1.0.0, <1.2.0", action: "paused", reason: "It can lose your notes on sync.", fixedIn: "1.2.0" }];
  const r = await w.run({ blacklist });
  assert.equal(verifyIndex(r.index.bytes, r.index.signature, w.publicKeys).parsed.blacklist.length, 1);
});

test("verifyPublished refuses an index that names a file that isn't there or differs", async () => {
  const w = world();
  w.add();
  const r = await w.run();
  w.publish(r);
  const reads = (override) => ({
    getIndex: async () => w.state.live,
    getPackage: async (m) => override ?? w.published.get(releaseTag(m.id, m.version)) ?? null,
    publicKeys: w.publicKeys,
  });
  await assert.rejects(verifyPublished({ ...reads(), getPackage: async () => null }), /isn't there/);
  const other = unsignedPackage({ manifest: manifestOf() });
  await assert.rejects(verifyPublished(reads(other)), /isn't signed/);
  await assert.rejects(verifyPublished({ ...reads(), getIndex: async () => null }), /no index/);
});
