// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  buildIndex,
  checkIndexObject,
  indexEntryFor,
  indexTrustedComment,
  parseIndex,
  signIndex,
  validityWindow,
  verifyIndex,
} from "../scripts/lib/index.mjs";
import { parsePublicKey, signPrehashed } from "../scripts/lib/minisign.mjs";
import { MAX_BLACKLIST, MAX_MODS, packageUrl } from "../scripts/lib/rules.mjs";
import { COMMIT, ephemeralRing, expectRefusal, sha256 } from "./helpers.mjs";

const vector = (name) => readFileSync(new URL(`./vectors/${name}`, import.meta.url));
const SHA = "a".repeat(64);

const facts = (over = {}) => ({
  id: "atlas.map",
  name: "Map",
  description: "Your documents, laid out by meaning.",
  tier: "first",
  author: "Atlas",
  version: "1.0.0",
  api: "1.0-1.0",
  sourceRepo: "itsAtlas-org/Personal-Manager",
  commit: COMMIT,
  licence: "AGPL-3.0-or-later",
  permissions: ["documents.meta", "ui.tab"],
  ...over,
});
const now = new Date("2026-12-01T10:20:30.789Z");
const parts = () => ({ ...validityWindow(now), seq: 1, mods: [indexEntryFor(facts(), SHA)], blacklist: [] });

test("PM's pinned vector parses, and our comment builder gives exactly its COMMENT", () => {
  const bytes = vector("pm-index-vector.json");
  const comment = vector("pm-index-vector.comment.txt").toString();
  const parsed = parseIndex(bytes);
  assert.equal(parsed.seq, 42);
  assert.equal(indexTrustedComment(parsed), comment);
  assert.equal(comment, "pmindex:1\tseq:42\texpires:2027-04-30T09:30:00Z\trevoke:95B83457064D517B");
  assert.equal(parsed.mods[0].url, packageUrl("atlas.map", "1.0.0"));
  // Without a revocation, which is every index before a rotation: three fields.
  const plain = bytes.toString().replace('"revokedKeyIds":["95B83457064D517B"]', '"revokedKeyIds":[]');
  assert.notEqual(plain, bytes.toString());
  assert.equal(indexTrustedComment(parseIndex(Buffer.from(plain))), "pmindex:1\tseq:42\texpires:2027-04-30T09:30:00Z");
});

test("the vector verifies under a ring where the rollover key signs it, as PM's test does", () => {
  const { rollover, main } = ephemeralRing();
  const bytes = vector("pm-index-vector.json");
  const sig = signPrehashed(rollover.key, bytes, vector("pm-index-vector.comment.txt").toString());
  // The vector revokes 95B83457064D517B, which is PM's real main id: stand in a ring that holds it.
  const standIn = { ...main.pub, id: "95B83457064D517B", role: "main" };
  const out = verifyIndex(bytes, sig, [standIn, rollover.pub]);
  assert.equal(out.signer.role, "rollover");
  // The same revocation signed by the main key is refused: only the rollover key revokes.
  const bySecond = signPrehashed(main.key, bytes, vector("pm-index-vector.comment.txt").toString());
  expectRefusal(() => verifyIndex(bytes, bySecond, [standIn, rollover.pub]), /only the rollover key may revoke/, "revocation");
});

test("a pair made by this tooling with a throwaway key, accepted by PM's real verifier, verifies here", () => {
  const key = parsePublicKey(readFileSync(new URL("./vectors/throwaway.pub", import.meta.url), "utf8").trim());
  const out = verifyIndex(vector("throwaway-index.json"), vector("throwaway-index.json.minisig"), [{ ...key, role: "main" }]);
  assert.equal(out.parsed.seq, 1);
  assert.equal(out.parsed.mods[0].id, "atlas.map");
  assert.equal(out.parsed.blacklist.length, 2);
  // Not under the real Atlas keys.
  expectRefusal(() => verifyIndex(vector("throwaway-index.json"), vector("throwaway-index.json.minisig"), ephemeralRing().publicKeys), null, "untrusted-key");
});

test("the writer's own output is what the mirror accepts: key order, two-space JSON, final LF, sorted mods", () => {
  const { bytes, comment, parsed } = buildIndex({
    ...parts(),
    mods: [indexEntryFor(facts({ id: "atlas.pin" }), SHA), indexEntryFor(facts({ id: "atlas.map" }), SHA)],
    blacklist: [{ reason: "r", action: "removed", sha256: "1".repeat(64) }],
  });
  const text = bytes.toString();
  assert.ok(text.endsWith("}\n"));
  const object = JSON.parse(text);
  assert.deepEqual(Object.keys(object), ["format", "seq", "issued", "expires", "revokedKeyIds", "mods", "blacklist"]);
  assert.deepEqual(Object.keys(object.mods[0]), ["id", "name", "description", "tier", "author", "version", "api", "url", "sha256", "permissions", "sourceRepo", "commit", "licence"]);
  assert.deepEqual(object.mods.map((m) => m.id), ["atlas.map", "atlas.pin"]);
  assert.deepEqual(Object.keys(object.blacklist[0]), ["sha256", "action", "reason"]);
  assert.equal(object.issued, "2026-12-01T10:20:30Z");
  assert.equal(object.expires, "2027-01-30T10:20:30Z");
  assert.equal(comment, "pmindex:1\tseq:1\texpires:2027-01-30T10:20:30Z");
  assert.equal(parsed.seq, 1);
  // The same inputs give the same bytes.
  assert.ok(buildIndex({ ...parts(), mods: [indexEntryFor(facts({ id: "atlas.pin" }), SHA), indexEntryFor(facts({ id: "atlas.map" }), SHA)], blacklist: [{ reason: "r", action: "removed", sha256: "1".repeat(64) }] }).bytes.equals(bytes));
});

test("validity: issued is now to the second, expires 60 days on, within PM's 120-day cap", () => {
  const w = validityWindow(now);
  assert.equal(w.issued.toISOString(), "2026-12-01T10:20:30.000Z");
  assert.equal((w.expires - w.issued) / 86_400_000, 60);
});

test("a signed index verifies; a changed byte, comment or key is refused", () => {
  const { main, publicKeys } = ephemeralRing();
  const built = buildIndex(parts());
  const sig = signIndex(main.key, built.bytes, built.parsed);
  assert.ok(sig.toString().includes(`trusted comment: ${built.comment}`));
  const out = verifyIndex(built.bytes, sig, publicKeys);
  assert.equal(out.signer.role, "main");
  const flipped = Buffer.from(built.bytes);
  flipped[10] ^= 1;
  expectRefusal(() => verifyIndex(flipped, sig, publicKeys), null, "bad-signature");
  // A signature with another seq in its comment: the signature is fine, the comment doesn't match the JSON.
  const wrong = signPrehashed(main.key, built.bytes, built.comment.replace("seq:1", "seq:2"));
  expectRefusal(() => verifyIndex(built.bytes, wrong, publicKeys), /aren't the ones in index.json/, "comment-mismatch");
  // A package's signature isn't an index's.
  const asPackage = signPrehashed(main.key, built.bytes, "pmmod:1\tx");
  expectRefusal(() => verifyIndex(built.bytes, asPackage, publicKeys), /isn't an index's/, "trusted-comment");
  // Size caps come first.
  expectRefusal(() => verifyIndex(Buffer.alloc((1 << 20) + 1), sig, publicKeys), /too large/);
  expectRefusal(() => verifyIndex(built.bytes, Buffer.alloc((4 << 10) + 1), publicKeys), /too large/);
});

test("only the rollover key revokes, and nothing revokes the rollover key", () => {
  const { main, rollover, publicKeys } = ephemeralRing();
  const make = (revoked) => buildIndex({ ...parts(), revokedKeyIds: revoked });
  const revokeMain = make([main.pub.id]);
  assert.ok(revokeMain.comment.endsWith(`\trevoke:${main.pub.id}`));
  const byMain = signIndex(main.key, revokeMain.bytes, revokeMain.parsed);
  expectRefusal(() => verifyIndex(revokeMain.bytes, byMain, publicKeys), /only the rollover key may revoke/, "revocation");
  const byRollover = signIndex(rollover.key, revokeMain.bytes, revokeMain.parsed);
  assert.equal(verifyIndex(revokeMain.bytes, byRollover, publicKeys).signer.role, "rollover");
  const revokeRollover = make([rollover.pub.id]);
  const sig = signIndex(rollover.key, revokeRollover.bytes, revokeRollover.parsed);
  expectRefusal(() => verifyIndex(revokeRollover.bytes, sig, publicKeys), /nothing may revoke/, "revocation");
  // An id nobody here holds is allowed and ignored.
  const stranger = make(["0000000000000001"]);
  assert.ok(verifyIndex(stranger.bytes, signIndex(main.key, stranger.bytes, stranger.parsed), publicKeys));
});

// ---- Refusals, table copied from index.rs (every one a Field refusal there) -------------------------

const goodObject = () => JSON.parse(buildIndex(parts()).bytes.toString());
const refusedWith = (change) => {
  const o = goodObject();
  change(o);
  return expectRefusal(() => checkIndexObject(o), null);
};

test("index-level refusals", () => {
  refusedWith((i) => (i.extra = 1));
  refusedWith((i) => (i.mods[0].extra = 1));
  refusedWith((i) => (i.blacklist = [{ id: "acme.x", versions: "*", action: "paused", reason: "r", fixed_in: "1.0.0" }]));
  for (const k of ["format", "seq", "issued", "expires", "revokedKeyIds", "mods", "blacklist"]) refusedWith((i) => delete i[k]);
  refusedWith((i) => delete i.mods[0].licence);
  refusedWith((i) => (i.mods = null));
  refusedWith((i) => (i.format = 2));
  assert.equal(refusedWith((i) => (i.format = 2)).code, "format");
  for (const seq of [0, -1, 1.5, "1", 2 ** 53, null]) refusedWith((i) => (i.seq = seq));
  checkIndexObject({ ...goodObject(), seq: 2 ** 53 - 1 });
  for (const bad of ["2027-01-30T00:00:00.000Z", "2027-01-30T00:00:00+00:00", "2027-02-30T00:00:00Z", "", null]) {
    refusedWith((i) => (i.issued = bad));
    refusedWith((i) => (i.expires = bad));
  }
  refusedWith((i) => (i.expires = i.issued));
  refusedWith((i) => (i.expires = "2026-11-30T00:00:00Z"));
  assert.match(refusedWith((i) => (i.expires = "2027-12-31T00:00:00Z")).message, /more than 120/);
  refusedWith((i) => (i.revokedKeyIds = ["95b83457064d517b"]));
  refusedWith((i) => (i.revokedKeyIds = ["95B83457064D517B", "95B83457064D517B"]));
  refusedWith((i) => (i.revokedKeyIds = ["993CE0152A3E4E8C", "95B83457064D517B"]));
  refusedWith((i) => (i.revokedKeyIds = Array.from({ length: 17 }, (_, n) => n.toString(16).toUpperCase().padStart(16, "0"))));
  checkIndexObject({ ...goodObject(), issued: "2026-12-01T00:00:00Z", expires: "2027-03-31T00:00:00Z" });
});

test("entry-level refusals", () => {
  const entry = (key, value) => refusedWith((i) => (i.mods[0][key] = value));
  const url = (s) => `https://${s}`;
  for (const [what, key, value] of [
    ["id grammar", "id", "Atlas.Map"],
    ["device id", "id", "acme.con"],
    ["empty name", "name", ""],
    ["long name", "name", "x".repeat(41)],
    ["hidden name", "name", "Map‮"],
    ["padded author", "author", " Atlas"],
    ["long description", "description", "x".repeat(281)],
    ["third party", "tier", "third"],
    ["unknown tier", "tier", "zeroth"],
    ["second party atlas", "tier", "second"],
    ["upper version", "version", "1.2.0-RC1"],
    ["build metadata", "version", "1.2.0+b1"],
    ["v prefix", "version", "v1.2.0"],
    ["api shape", "api", "1.0"],
    ["api order", "api", "1.2-1.0"],
    ["api zeros", "api", "01.0-1.0"],
    ["http", "url", "http://github.com/itsAtlas-org/PM-Mods/releases/download/atlas.map-v1.0.0/atlas.map-1.0.0.pmmod"],
    ["other spelling", "url", url("github.com/itsAtlas-org/pm-mods/releases/download/atlas.map-v1.0.0/atlas.map-1.0.0.pmmod")],
    ["latest", "url", url("github.com/itsAtlas-org/PM-Mods/releases/latest/download/atlas.map-1.0.0.pmmod")],
    ["other version", "url", url("github.com/itsAtlas-org/PM-Mods/releases/download/atlas.map-v1.1.0/atlas.map-1.1.0.pmmod")],
    ["query", "url", `${packageUrl("atlas.map", "1.0.0")}?x=1`],
    ["other host", "url", url("evil.example/itsAtlas-org/PM-Mods/releases/download/atlas.map-v1.0.0/atlas.map-1.0.0.pmmod")],
    ["upper sha", "sha256", SHA.toUpperCase()],
    ["short sha", "sha256", SHA.slice(1)],
    ["unknown permission", "permissions", ["ui.tab", "everything"]],
    ["unsorted permissions", "permissions", ["ui.tab", "documents.meta"]],
    ["repeated permission", "permissions", ["ui.tab", "ui.tab"]],
    ["permissions not a list", "permissions", "ui.tab"],
    ["source repo", "sourceRepo", "itsAtlas-org"],
    ["commit", "commit", COMMIT.toUpperCase()],
    ["licence", "licence", "MIT"],
  ]) {
    assert.ok(entry(key, value), what);
  }
  // A second-party entry outside atlas. passes.
  const o = goodObject();
  Object.assign(o.mods[0], { id: "acme.tools", tier: "second", author: "Acme", permissions: [], url: packageUrl("acme.tools", "1.0.0") });
  checkIndexObject(o);
  // Descriptions may hold newlines; names may not.
  o.mods[0].description = "line one\nline two";
  checkIndexObject(o);
  o.mods[0].name = "two\nlines";
  expectRefusal(() => checkIndexObject(o));
});

test("the catalogue is ascending, unique and bounded; the blacklist is too", () => {
  const o = goodObject();
  const second = { ...o.mods[0], id: "atlas.pin", url: packageUrl("atlas.pin", "1.0.0") };
  refusedWith((i) => (i.mods = [second, i.mods[0]]));
  refusedWith((i) => (i.mods = [i.mods[0], i.mods[0]]));
  checkIndexObject({ ...o, mods: [o.mods[0], second] });
  const many = Array.from({ length: MAX_MODS + 1 }, (_, n) => {
    const id = `acme.m${String(n).padStart(4, "0")}`;
    return { ...o.mods[0], id, tier: "second", url: packageUrl(id, "1.0.0") };
  });
  expectRefusal(() => checkIndexObject({ ...o, mods: many }), /too many/);
  checkIndexObject({ ...o, mods: many.slice(0, MAX_MODS) });
  const entry = { sha256: "1".repeat(64), action: "paused", reason: "r" };
  checkIndexObject({ ...o, blacklist: Array(MAX_BLACKLIST).fill(entry) });
  expectRefusal(() => checkIndexObject({ ...o, blacklist: Array(MAX_BLACKLIST + 1).fill(entry) }), /too long/);
  // Mods are ordered by BYTES, not by locale or UTF-16: "atlas.a-b" < "atlas.a1"? '-' (0x2d) < '1' (0x31).
  const ids = ["atlas.a-b", "atlas.a1"].map((id) => ({ ...o.mods[0], id, url: packageUrl(id, "1.0.0") }));
  checkIndexObject({ ...o, mods: ids });
  expectRefusal(() => checkIndexObject({ ...o, mods: [...ids].reverse() }), /ascending/);
});

test("the index parser reads bytes strictly: caps, UTF-8, a BOM, a repeated key", () => {
  const good = buildIndex(parts()).bytes;
  assert.ok(parseIndex(good));
  expectRefusal(() => parseIndex(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), good])), /malformed/, "json");
  expectRefusal(() => parseIndex(Buffer.from(good.toString().replace('"seq": 1,', '"seq": 1, "seq": 1,'))), /repeated/, "json");
  expectRefusal(() => parseIndex(Buffer.from([0xff])), /malformed/, "json");
  for (const bad of ["not json", "[]", "{}", "", '{"format":1']) expectRefusal(() => parseIndex(Buffer.from(bad)));
});

test("entry sha256 is the SIGNED file's: indexEntryFor takes it as given", () => {
  assert.equal(indexEntryFor(facts(), sha256("signed")).sha256, sha256("signed"));
});
