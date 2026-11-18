// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { test } from "node:test";

import { signPrehashed } from "../scripts/lib/minisign.mjs";
import {
  inspectPackage,
  manifestFacts,
  parsePackageComment,
  signPackage,
  trustedCommentFor,
  verifyPackage,
} from "../scripts/lib/package.mjs";
import { CHECKSUMS, readZip, SIGNATURE, writeZip } from "../scripts/lib/zip.mjs";
import { COMMIT, entryFor, ephemeralRing, expectRefusal, manifestOf, sha256, unsignedPackage } from "./helpers.mjs";

const sign = (bytes, entry, over = {}) => {
  const { main, publicKeys } = ephemeralRing();
  return signPackage(bytes, entry, over.key ?? main.key, over.publicKeys ?? publicKeys);
};

test("the trusted comment is eight TAB-joined fields in PM's order", () => {
  const facts = manifestFacts(manifestOf());
  assert.equal(
    trustedCommentFor(facts),
    ["pmmod:1", "id:atlas.map", "version:1.1.0", "tier:first", "author:Atlas", "sourceRepo:itsAtlas-org/Personal-Manager", `commit:${COMMIT}`, "api:1.0-1.0"].join("\t"),
  );
  assert.deepEqual(parsePackageComment(trustedCommentFor(facts)), {
    id: "atlas.map", version: "1.1.0", tier: "first", author: "Atlas", sourceRepo: "itsAtlas-org/Personal-Manager", commit: COMMIT, api: "1.0-1.0",
  });
  // api from apiVersion, with a wider range.
  assert.equal(manifestFacts(manifestOf({ apiVersion: { min: "1.0", target: "2.3" } })).api, "1.0-2.3");
});

test("a comment value with a control character or a TAB can't be signed", () => {
  for (const author of ["A\tB", "A\nB", "A\u0000B"]) {
    expectRefusal(() => manifestFacts(manifestOf({ publisher: { ...manifestOf().publisher, author } })), /author/);
  }
  const facts = manifestFacts(manifestOf());
  expectRefusal(() => trustedCommentFor({ ...facts, author: "A\tB" }), /control character/);
  expectRefusal(() => trustedCommentFor({ ...facts, commit: "" }), /empty/);
});

test("PM's parser refusals for a comment are mirrored", () => {
  const good = trustedCommentFor(manifestFacts(manifestOf()));
  const parts = good.split("\t");
  const swap = (n, value) => parts.map((p, i) => (i === n ? value : p)).join("\t");
  expectRefusal(() => parsePackageComment(parts.slice(0, 7).join("\t")), /wrong number/);
  expectRefusal(() => parsePackageComment(`${good}\textra:1`), /wrong number/);
  expectRefusal(() => parsePackageComment(swap(1, "ID:atlas.map")), /expected id/);
  expectRefusal(() => parsePackageComment(swap(0, "pmmod:2")), /not a mod's signature/);
  expectRefusal(() => parsePackageComment(swap(3, "tier:third")), /tier/);
  expectRefusal(() => parsePackageComment(swap(6, "commit:ABC")), /commit/);
  expectRefusal(() => parsePackageComment(swap(4, "author:")), /empty/);
  // Fields out of order are refused.
  expectRefusal(() => parsePackageComment([parts[0], parts[2], parts[1], ...parts.slice(3)].join("\t")), /expected id/);
});

test("signing a pre-sign package: the signature covers checksums.json, the entries are the unsigned ones plus the signature", () => {
  const unsigned = unsignedPackage();
  const entry = entryFor(unsigned);
  const signed = sign(unsigned, entry);
  const before = readZip(unsigned);
  const after = readZip(signed.bytes);
  assert.deepEqual([...after.keys()], [...before.keys(), SIGNATURE].sort());
  for (const [k, v] of before) assert.ok(after.get(k).equals(v), k);
  assert.equal(signed.sha256, sha256(signed.bytes));
  const back = verifyPackage(signed.bytes, ephemeralRing().publicKeys, entry);
  assert.equal(back.comment, signed.comment);
  assert.equal(back.signer.role, "main");
  assert.ok(back.unsigned.equals(unsigned), "minus its signature, the package is the pinned unsigned bytes");
  assert.equal(back.unsignedSha256, entry.unsignedSha256);
  // Deterministic: signing again gives the same file.
  assert.ok(sign(unsigned, entry).bytes.equals(signed.bytes));
});

test("the catalogue pins what is signed: sha256, id, version, tier, author, repo, commit", () => {
  const unsigned = unsignedPackage();
  const entry = entryFor(unsigned);
  expectRefusal(() => sign(unsigned, { ...entry, unsignedSha256: sha256("other") }), /catalogue records/);
  for (const [, over, pattern] of [
    ["id", { id: "atlas.other" }, /manifest's id/],
    ["version", { version: "1.1.1" }, /manifest's version/],
    ["tier", { tier: "second" }, /manifest's tier/],
    ["author", { author: "Someone" }, /manifest's author/],
    ["repo", { repo: "acme/other" }, /manifest's sourceRepo/],
    ["commit", { commit: "1".repeat(40) }, /manifest's commit/],
  ]) {
    expectRefusal(() => sign(unsigned, { ...entry, ...over }), pattern);
  }
});

test("the manifest's own faults stop a signature (the all-zero commit, tier and id, licence, text rules)", () => {
  const faulty = (patch, pattern) => {
    const manifest = manifestOf(patch);
    const unsigned = unsignedPackage({ manifest });
    expectRefusal(() => sign(unsigned, entryFor(unsigned, manifestOf())), pattern);
  };
  faulty({ publisher: { ...manifestOf().publisher, commit: "0".repeat(40) } }, /commit|placeholder/);
  faulty({ publisher: { ...manifestOf().publisher, tier: "second" } }, /atlas/);
  faulty({ licence: "MIT" }, /licence/);
  faulty({ name: "x".repeat(41) }, /name/);
  faulty({ name: "Map‮" }, /name/);
  faulty({ description: "x".repeat(281) }, /description/);
  faulty({ apiVersion: { min: "1.2", target: "1.0" } }, /apiVersion/);
  faulty({ apiVersion: { min: "01.0", target: "1.0" } }, /apiVersion/);
  faulty({ permissions: [{ id: "everything", why: "x" }] }, /unknown permission/);
  faulty({ permissions: [{ id: "storage", why: "x" }, { id: "storage", why: "y" }] }, /twice/);
  faulty({ version: "1.1.0+build" }, /version/);
});

test("the package itself is checked: files listed, checksums right, nothing extra, not already signed", () => {
  const { main } = ephemeralRing();
  const entryOf = (b) => entryFor(b);
  // A file that checksums.json doesn't list.
  const extra = unsignedPackage({ raw: { "app/extra.js": "x" } });
  expectRefusal(() => sign(extra, entryOf(extra)), /aren't exactly the files/);
  // A listed file that is changed after the checksums were made.
  const changed = unsignedPackage({ raw: { "app/index.html": "<html>changed</html>" } });
  expectRefusal(() => sign(changed, entryOf(changed)), /doesn't match its checksum/);
  // Not the AGPL.
  const licence = unsignedPackage({ files: { "LICENCE.txt": "MIT" } });
  expectRefusal(() => sign(licence, entryOf(licence)), /AGPL/);
  // Already signed.
  const unsigned = unsignedPackage();
  const signed = sign(unsigned, entryOf(unsigned));
  expectRefusal(() => sign(signed.bytes, entryOf(signed.bytes)), /already signed/);
  // A stray pmmod/ entry.
  const stray = unsignedPackage({ raw: { "pmmod/other.txt": "x" } });
  expectRefusal(() => sign(stray, entryOf(stray)), /isn't allowed in a mod/);
  // No manifest.
  const noManifest = unsignedPackage({ files: { "manifest.json": null } });
  expectRefusal(() => sign(noManifest, entryOf(noManifest)), /no manifest.json/);
  // A manifest that repeats a key (JSON.parse would keep the last; PM refuses).
  const entries = readZip(unsigned);
  entries.set("manifest.json", Buffer.from(entries.get("manifest.json").toString().replace('"version": "1.1.0"', '"version": "1.1.0", "version": "9.9.9"')));
  const dup = writeZip(entries);
  expectRefusal(() => inspectPackage(dup, { signed: false }), /checksum|repeated/);
});

test("a signed package is refused when anything is changed after signing", () => {
  const { main, rollover, publicKeys } = ephemeralRing();
  const unsigned = unsignedPackage();
  const entry = entryFor(unsigned);
  const signed = sign(unsigned, entry);
  const entries = readZip(signed.bytes);
  const rebuilt = (mutate) => {
    const e = new Map(entries);
    mutate(e);
    return writeZip(e);
  };
  // Changing a file and fixing checksums.json up: the signature over checksums.json no longer holds.
  const evil = unsignedPackage({ files: { "app/index.html": "<html>evil</html>" } });
  const tampered = rebuilt((e) => {
    e.set("app/index.html", Buffer.from("<html>evil</html>"));
    e.set(CHECKSUMS, readZip(evil).get(CHECKSUMS));
  });
  expectRefusal(() => verifyPackage(tampered, publicKeys), null, "bad-signature");
  // A signature by a key that isn't pinned.
  const stranger = ephemeralRing().rollover;
  assert.equal(verifyPackage(signed.bytes, [rollover.pub, main.pub]).signer.role, "main");
  expectRefusal(() => verifyPackage(signed.bytes, [stranger.pub]), /isn't by a key/, "untrusted-key");
  // Missing signature.
  expectRefusal(() => verifyPackage(unsigned, publicKeys), /isn't signed/);
  // A signature whose comment names other facts than the manifest.
  const wrongComment = signPrehashed(main.key, entries.get(CHECKSUMS), trustedCommentFor({ ...manifestFacts(manifestOf()), version: "9.9.9" }));
  expectRefusal(() => verifyPackage(rebuilt((e) => e.set(SIGNATURE, wrongComment)), publicKeys), /manifest's version isn't the one that was signed/);
  // A comment that isn't a package's (an index's signature on checksums.json).
  const asIndex = signPrehashed(main.key, entries.get(CHECKSUMS), "pmindex:1\tseq:1\texpires:2027-01-30T00:00:00Z");
  expectRefusal(() => verifyPackage(rebuilt((e) => e.set(SIGNATURE, asIndex)), publicKeys), /wrong number of fields/);
  // Against the wrong catalogue entry.
  expectRefusal(() => verifyPackage(signed.bytes, publicKeys, { ...entry, unsignedSha256: sha256("z") }), /catalogue records/);
  expectRefusal(() => verifyPackage(signed.bytes, publicKeys, { ...entry, commit: "2".repeat(40) }), /commit/);
  // An oversized signature entry.
  const big = rebuilt((e) => e.set(SIGNATURE, Buffer.alloc(5000, 65)));
  expectRefusal(() => verifyPackage(big, publicKeys), /too large/);
});
