// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { crc32 as nodeCrc32 } from "node:zlib";

import { signPackage } from "../scripts/lib/package.mjs";
import { checkPath, crc32, readZip, writeZip } from "../scripts/lib/zip.mjs";
import { ephemeralRing, entryFor, expectRefusal, manifestOf, unsignedPackage } from "./helpers.mjs";

const files = () => new Map([["manifest.json", Buffer.from("{}")], ["LICENCE.txt", Buffer.from("l")], ["app/b.js", Buffer.from("b")], ["app/a.js", Buffer.from("a")]]);

test("crc32 agrees with node's", () => {
  for (const s of ["", "a", "hello world", "x".repeat(10000)]) assert.equal(crc32(Buffer.from(s)), nodeCrc32(Buffer.from(s)));
});

test("the writer sorts by path, stores, and is deterministic; the reader gives the same entries back", () => {
  const a = writeZip(files());
  const reordered = new Map([...files()].reverse());
  assert.ok(a.equals(writeZip(reordered)));
  const back = readZip(a);
  assert.deepEqual([...back.keys()], ["LICENCE.txt", "app/a.js", "app/b.js", "manifest.json"]);
  assert.equal(back.get("app/a.js").toString(), "a");
  // 1980-01-01, method 0, creator Unix: the fixed header fields.
  assert.equal(a.readUInt16LE(8), 0);
  assert.equal(a.readUInt16LE(10), 0);
  assert.equal(a.readUInt16LE(12), 0x21);
});

test("the reader refuses what the writer never writes", () => {
  const good = writeZip(files());
  const bad = (mutate, pattern) => {
    const b = Buffer.from(good);
    mutate(b);
    expectRefusal(() => readZip(b), pattern);
  };
  const end = good.length - 22;
  bad((b) => b.writeUInt16LE(5, end + 20), /commented|zip64/);
  bad((b) => b.writeUInt32LE(0xffffffff, end + 16), /zip64/);
  bad((b) => b.writeUInt16LE(8, 8), /headers don.t agree/); // local flags/method disagree with the directory
  expectRefusal(() => readZip(Buffer.concat([Buffer.from("junk"), good])), /readable/);
  expectRefusal(() => readZip(Buffer.concat([good, Buffer.from("x")])), /no end record/);
  expectRefusal(() => readZip(Buffer.alloc(10)), /no end record/);
  // A flipped data byte: the CRC catches it.
  const damaged = Buffer.from(good);
  damaged[30 + "LICENCE.txt".length] ^= 1;
  expectRefusal(() => readZip(damaged), /damaged/);
  // A deflated entry is refused (the packer never deflates).
  const deflated = Buffer.from(good);
  deflated.writeUInt16LE(8, good.readUInt32LE(end + 16) + 10);
  expectRefusal(() => readZip(deflated), /isn't stored|headers don't agree/);
  // Names that the package layout forbids.
  for (const name of ["../x", "/x", "a\\b", "app/", "other.txt", "app/CON.js", "app/a b.js", "app/a:b"]) {
    expectRefusal(() => checkPath(name), /isn't allowed in a mod/);
  }
  expectRefusal(() => readZip(writeZip(new Map([["manifest.json", Buffer.from("x")], ["app/A.js", Buffer.from("a")], ["app/a.js", Buffer.from("b")]]))), /same file/);
  expectRefusal(() => readZip(writeZip(new Map([["app/a", Buffer.from("x")], ["app/a/b.js", Buffer.from("y")]]))), /file and a folder/);
});

// With PM_CHECKOUT set to a PM source tree: our writer and PM's `attach` give the same bytes.
const pm = process.env.PM_CHECKOUT;
test("signing here equals `pack-mod.mjs attach` byte for byte (needs PM_CHECKOUT)", { skip: !pm || !existsSync(join(pm, "scripts/pack-mod.mjs")) }, async () => {
  const packMod = await import(pathToFileURL(join(pm, "scripts/pack-mod.mjs")).href);
  const { main, publicKeys } = ephemeralRing();
  const manifest = manifestOf();
  const unsigned = unsignedPackage({ manifest });
  const signed = signPackage(unsigned, entryFor(unsigned, manifest), main.key, publicKeys);
  const signatureText = readZip(signed.bytes).get("pmmod/signature.minisig");
  const viaPm = packMod.attach(unsigned, signatureText);
  assert.ok(Buffer.from(viaPm).equals(signed.bytes), "attach and our writer produce different bytes");
  // And pack-mod's own reader takes our unsigned fixture as a package of its kind.
  assert.equal(packMod.verifyArchive(signed.bytes).kind, "signed");
});
