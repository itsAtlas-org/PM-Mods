// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { ATLAS_MOD_KEYS, pinnedPublicKeys } from "../scripts/lib/keys.mjs";
import {
  blake2b,
  generateKey,
  keyIdText,
  loadSecretKey,
  parsePublicKey,
  pickParams,
  signPrehashed,
  verifySignature,
} from "../scripts/lib/minisign.mjs";
import { expectRefusal, ephemeralRing } from "./helpers.mjs";

test("BLAKE2b with a chosen length equals node's blake2b512 at 512 bits", () => {
  for (const n of [0, 1, 127, 128, 129, 255, 256, 300, 1000]) {
    const data = Buffer.alloc(n, 7);
    assert.equal(blake2b(data, 64).toString("hex"), createHash("blake2b512").update(data).digest("hex"), `length ${n}`);
  }
  // Short digests are not prefixes of the long one (the length is in the parameter block): known vector.
  assert.equal(
    blake2b(Buffer.from("abc"), 32).toString("hex"),
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  );
  assert.throws(() => blake2b(Buffer.alloc(1), 0));
  assert.throws(() => blake2b(Buffer.alloc(1), 65));
});

test("pickParams matches libsodium for the two settings in the wild", () => {
  // `tauri signer generate` (opslimit 1048576, memlimit 32 MiB) and minisign's default (32 MiB ops, 1 GiB).
  assert.deepEqual(pickParams(1048576, 33554432), { N: 32768, nLog2: 15, r: 8, p: 1 });
  assert.deepEqual(pickParams(33554432, 1073741824), { N: 1048576, nLog2: 20, r: 8, p: 1 });
  // Below the floor, opslimit is raised to 32768: N = 2^11 by the "ops < mem/32" branch.
  assert.equal(pickParams(1, 33554432).p, 1);
  assert.equal(pickParams(1, 33554432).r, 8);
});

test("key ids print as 16 uppercase hex digits of the little-endian bytes", () => {
  assert.equal(keyIdText(Buffer.from([0x7b, 0x51, 0x4d, 0x06, 0x57, 0x34, 0xb8, 0x95])), "95B83457064D517B");
  assert.equal(keyIdText(Buffer.from([1, 0, 0, 0, 0, 0, 0, 0])), "0000000000000001");
});

test("the pinned Atlas keys decode (42 bytes, Ed) to the ids the table names", () => {
  for (const k of ATLAS_MOD_KEYS) {
    const parsed = parsePublicKey(k.public);
    assert.equal(parsed.id, k.id);
    assert.equal(parsed.raw.length, 32);
  }
  assert.deepEqual(
    pinnedPublicKeys().map((k) => [k.role, k.id]),
    [["main", "95B83457064D517B"], ["rollover", "993CE0152A3E4E8C"]],
  );
});

test("a generated key round-trips through the encrypted layout, as text or as base64", () => {
  const g = generateKey({ password: "pw" });
  for (const form of [g.secretText, g.secretBase64, `${g.secretBase64}\n`]) {
    const key = loadSecretKey(form, "pw");
    assert.equal(key.id, g.id);
    assert.equal(parsePublicKey(g.publicLine).id, key.id);
    assert.ok(key.raw.equals(parsePublicKey(g.publicLine).raw));
  }
});

test("a wrong password, a damaged key and an unknown layout are refused plainly", () => {
  const g = generateKey({ password: "pw" });
  expectRefusal(() => loadSecretKey(g.secretText, "PW"), /password is wrong/, "password");
  expectRefusal(() => loadSecretKey(g.secretText, ""), /password is wrong/, "password");
  // Flip one byte of the encrypted part: the checksum catches it.
  const lines = g.secretText.split("\n");
  const blob = Buffer.from(lines[1], "base64");
  blob[100] ^= 1;
  expectRefusal(() => loadSecretKey(`${lines[0]}\n${blob.toString("base64")}\n`, "pw"), /checksum is wrong/);
  // An unencrypted-looking or other-algorithm key.
  const other = Buffer.from(lines[1], "base64");
  other.write("EdB2B2", 0, "latin1");
  expectRefusal(() => loadSecretKey(`${lines[0]}\n${other.toString("base64")}\n`, "pw"), /only an encrypted rsign2 key/);
  expectRefusal(() => loadSecretKey("not a key", "pw"));
  expectRefusal(() => loadSecretKey(`${lines[0]}\n${lines[1]}\nextra\n`, "pw"), /two lines/);
  const short = Buffer.from(lines[1], "base64").subarray(0, 100);
  expectRefusal(() => loadSecretKey(`${lines[0]}\n${short.toString("base64")}\n`, "pw"), /158 bytes/);
});

test("a key file that asks for absurd scrypt settings is refused, not run", () => {
  const g = generateKey({ password: "pw" });
  const lines = g.secretText.split("\n");
  const blob = Buffer.from(lines[1], "base64");
  blob.writeBigUInt64LE(1n << 40n, 38);
  blob.writeBigUInt64LE(1n << 40n, 46);
  expectRefusal(() => loadSecretKey(`${lines[0]}\n${blob.toString("base64")}\n`, "pw"), /won't run/);
});

test("signatures: four lines, prehashed, verified with the key, covering the trusted comment", () => {
  const { main } = ephemeralRing();
  const message = Buffer.from("hello checksums");
  const sig = signPrehashed(main.key, message, "pmmod:1\tid:x");
  const text = sig.toString("utf8");
  const lines = text.split("\n");
  assert.equal(lines.length, 5);
  assert.equal(lines[4], "");
  assert.match(lines[0], /^untrusted comment: /);
  assert.equal(Buffer.from(lines[1], "base64").length, 74);
  assert.equal(Buffer.from(lines[1], "base64").subarray(0, 2).toString(), "ED");
  assert.equal(lines[2], "trusted comment: pmmod:1\tid:x");
  assert.equal(Buffer.from(lines[3], "base64").length, 64);
  const ok = verifySignature(message, sig, [main.pub]);
  assert.equal(ok.trustedComment, "pmmod:1\tid:x");
  assert.equal(ok.index, 0);
  // Ed25519 is deterministic: the same inputs give the same bytes.
  assert.ok(sig.equals(signPrehashed(main.key, message, "pmmod:1\tid:x")));
});

test("tampering with the message, the comment or the signature is refused", () => {
  const { main, rollover } = ephemeralRing();
  const message = Buffer.from("m");
  const sig = signPrehashed(main.key, message, "c");
  expectRefusal(() => verifySignature(Buffer.from("n"), sig, [main.pub]), /doesn't verify/, "bad-signature");
  const text = sig.toString();
  expectRefusal(() => verifySignature(message, Buffer.from(text.replace("trusted comment: c", "trusted comment: d")), [main.pub]), null, "bad-signature");
  const lines = text.split("\n");
  const sigBytes = Buffer.from(lines[1], "base64");
  sigBytes[20] ^= 1;
  lines[1] = sigBytes.toString("base64");
  expectRefusal(() => verifySignature(message, Buffer.from(lines.join("\n")), [main.pub]), null, "bad-signature");
  // A key that isn't trusted here.
  expectRefusal(() => verifySignature(message, sig, [rollover.pub]), /isn't by a key/, "untrusted-key");
  // Either trusted key may sign; the index of the signer says which.
  const bySecond = signPrehashed(rollover.key, message, "c");
  assert.equal(verifySignature(message, bySecond, [main.pub, rollover.pub]).index, 1);
});

test("malformed signature files are refused the way PM refuses them", () => {
  const { main } = ephemeralRing();
  const message = Buffer.from("m");
  const good = signPrehashed(main.key, message, "c").toString();
  const check = (text, code = "malformed") => expectRefusal(() => verifySignature(message, Buffer.from(text), [main.pub]), null, code);
  check(`${good}extra line\n`);
  check(good.split("\n").slice(0, 3).join("\n") + "\n");
  check(good.replace("\ntrusted comment: ", "\nTrusted comment: "));
  check("");
  // CRLF endings are read as Rust's lines() reads them.
  assert.ok(verifySignature(message, Buffer.from(good.replace(/\n/g, "\r\n")), [main.pub]));
  // Legacy (non-prehashed) mode: "Ed" instead of "ED", refused when the key id matches.
  const lines = good.split("\n");
  const raw = Buffer.from(lines[1], "base64");
  raw.write("Ed", 0, "latin1");
  lines[1] = raw.toString("base64");
  check(lines.join("\n"), "legacy");
  raw.write("XX", 0, "latin1");
  lines[1] = raw.toString("base64");
  check(lines.join("\n"));
  // Not UTF-8; not canonical base64.
  expectRefusal(() => verifySignature(message, Buffer.from([0xff, 0xfe]), [main.pub]), null, "malformed");
  const line1 = good.split("\n")[1];
  check(good.replace(line1, `${line1}=`));
});

test("a trusted comment with a control character, or an untrusted one with a tab, can't be signed", () => {
  const { main } = ephemeralRing();
  for (const bad of ["a\nb", "a\rb", "a\u0000b", "a\u007fb"]) {
    expectRefusal(() => signPrehashed(main.key, Buffer.from("m"), bad), /control character/);
  }
  assert.ok(signPrehashed(main.key, Buffer.from("m"), "a\tb"));
  expectRefusal(() => signPrehashed(main.key, Buffer.from("m"), "c", "a\tb"), /control character/);
});
