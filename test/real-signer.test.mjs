// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Evidence from a REAL signer, not from this repo's own generator (which shares its layout code with the
// loader, so a consistent mistake would pass every test that uses only it).
//
//  1. Committed vectors (test/vectors/tauri-signer*): a throwaway key made by `npx tauri signer generate`,
//     a file signed by `npx tauri signer sign`, and a package signed here with that key. Only the PUBLIC
//     key and signatures are committed; the secret key was destroyed (no secret is ever committed).
//  2. TAURI_CLI=/path/to/tauri (a Tauri CLI, e.g. node_modules/.bin/tauri in a PM checkout): the same,
//     live. Generates a fresh throwaway key in a scratch folder, checks loadSecretKey decrypts it (id and
//     public half match what the CLI wrote) and that a signature the CLI makes verifies. Skipped without it.
//     Run it whenever lib/minisign.mjs changes; sign.mjs --key-check-only is the same proof for the real key.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { pinnedPublicKeys } from "../scripts/lib/keys.mjs";
import { loadSecretKey, parsePublicKey, signPrehashed, verifySignature } from "../scripts/lib/minisign.mjs";
import { verifyPackage } from "../scripts/lib/package.mjs";
import { SIGNATURE, readZip, writeZip } from "../scripts/lib/zip.mjs";
import { expectRefusal, sha256 } from "./helpers.mjs";

const vec = (name) => readFileSync(fileURLToPath(new URL(`./vectors/${name}`, import.meta.url)));
/** The key line of a Tauri `.pub` file (base64 of a two-line minisign public key file). */
const tauriPub = (file) => parsePublicKey(Buffer.from(file.toString().trim(), "base64").toString().split("\n")[1]);

test("a file signed by `tauri signer sign` verifies under the key `tauri signer generate` wrote", () => {
  const pub = tauriPub(vec("tauri-signer.pub"));
  assert.equal(pub.id, "C68FD30F1B8A179B");
  const message = vec("tauri-signer-message.txt");
  const signature = Buffer.from(vec("tauri-signer-message.txt.sig").toString().trim(), "base64");
  const ok = verifySignature(message, signature, [pub]);
  assert.match(ok.trustedComment, /^timestamp:\d+\tfile:msg\.txt$/, "Tauri's own trusted comment");
  // Any change to the message, the signature or the key is refused.
  expectRefusal(() => verifySignature(Buffer.from("other"), signature, [pub]), /doesn't verify/, "bad-signature");
  const flipped = Buffer.from(signature);
  flipped[flipped.indexOf("RUS") + 12] ^= 1;
  expectRefusal(() => verifySignature(message, flipped, [pub]));
  expectRefusal(() => verifySignature(message, signature, pinnedPublicKeys()), /isn't by a key that is trusted here/, "untrusted-key");
});

test("a package signed with that real key verifies, reads back its facts, and is the pinned bytes without its signature", () => {
  const pub = { ...tauriPub(vec("tauri-signer.pub")), role: "main" };
  const bytes = vec("tauri-signer-package.bin");
  const v = verifyPackage(bytes, [pub]);
  assert.equal(v.facts.id, "atlas.map");
  assert.equal(v.facts.version, "1.1.0");
  assert.equal(v.signer.id, "C68FD30F1B8A179B");
  assert.equal(v.sha256, sha256(bytes));
  // Signing is deterministic and only adds one entry: take it out and the pre-sign bytes come back.
  const entries = readZip(bytes);
  entries.delete(SIGNATURE);
  assert.equal(sha256(writeZip(entries)), "b1ccddcf16b3578253754bd6b3dc5b0cc3e0142282b7744fc37fd84557de0de6");
  // Not trusted by the Atlas keys, and one flipped byte in the checksums is refused.
  expectRefusal(() => verifyPackage(bytes, pinnedPublicKeys()), /trusted/);
  const bad = Buffer.from(bytes);
  bad[bad.length - 200] ^= 1;
  assert.throws(() => verifyPackage(bad, [pub]));
});

const cli = process.env.TAURI_CLI;
const scratchDirs = [];
after(() => scratchDirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

test("a key made by the live Tauri CLI decrypts here, and its signatures verify (needs TAURI_CLI)", { skip: !cli }, () => {
  // On disk under ~/.cache, not in /tmp (tmpfs); deleted afterwards.
  const dir = mkdtempSync(join(homedir(), ".cache", "pm-mods-tauri-"));
  scratchDirs.push(dir);
  const run = (args, env = {}) => execFileSync(cli, args, { env: { PATH: process.env.PATH, ...env }, cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  run(["signer", "generate", "--ci", "-w", "t.key", "-p", "test-password"]);
  const keyText = readFileSync(join(dir, "t.key"), "utf8");
  const pub = tauriPub(readFileSync(join(dir, "t.key.pub")));
  const key = loadSecretKey(keyText, "test-password");
  assert.equal(key.id, pub.id);
  assert.ok(key.raw.equals(pub.raw), "the decrypted key's public half is the one the CLI wrote");
  expectRefusal(() => loadSecretKey(keyText, "wrong"), /password is wrong/, "password");
  // What the CLI signs verifies here...
  writeFileSync(join(dir, "m.txt"), "live signer message\n");
  run(["signer", "sign", "m.txt"], { TAURI_SIGNING_PRIVATE_KEY_PATH: join(dir, "t.key"), TAURI_SIGNING_PRIVATE_KEY_PASSWORD: "test-password" });
  const sig = Buffer.from(readFileSync(join(dir, "m.txt.sig"), "utf8").trim(), "base64");
  verifySignature(readFileSync(join(dir, "m.txt")), sig, [pub]);
  // ...and what we sign with the decrypted key verifies under the same public key.
  const mine = signPrehashed(key, Buffer.from("x"), "pmkeycheck:1");
  assert.equal(verifySignature(Buffer.from("x"), mine, [pub]).trustedComment, "pmkeycheck:1");
});
