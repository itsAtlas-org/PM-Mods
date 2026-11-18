// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// minisign, as far as PM needs it, with node:crypto only: read an encrypted secret key (the kind
// `npx tauri signer generate` writes, rsign2's layout), sign PREHASHED ("ED") with a trusted comment,
// and verify a signature the way PM's check_minisign does (package.rs). `tauri signer sign` cannot be
// used: it writes a fixed trusted comment (`timestamp:...file:...`), and PM needs `pmmod:1` / `pmindex:1`.
//
// A key file's second line is base64 of 158 bytes:
//   "Ed" sig alg, "Sc" kdf (scrypt), "B2" checksum alg, salt 32, opslimit u64 LE, memlimit u64 LE,
//   then 104 encrypted bytes = key id 8 + secret key 64 (Ed25519 seed 32 + public 32) + checksum 32,
//   where checksum = BLAKE2b-256(sig alg + key id + secret key).
// The stream that encrypts them is libsodium's crypto_pwhash_scryptsalsa208sha256 output, i.e. scrypt
// with N/r/p picked from opslimit/memlimit by libsodium's `pickparams` (below).
//
// A signature file is four LF-ended lines:
//   untrusted comment: <text>
//   base64("ED" + key id 8 + Ed25519(BLAKE2b-512(message)) 64)
//   trusted comment: <text>
//   base64(Ed25519(signature 64 + trusted comment bytes) 64)

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  scryptSync,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";

import { quote, refuse } from "./rules.mjs";

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const KEY_BLOB = 158;
const MAX_SCRYPT_BYTES = 2 ** 31; // 128 * N * r: refuse a key file that asks a runner for more than 2 GiB

// ---- Key ids and base64 -----------------------------------------------------------------------------

/** 16 uppercase hex digits of the 8 key-id bytes read little-endian (keys.rs `KeyId`). */
export function keyIdText(bytes8) {
  return Buffer.from(bytes8).readBigUInt64LE(0).toString(16).toUpperCase().padStart(16, "0");
}

/** A strict base64 line: canonical alphabet and padding, so two spellings can't decode alike. */
export function decodeBase64Strict(line, what = "base64") {
  if (typeof line !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(line) || line.length % 4 !== 0) {
    refuse(`${what} isn't base64`, "malformed");
  }
  const bytes = Buffer.from(line, "base64");
  if (bytes.toString("base64") !== line) refuse(`${what} isn't canonical base64`, "malformed");
  return bytes;
}

// ---- BLAKE2b with a chosen digest length (node:crypto offers 512 only) ------------------------------

const M64 = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

/** Unkeyed BLAKE2b (RFC 7693) with a digest of `outLength` bytes (1..64). */
export function blake2b(data, outLength) {
  if (!Number.isInteger(outLength) || outLength < 1 || outLength > 64) {
    throw new RangeError("a BLAKE2b digest is 1 to 64 bytes");
  }
  const input = Buffer.from(data);
  const h = IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLength);
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let b = 0; b < blocks; b++) {
    const block = Buffer.alloc(128);
    input.copy(block, 0, b * 128, Math.min(input.length, (b + 1) * 128));
    const m = Array.from({ length: 16 }, (_, i) => block.readBigUInt64LE(i * 8));
    const last = b === blocks - 1;
    const t = BigInt(last ? input.length : (b + 1) * 128);
    const v = [...h, ...IV];
    v[12] ^= t & M64;
    v[13] ^= t >> 64n;
    if (last) v[14] ^= M64;
    const g = (a, bb, c, d, x, y) => {
      v[a] = (v[a] + v[bb] + x) & M64;
      v[d] = rotr(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & M64;
      v[bb] = rotr(v[bb] ^ v[c], 24n);
      v[a] = (v[a] + v[bb] + y) & M64;
      v[d] = rotr(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & M64;
      v[bb] = rotr(v[bb] ^ v[c], 63n);
    };
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      g(0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = Buffer.alloc(64);
  h.forEach((word, i) => out.writeBigUInt64LE(word, i * 8));
  return out.subarray(0, outLength);
}

// ---- The password stream (libsodium pickparams) -----------------------------------------------------

/** libsodium `pickparams`: scrypt N (as log2), r and p for an opslimit and a memlimit (BigInt maths). */
export function pickParams(opslimitIn, memlimitIn) {
  let opslimit = BigInt(opslimitIn);
  const memlimit = BigInt(memlimitIn);
  if (opslimit < 32768n) opslimit = 32768n;
  const r = 8n;
  const smallestLog2 = (maxN) => {
    let n = 1n;
    while (n < 63n && !(1n << n > maxN / 2n)) n += 1n;
    return n;
  };
  let nLog2;
  let p;
  if (opslimit < memlimit / 32n) {
    p = 1n;
    nLog2 = smallestLog2(opslimit / (r * 4n));
  } else {
    nLog2 = smallestLog2(memlimit / (r * 128n));
    let maxrp = opslimit / 4n / (1n << nLog2);
    if (maxrp > 0x3fffffffn) maxrp = 0x3fffffffn;
    p = maxrp / r;
  }
  return { N: 2 ** Number(nLog2), nLog2: Number(nLog2), r: Number(r), p: Number(p) };
}

function passwordStream(password, salt, opslimit, memlimit, length) {
  const { N, r, p } = pickParams(opslimit, memlimit);
  if (p < 1 || 128 * N * r > MAX_SCRYPT_BYTES) {
    refuse("the key file asks for key-derivation settings this signer won't run", "malformed");
  }
  return scryptSync(Buffer.from(password, "utf8"), salt, length, {
    N,
    r,
    p,
    maxmem: 128 * N * r * 2 + (1 << 20),
  });
}

// ---- Keys -------------------------------------------------------------------------------------------

const publicKeyObject = (raw32) =>
  createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: "der", type: "spki" });
const privateKeyObject = (seed32) =>
  createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed32]), format: "der", type: "pkcs8" });
const rawPublicOf = (privateKey) =>
  createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);

/** A public key from the base64 line a `.pub` file's second line holds (42 bytes, "Ed" + id + key). */
export function parsePublicKey(base64) {
  const bytes = decodeBase64Strict(base64, "a public key");
  if (bytes.length !== 42) refuse("a public key is 42 bytes", "malformed");
  const alg = bytes.subarray(0, 2).toString("latin1");
  if (alg !== "Ed" && alg !== "ED") refuse("a public key must use the Ed25519 algorithm", "malformed");
  const raw = Buffer.from(bytes.subarray(10));
  const idBytes = Buffer.from(bytes.subarray(2, 10));
  return {
    base64,
    idBytes,
    id: keyIdText(idBytes),
    raw,
    object: publicKeyObject(raw),
  };
}

/** Accept the secret as the Tauri CLI writes it (base64 of the minisign text) or as the text itself. */
export function secretKeyLines(secret) {
  let text = String(secret).trim();
  if (!text.startsWith("untrusted comment:")) {
    try {
      text = decodeBase64Strict(text.replace(/\s+/g, ""), "the key file").toString("utf8");
    } catch {
      refuse("the key file is neither minisign text nor base64 of it", "malformed");
    }
  }
  const lines = text.split(/\r?\n/).filter((l, i, all) => !(l === "" && i === all.length - 1));
  if (lines.length !== 2 || !lines[0].startsWith("untrusted comment:")) {
    refuse("the key file isn't a minisign secret key (two lines)", "malformed");
  }
  return lines;
}

/**
 * Decrypt an rsign2/minisign secret key. Returns {idBytes, id, seed, raw (public), privateKey}. Fails
 * with a plain message on a wrong password (the checksum), a damaged file, or a key whose stored
 * public half isn't what its seed gives.
 */
export function loadSecretKey(secret, password) {
  const blob = decodeBase64Strict(secretKeyLines(secret)[1], "the secret key");
  if (blob.length !== KEY_BLOB) refuse("the secret key isn't 158 bytes", "malformed");
  const alg = blob.subarray(0, 6).toString("latin1");
  if (alg !== "EdScB2") {
    refuse(
      `the secret key uses ${quote(alg)}, not Ed + Sc (scrypt) + B2 (BLAKE2b): only an encrypted rsign2 key is read`,
      "malformed",
    );
  }
  const salt = blob.subarray(6, 38);
  const opslimit = blob.readBigUInt64LE(38);
  const memlimit = blob.readBigUInt64LE(46);
  const stream = passwordStream(password, salt, opslimit, memlimit, 104);
  const plain = Buffer.alloc(104);
  for (let i = 0; i < 104; i++) plain[i] = blob[54 + i] ^ stream[i];
  const idBytes = plain.subarray(0, 8);
  const sk = plain.subarray(8, 72);
  const checksum = plain.subarray(72, 104);
  const expected = blake2b(Buffer.concat([blob.subarray(0, 2), idBytes, sk]), 32);
  if (!expected.equals(checksum)) {
    refuse("the key's checksum is wrong: the password is wrong, or the key file is damaged", "password");
  }
  const seed = Buffer.from(sk.subarray(0, 32));
  const privateKey = privateKeyObject(seed);
  const raw = Buffer.from(rawPublicOf(privateKey));
  if (!raw.equals(sk.subarray(32))) refuse("the key's public half isn't the one its secret gives", "malformed");
  return { idBytes: Buffer.from(idBytes), id: keyIdText(idBytes), seed, raw, privateKey };
}

/** The `.pub` line (base64 of "Ed" + id + key) for a loaded key. */
export const publicKeyLine = (key) =>
  Buffer.concat([Buffer.from("Ed"), key.idBytes, key.raw]).toString("base64");

/**
 * A new key, in rsign2's layout. For TESTS and local rehearsals only (the real keys come from
 * `tauri signer generate`). Defaults to the settings the Tauri CLI writes (32 MiB, N = 32768).
 */
export function generateKey({
  password,
  opslimit = 1048576,
  memlimit = 33554432,
  idBytes = randomBytes(8),
} = {}) {
  if (typeof password !== "string") throw new TypeError("a password is needed");
  const seed = randomBytes(32);
  const privateKey = privateKeyObject(seed);
  const raw = Buffer.from(rawPublicOf(privateKey));
  const sk = Buffer.concat([seed, raw]);
  const salt = randomBytes(32);
  const checksum = blake2b(Buffer.concat([Buffer.from("Ed"), idBytes, sk]), 32);
  const plain = Buffer.concat([idBytes, sk, checksum]);
  const stream = passwordStream(password, salt, opslimit, memlimit, 104);
  const encrypted = Buffer.alloc(104);
  for (let i = 0; i < 104; i++) encrypted[i] = plain[i] ^ stream[i];
  const head = Buffer.alloc(54);
  head.write("EdScB2", 0, "latin1");
  salt.copy(head, 6);
  head.writeBigUInt64LE(BigInt(opslimit), 38);
  head.writeBigUInt64LE(BigInt(memlimit), 46);
  const keyText = `untrusted comment: rsign encrypted secret key\n${Buffer.concat([head, encrypted]).toString("base64")}\n`;
  const key = { idBytes: Buffer.from(idBytes), id: keyIdText(idBytes), seed, raw, privateKey };
  const publicLine = publicKeyLine(key);
  return {
    id: key.id,
    secretText: keyText,
    // What `tauri signer generate` stores in the secret: base64 of the minisign text.
    secretBase64: Buffer.from(keyText).toString("base64"),
    publicLine,
    publicText: `untrusted comment: minisign public key: ${key.id}\n${publicLine}\n`,
  };
}

// ---- Signing ----------------------------------------------------------------------------------------

/** A comment goes on one line: a tab is allowed (PM's trusted comments use them), no other control. */
function checkComment(text, what, allowTab) {
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (/\p{Cc}/u.test(ch) && !(allowTab && ch === "\t")) {
      refuse(`${what} has a control character (U+${cp.toString(16).toUpperCase().padStart(4, "0")})`);
    }
  }
}

/** A minisign signature file, prehashed, over `message`; the trusted comment is covered by the signature. */
export function signPrehashed(key, message, trustedComment, untrustedComment = "signature from Atlas mod key") {
  checkComment(trustedComment, "the trusted comment", true);
  checkComment(untrustedComment, "the untrusted comment", false);
  const prehash = createHash("blake2b512").update(message).digest();
  const sig = edSign(null, prehash, key.privateKey);
  const global = edSign(null, Buffer.concat([sig, Buffer.from(trustedComment, "utf8")]), key.privateKey);
  const line2 = Buffer.concat([Buffer.from("ED"), key.idBytes, sig]).toString("base64");
  return Buffer.from(
    `untrusted comment: ${untrustedComment}\n${line2}\ntrusted comment: ${trustedComment}\n${global.toString("base64")}\n`,
    "utf8",
  );
}

// ---- Verifying (package.rs `check_minisign`) --------------------------------------------------------

/** Rust's `str::lines`: split on LF, drop a CR before it, and no empty last line after a final LF. */
const rustLines = (text) => {
  const lines = text.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
};

/**
 * Check `signature` over `message` against any of `publicKeys` (from parsePublicKey): prehashed only.
 * Returns {index, key, trustedComment, signatureBytes}. Throws a Refusal whose `code` is one of
 * malformed, legacy, untrusted-key, bad-signature, the same four faults PM tells apart.
 */
export function verifySignature(message, signature, publicKeys) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(signature);
  } catch {
    refuse("the signature isn't UTF-8", "malformed");
  }
  const lines = rustLines(text);
  if (lines.length !== 4) refuse("the signature isn't minisign's four lines", "malformed");
  if (!lines[2].startsWith("trusted comment: ")) refuse("no trusted comment", "malformed");
  const bin1 = decodeBase64Strict(lines[1], "the signature");
  const bin2 = decodeBase64Strict(lines[3], "the global signature");
  if (bin1.length !== 74 || bin2.length !== 64) refuse("the signature has the wrong length", "malformed");
  const alg = bin1.subarray(0, 2).toString("latin1");
  if (alg !== "Ed" && alg !== "ED") refuse("the signature uses an unknown algorithm", "malformed");
  const keyId = bin1.subarray(2, 10);
  const sig = bin1.subarray(10);
  const trustedComment = lines[2].slice("trusted comment: ".length);

  let idMatched = false;
  for (let index = 0; index < publicKeys.length; index++) {
    const key = publicKeys[index];
    if (!key.idBytes.equals(keyId)) continue;
    if (alg === "Ed") refuse("the signature uses minisign's legacy mode, which PM refuses", "legacy");
    idMatched = true;
    const prehash = createHash("blake2b512").update(message).digest();
    const global = Buffer.concat([sig, Buffer.from(trustedComment, "utf8")]);
    if (edVerify(null, prehash, key.object, sig) && edVerify(null, global, key.object, bin2)) {
      return { index, key, trustedComment, signatureBytes: Buffer.from(sig) };
    }
  }
  if (idMatched) refuse("the signature doesn't verify", "bad-signature");
  refuse("the signature isn't by a key that is trusted here", "untrusted-key");
}
