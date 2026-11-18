// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared fixtures for the tests: ephemeral keys (made here, never saved), a small synthetic package, and
// the catalogue entry that pins it. Nothing here is a real key or a real mod.

import { createHash } from "node:crypto";

import { generateKey, loadSecretKey, parsePublicKey } from "../scripts/lib/minisign.mjs";
import { CHECKSUMS, writeZip } from "../scripts/lib/zip.mjs";

export const COMMIT = "0123456789abcdef0123456789abcdef01234567";
export const sha256 = (b) => createHash("sha256").update(b).digest("hex");

let cached = null;
/** A main and a rollover key, made once per test process, with a test password and cheap settings. */
export function ephemeralRing() {
  if (cached) return cached;
  const make = (role) => {
    const generated = generateKey({ password: "test-password" });
    const key = loadSecretKey(generated.secretBase64, "test-password");
    return { role, key, generated, pub: { ...parsePublicKey(generated.publicLine), role } };
  };
  const main = make("main");
  const rollover = make("rollover");
  cached = { main, rollover, publicKeys: [main.pub, rollover.pub] };
  return cached;
}

export const AGPL = "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n";

export function manifestOf(over = {}) {
  return {
    id: "atlas.map",
    name: "Document Map",
    description: "Your documents, laid out on one map.",
    version: "1.1.0",
    apiVersion: { min: "1.0", target: "1.0" },
    publisher: { tier: "first", author: "Atlas", sourceRepo: "itsAtlas-org/Personal-Manager", commit: COMMIT },
    licence: "AGPL-3.0-or-later",
    permissions: [
      { id: "ui.tab", why: "Adds the Map tab." },
      { id: "documents.meta", why: "Lays out your documents." },
    ],
    entry: { page: "app/index.html" },
    ...over,
  };
}

/** checksums.json as pack-mod.mjs writes it (two-space JSON, LF at the end). */
export function checksumsFor(files) {
  const list = [...files.keys()]
    .filter((p) => !p.startsWith("pmmod/"))
    .sort()
    .map((path) => ({ path, sha256: sha256(files.get(path)) }));
  return Buffer.from(`${JSON.stringify({ format: 1, files: list }, null, 2)}\n`);
}

/** A pre-sign package (what pack-mod.mjs writes before signing). `files` replaces/extends the defaults. */
export function unsignedPackage({ manifest = manifestOf(), files = {}, raw = {} } = {}) {
  const entries = new Map([
    ["manifest.json", Buffer.from(JSON.stringify(manifest, null, 2))],
    ["LICENCE.txt", Buffer.from(AGPL)],
    ["NOTICE.txt", Buffer.from("notice\n")],
    ["app/index.html", Buffer.from("<!doctype html><html><head><meta charset=\"utf-8\"><title>t</title></head><body>hi</body></html>\n")],
  ]);
  for (const [k, v] of Object.entries(files)) {
    if (v === null) entries.delete(k);
    else entries.set(k, Buffer.from(v));
  }
  entries.set(CHECKSUMS, checksumsFor(entries));
  for (const [k, v] of Object.entries(raw)) entries.set(k, Buffer.from(v)); // after the checksums, so these can disagree
  return writeZip(entries);
}

/** The catalogue entry that pins `bytes` and its manifest. */
export function entryFor(bytes, manifest = manifestOf(), over = {}) {
  return {
    id: manifest.id,
    version: manifest.version,
    tier: manifest.publisher.tier,
    author: manifest.publisher.author,
    repo: manifest.publisher.sourceRepo,
    commit: manifest.publisher.commit,
    path: `mods/${manifest.id}`,
    unsignedSha256: sha256(bytes),
    licence: "AGPL-3.0-or-later",
    ...over,
  };
}

export function expectRefusal(fn, pattern, code) {
  let thrown = null;
  try {
    fn();
  } catch (e) {
    thrown = e;
  }
  if (!thrown) throw new Error("expected a refusal, none thrown");
  if (pattern && !pattern.test(thrown.message)) throw new Error(`refusal ${JSON.stringify(thrown.message)} doesn't match ${pattern}`);
  if (code && thrown.code !== code) throw new Error(`refusal code ${thrown.code}, wanted ${code} (${thrown.message})`);
  return thrown;
}
