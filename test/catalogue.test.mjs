// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { entryFromManifest, withEntry } from "../scripts/add-entry.mjs";
import {
  appendedEntries,
  CATALOGUE_FIELDS,
  latestPerId,
  parseBlacklist,
  parseCatalogue,
  serializeBlacklist,
  serializeCatalogue,
} from "../scripts/lib/catalogue.mjs";
import { COMMIT, expectRefusal, manifestOf, sha256 } from "./helpers.mjs";

const entry = (over = {}) => ({
  id: "atlas.map",
  version: "1.0.0",
  tier: "first",
  author: "Atlas",
  repo: "itsAtlas-org/Personal-Manager",
  commit: COMMIT,
  path: "mods/atlas.map",
  unsignedSha256: sha256("x"),
  licence: "AGPL-3.0-or-later",
  ...over,
});
const text = (mods) => JSON.stringify({ format: 1, mods });

test("the committed catalogue and blacklist are valid and empty to begin with", () => {
  assert.deepEqual(parseCatalogue(readFileSync(new URL("../catalogue.json", import.meta.url), "utf8")), []);
  assert.deepEqual(parseBlacklist(readFileSync(new URL("../blacklist.json", import.meta.url), "utf8")), []);
});

test("a catalogue is parsed strictly and keeps one order", () => {
  const mods = [entry({ id: "acme.tools", tier: "second", author: "Acme", path: "tools" }), entry(), entry({ version: "1.1.0" })];
  const parsed = parseCatalogue(text(mods));
  assert.equal(parsed.length, 3);
  assert.deepEqual(Object.keys(parsed[0]), CATALOGUE_FIELDS);
  // Serialising sorts by id then semver precedence (1.10.0 after 1.9.0), and round-trips.
  const shuffled = [entry({ version: "1.10.0" }), entry({ version: "1.9.0" }), entry({ id: "acme.tools", tier: "second", author: "Acme", path: "tools" })];
  const out = serializeCatalogue(shuffled);
  assert.deepEqual(parseCatalogue(out).map((e) => `${e.id}@${e.version}`), ["acme.tools@1.0.0", "atlas.map@1.9.0", "atlas.map@1.10.0"]);
  assert.ok(out.endsWith("}\n"));
});

test("catalogue refusals", () => {
  const bad = (m, pattern) => expectRefusal(() => parseCatalogue(m), pattern);
  bad("not json", /not valid JSON/);
  bad("[]", /must be/);
  bad('{"format":1}', /must be/);
  bad('{"format":2,"mods":[]}', /unknown format/);
  bad('{"format":1,"mods":{}}', /list/);
  bad('{"format":1,"mods":[],"extra":1}', /must be/);
  bad('{"format":1,"format":1,"mods":[]}', /repeated/);
  for (const [, over, pattern] of [
    ["unknown field", { extra: "x" }, /unknown field/],
    ["bad id", { id: "Atlas.Map" }, /id/],
    ["device id", { id: "acme.con", tier: "second" }, /device/],
    ["version", { version: "v1.0.0" }, /version/],
    ["build metadata", { version: "1.0.0+1" }, /version/],
    ["tier mismatch", { tier: "second" }, /atlas/],
    ["third tier", { tier: "third" }, /first or second/],
    ["author padded", { author: " Atlas" }, /author/],
    ["repo", { repo: "itsAtlas-org" }, /repo/],
    ["short commit", { commit: "abc" }, /commit/],
    ["upper commit", { commit: COMMIT.toUpperCase() }, /commit/],
    ["zero commit", { commit: "0".repeat(40) }, /placeholder/],
    ["absolute path", { path: "/mods/x" }, /path/],
    ["dotdot path", { path: "mods/../x" }, /path/],
    ["odd path", { path: "mods/a b" }, /path/],
    ["sha", { unsignedSha256: "abc" }, /unsignedSha256/],
    ["licence", { licence: "MIT" }, /licence/],
    ["number", { version: 1 }, /text/],
  ]) {
    bad(text([entry(over)]), pattern);
  }
  const missing = entry();
  delete missing.path;
  bad(text([missing]), /no path/);
  bad(text([entry(), entry()]), /listed twice/);
  bad(text([entry({ version: "1.1.0" }), entry({ version: "1.0.0" })]), /out of order/);
  bad(text([entry({ id: "atlas.zed" }), entry({ id: "atlas.map" })]), /out of order/);
});

test("entries are append-only history", () => {
  const base = parseCatalogue(text([entry()]));
  const added = parseCatalogue(text([entry(), entry({ version: "1.1.0" })]));
  assert.deepEqual(appendedEntries(base, added).map((e) => e.version), ["1.1.0"]);
  assert.deepEqual(appendedEntries(base, base), []);
  expectRefusal(() => appendedEntries(added, base), /removed/);
  expectRefusal(() => appendedEntries(base, parseCatalogue(text([entry({ unsignedSha256: sha256("y") })]))), /changed/);
  expectRefusal(() => appendedEntries(base, parseCatalogue(text([entry({ commit: "1".repeat(40) })]))), /changed/);
});

test("the latest version of each id is what the index lists", () => {
  const all = parseCatalogue(text([entry({ version: "1.0.0" }), entry({ version: "1.2.0-rc.1" }), entry({ version: "1.9.0" }), entry({ version: "1.10.0" }), entry({ id: "atlas.pin", path: "mods/atlas.pin" })]));
  assert.deepEqual(latestPerId(all).map((e) => `${e.id}@${e.version}`), ["atlas.map@1.10.0", "atlas.pin@1.0.0"]);
});

test("the blacklist is parsed with the index's shapes and written in the index's key order", () => {
  const entries = [
    { reason: "It can lose your notes on sync.", action: "paused", versions: ">=1.0.0, <1.2.0", id: "acme.notes", fixedIn: "1.2.0" },
    { reason: "It sends your documents elsewhere.", action: "removed", sha256: "1".repeat(64) },
  ];
  const parsed = parseBlacklist(JSON.stringify({ format: 1, entries }));
  assert.deepEqual(Object.keys(parsed[0]), ["id", "versions", "action", "reason", "fixedIn"]);
  assert.deepEqual(Object.keys(parsed[1]), ["sha256", "action", "reason"]);
  assert.deepEqual(parseBlacklist(serializeBlacklist(parsed)), parsed);
  expectRefusal(() => parseBlacklist('{"format":1,"entries":[{"sha256":"abc","action":"paused","reason":"r"}]}'), /entry 1/);
  expectRefusal(() => parseBlacklist('{"format":1}'), /must be/);
  expectRefusal(() => parseBlacklist('{"format":1,"entries":[],"x":1}'), /must be/);
  expectRefusal(() => parseBlacklist(JSON.stringify({ format: 1, entries: Array(1001).fill(entries[1]) })), /too long/);
});

test("add-entry fills an entry from the pinned manifest and appends to the file", () => {
  const manifest = { ...manifestOf(), publisher: { ...manifestOf().publisher, commit: "0".repeat(40) } };
  const args = { id: "atlas.map", version: "1.1.0", commit: COMMIT, unsignedSha256: sha256("p"), repo: "itsAtlas-org/Personal-Manager", path: "mods/atlas.map" };
  const e = entryFromManifest(manifest, args);
  assert.deepEqual(Object.keys(e), CATALOGUE_FIELDS);
  assert.equal(e.tier, "first");
  assert.equal(e.author, "Atlas");
  const next = withEntry('{"format":1,"mods":[]}', e);
  assert.equal(parseCatalogue(next)[0].commit, COMMIT);
  expectRefusal(() => withEntry(next, e), /already in the catalogue/);
  expectRefusal(() => entryFromManifest(manifest, { ...args, id: "atlas.other" }), /manifest's id/);
  expectRefusal(() => entryFromManifest(manifest, { ...args, version: "2.0.0" }), /manifest's version/);
  expectRefusal(() => entryFromManifest(manifest, { ...args, repo: "acme/x" }), /sourceRepo/);
  expectRefusal(() => entryFromManifest(manifest, { ...args, unsignedSha256: "abc" }), /unsignedSha256/);
});
