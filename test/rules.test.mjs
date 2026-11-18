// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  blacklistEntryFault,
  compareVersions,
  INDEX_SIGNATURE_URL,
  INDEX_URL,
  modIdFault,
  packageUrl,
  parseTime,
  parseVersionName,
  parseVersionRange,
  PERMISSIONS,
  plainTextFault,
  tierFault,
  timeText,
} from "../scripts/lib/rules.mjs";
import { ATLAS_MOD_KEYS } from "../scripts/lib/keys.mjs";

const SHA = "a".repeat(64);

test("mod ids: two to five lowercase parts, no device names", () => {
  for (const good of ["atlas.map", "acme.notes-2", "a.b.c.d.e", "acme.x".padEnd(6, "x")]) assert.equal(modIdFault(good), null, good);
  for (const bad of ["atlas", "Atlas.Map", "acme.con", "acme.com1", "acme.nul.txt", "a.b.c.d.e.f", "acme.", ".acme", "acme..x", "1acme.x", "acme.x_y", `acme.${"x".repeat(32)}`, "acme.-x"]) {
    assert.notEqual(modIdFault(bad), null, bad);
  }
  assert.equal(modIdFault(5), "isn't text");
});

test("tiers: atlas. is first party's and only first party publishes there", () => {
  assert.equal(tierFault("atlas.map", "first"), null);
  assert.equal(tierFault("acme.tools", "second"), null);
  assert.notEqual(tierFault("atlas.map", "second"), null);
  assert.notEqual(tierFault("acme.tools", "first"), null);
  assert.notEqual(tierFault("acme.tools", "third"), null);
});

test("version names are canonical lowercase semver without build metadata", () => {
  for (const good of ["0.0.0", "1.2.3", "1.2.3-rc.1", "1.0.0-alpha", "10.20.30", "1.0.0-0", "1.0.0-x-y.z"]) assert.ok(parseVersionName(good), good);
  for (const bad of ["1.2", "v1.2.3", "01.2.3", "1.2.3+b", "1.2.3-RC1", "1.2.3-01", "1.2.3-", "1.2.3-a..b", " 1.2.3", "1.2.3 ", "1.2.3-é", `1.0.0-${"a".repeat(60)}`, "", 5]) {
    assert.equal(parseVersionName(bad), null, String(bad));
  }
});

test("semver precedence follows the semver crate", () => {
  const ascending = ["0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0"];
  for (let i = 0; i < ascending.length; i++) {
    for (let j = 0; j < ascending.length; j++) {
      assert.equal(Math.sign(compareVersions(ascending[i], ascending[j])), Math.sign(i - j), `${ascending[i]} vs ${ascending[j]}`);
    }
  }
  assert.equal(compareVersions("1.0.0-9", "1.0.0-a"), -1, "numeric identifiers sort below alphanumeric ones");
  assert.equal(compareVersions("99999999999999999.0.0", "99999999999999998.0.0"), 1, "beyond 2^53 exactly");
});

test("version ranges: PM's small strict grammar (table copied from index.rs)", () => {
  for (const bad of ["", " ", "1.0.0", "^1.0.0", "~1.0.0", "1.*", ">=1.0", ">=1.0.0,<2.0.0", "<2.0.0, >=1.0.0", ">=2.0.0, <1.0.0", ">=1.0.0, <1.0.0", ">=1.0.0, >1.1.0", "<1.0.0, <2.0.0", ">=1.0.0, <2.0.0, <3.0.0", "=1.0.0, <2.0.0", ">= 1.0.0", ">=V1.0.0", ">=1.0.0-RC1", ">=1.0.0+b", "* ", "**"]) {
    assert.equal(parseVersionRange(bad), null, JSON.stringify(bad));
  }
  for (const good of ["*", "=1.1.0", ">1.0.0", "<=2.0.0", "<2.0.0", ">=1.0.0", ">=1.0.0, <1.2.0", ">1.0.0, <=1.0.1"]) assert.ok(parseVersionRange(good), good);
});

function entryFault(e) {
  return blacklistEntryFault(e);
}

test("blacklist entries: one shape each (table copied from index.rs)", () => {
  const sha = SHA;
  const base = { action: "paused", reason: "r" };
  for (const [what, bad] of [
    ["id without versions", { id: "acme.x", ...base }],
    ["versions without id", { versions: "*", ...base }],
    ["both kinds", { id: "acme.x", versions: "*", sha256: sha, ...base }],
    ["id and sha", { id: "acme.x", sha256: sha, ...base }],
    ["neither", base],
    ["bad id", { id: "ACME.x", versions: "*", ...base }],
    ["bad sha", { sha256: "abc", ...base }],
    ["action", { sha256: sha, action: "deleted", reason: "r" }],
    ["empty reason", { sha256: sha, action: "paused", reason: "" }],
    ["two-line reason", { sha256: sha, action: "paused", reason: "a\nb" }],
    ["long reason", { sha256: sha, action: "paused", reason: "r".repeat(281) }],
    ["removed with a fix", { sha256: sha, action: "removed", reason: "r", fixedIn: "2.0.0" }],
    ["bad fix", { sha256: sha, ...base, fixedIn: "2.0" }],
    ["null fix", { sha256: sha, ...base, fixedIn: null }],
    ["fix inside", { id: "acme.x", versions: ">=1.0.0, <2.0.0", ...base, fixedIn: "1.5.0" }],
    ["fix below", { id: "acme.x", versions: ">=1.0.0, <2.0.0", ...base, fixedIn: "0.9.0" }],
    ["fix at an inclusive top", { id: "acme.x", versions: "<=2.0.0", ...base, fixedIn: "2.0.0" }],
    ["fix with no top", { id: "acme.x", versions: ">=1.0.0", ...base, fixedIn: "3.0.0" }],
    ["fix of everything", { id: "acme.x", versions: "*", ...base, fixedIn: "3.0.0" }],
    ["unknown field", { sha256: sha, ...base, fixed_in: "1.2.0" }],
    ["not an object", []],
  ]) {
    assert.notEqual(entryFault(bad), null, what);
  }
  for (const good of [
    { id: "acme.x", versions: "<2.0.0", ...base, fixedIn: "2.0.0" },
    { id: "acme.x", versions: "=1.0.0", action: "removed", reason: "r" },
    { id: "acme.x", versions: "*", action: "removed", reason: "r" },
    { sha256: sha, ...base, fixedIn: "2.0.0" },
    { id: "acme.notes", versions: ">=1.0.0, <1.2.0", action: "paused", reason: "It can lose your notes on sync.", fixedIn: "1.2.0" },
  ]) {
    assert.equal(entryFault(good), null, JSON.stringify(good));
  }
});

test("plain text: bounded, trimmed, nothing hidden, few stacked marks", () => {
  assert.equal(plainTextFault("Map", 40, false, false), null);
  assert.equal(plainTextFault("", 40, false, true), null);
  assert.equal(plainTextFault("line one\nline two", 280, true, true), null);
  for (const [s, newlines] of [["", false], [" Atlas", false], ["Atlas ", false], ["x".repeat(41), false], ["Map‮", false], ["a​b", false], ["a\tb", false], ["a\nb", false], ["a b", false], ["a﻿b", false], ["é̂̃̄̅", false]]) {
    assert.notEqual(plainTextFault(s, 40, newlines, false), null, JSON.stringify(s));
  }
  assert.equal(plainTextFault("é̂̃̄", 40, false, false), null, "four marks are allowed");
  assert.notEqual(plainTextFault("a\u{e0001}b", 40, false, false), null, "tag characters");
  assert.notEqual(plainTextFault("lone \ud800 surrogate", 40, false, false), null);
});

test("times have one spelling", () => {
  const t = parseTime("2027-01-30T00:00:00Z");
  assert.equal(timeText(t), "2027-01-30T00:00:00Z");
  for (const bad of ["2027-01-30T00:00:00.000Z", "2027-01-30T00:00:00+00:00", "2027-01-30 00:00:00Z", "2027-02-30T00:00:00Z", "2027-01-30T24:00:00Z", "2027-01-30T00:00:60Z", "", 5, "2027-1-30T00:00:00Z"]) {
    assert.equal(parseTime(bad), null, String(bad));
  }
});

test("the published URLs are exactly PM's spelling", () => {
  assert.equal(INDEX_URL, "https://github.com/itsAtlas-org/PM-Mods/releases/download/index/index.json");
  assert.equal(INDEX_SIGNATURE_URL, "https://github.com/itsAtlas-org/PM-Mods/releases/download/index/index.json.minisig");
  assert.equal(
    packageUrl("atlas.map", "1.0.0"),
    "https://github.com/itsAtlas-org/PM-Mods/releases/download/atlas.map-v1.0.0/atlas.map-1.0.0.pmmod",
  );
});

// With PM_CHECKOUT set to a PM source tree, pin the constants and the key table to PM's own text.
const pm = process.env.PM_CHECKOUT;
test("constants and keys equal PM's sources (needs PM_CHECKOUT)", { skip: !pm || !existsSync(join(pm, "src-tauri/src/mods/index.rs")) }, () => {
  const mods = join(pm, "src-tauri/src/mods");
  const index = readFileSync(join(mods, "index.rs"), "utf8");
  const pkg = readFileSync(join(mods, "package.rs"), "utf8");
  const keys = readFileSync(join(mods, "keys.rs"), "utf8");
  const list = /pub const PERMISSIONS: &\[&str\] = &\[([^\]]*)\]/.exec(pkg)[1].match(/"([^"]+)"/g).map((s) => s.slice(1, -1));
  assert.deepEqual(PERMISSIONS, list);
  assert.match(index, /RELEASE_DOWNLOAD_PREFIX: &str =\s*"https:\/\/github.com\/itsAtlas-org\/PM-Mods\/releases\/download\/"/);
  assert.match(index, /pub const MAX_VALIDITY_DAYS: i64 = 120;/);
  assert.match(index, /pub const MAX_MODS: usize = 1000;/);
  assert.match(index, /pub const MAX_BLACKLIST: usize = 1000;/);
  assert.match(index, /pub const MAX_REVOKED: usize = 16;/);
  assert.match(index, /pub const INDEX_CAP: usize = 1 << 20;/);
  assert.match(index, /pub const SIGNATURE_CAP: usize = 4 << 10;/);
  for (const k of ATLAS_MOD_KEYS) {
    assert.ok(keys.includes(`id: "${k.id}"`), `${k.role} id`);
    assert.ok(keys.includes(`public: "${k.public}"`), `${k.role} public key`);
  }
});
