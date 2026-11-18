// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The live index read through the API (lib/live.mjs, live-index.mjs) and the build-folder reader
// (lib/unsigned.mjs). No network and no real gh: a fake gh over a map of releases.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { fetchLive } from "../scripts/live-index.mjs";
import { NO_INDEX_MARKER, readLiveIndex } from "../scripts/lib/live.mjs";
import { readUnsignedDir } from "../scripts/lib/unsigned.mjs";

const dirs = [];
const scratch = () => {
  const d = mkdtempSync(join(tmpdir(), "pm-mods-live-test-"));
  dirs.push(d);
  return d;
};
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

const REPO = "itsAtlas-org/PM-Mods";

/** A fake gh: releases is Map tag -> Map assetName -> Buffer; `download` writes the matching files to --dir. */
function fakeGh(releases, { downloadFails = false } = {}) {
  const calls = [];
  const gh = async (args) => {
    calls.push(args);
    const tag = args[2];
    if (args[0] === "release" && args[1] === "view") {
      if (!releases.has(tag)) return { code: 1, stdout: "", stderr: "release not found" };
      return { code: 0, stdout: JSON.stringify({ assets: [...releases.get(tag).keys()].map((name) => ({ name })) }), stderr: "" };
    }
    if (args[0] === "release" && args[1] === "download") {
      if (downloadFails) return { code: 1, stdout: "", stderr: "HTTP 502" };
      const patterns = args.flatMap((a, i) => (a === "--pattern" ? [args[i + 1]] : []));
      const dir = args[args.indexOf("--dir") + 1];
      for (const [name, bytes] of releases.get(tag)) if (patterns.includes(name)) writeFileSync(join(dir, name), bytes);
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { gh, calls };
}

test("readLiveIndex: no index release at all is the one case that is a first publish", async () => {
  assert.equal(await readLiveIndex({ gh: fakeGh(new Map()).gh, repo: REPO }), null);
});

test("readLiveIndex: reads the pair through `gh release download`, not a public URL", async () => {
  const releases = new Map([["index", new Map([["index.json", Buffer.from("J")], ["index.json.minisig", Buffer.from("S")]])]]);
  const { gh, calls } = fakeGh(releases);
  const pair = await readLiveIndex({ gh, repo: REPO });
  assert.equal(pair.json.toString(), "J");
  assert.equal(pair.signature.toString(), "S");
  assert.ok(calls.some((c) => c[0] === "release" && c[1] === "download" && c.includes("--repo") && c.includes(REPO)));
});

test("readLiveIndex: a release that exists but lacks an asset is a torn replacement, never a first publish", async () => {
  for (const names of [[], ["index.json"], ["index.json.minisig"]]) {
    const releases = new Map([["index", new Map(names.map((n) => [n, Buffer.from("x")]))]]);
    await assert.rejects(readLiveIndex({ gh: fakeGh(releases).gh, repo: REPO }), /interrupted replacement, not a first publish[\s\S]*signed-index/);
  }
});

test("readLiveIndex: a failing view or download stops the run (it is not 'absent')", async () => {
  const failingView = async () => ({ code: 1, stdout: "", stderr: "HTTP 502: Bad Gateway" });
  await assert.rejects(readLiveIndex({ gh: failingView, repo: REPO }), /failed: HTTP 502/);
  const releases = new Map([["index", new Map([["index.json", Buffer.from("J")], ["index.json.minisig", Buffer.from("S")]])]]);
  await assert.rejects(readLiveIndex({ gh: fakeGh(releases, { downloadFails: true }).gh, repo: REPO }), /download failed: HTTP 502/);
});

test("live-index: writes the pair, or the first-publish marker alone", async () => {
  const first = scratch();
  assert.equal(await fetchLive({ dir: first, repo: REPO, gh: fakeGh(new Map()).gh }), "first");
  assert.deepEqual(readdirSync(first), [NO_INDEX_MARKER]);
  const live = scratch();
  const releases = new Map([["index", new Map([["index.json", Buffer.from("J")], ["index.json.minisig", Buffer.from("S")]])]]);
  assert.equal(await fetchLive({ dir: live, repo: REPO, gh: fakeGh(releases).gh }), "live");
  assert.deepEqual(readdirSync(live).sort(), ["index.json", "index.json.minisig"]);
  assert.equal(readFileSync(join(live, "index.json"), "utf8"), "J");
  await assert.rejects(fetchLive({ dir: scratch(), repo: "nope", gh: fakeGh(new Map()).gh }), /owner\/repo/);
});

test("readUnsignedDir: only the catalogue's names, only regular files, within the cap", () => {
  const cat = [{ id: "a.one", version: "1.0.0" }];
  const dir = scratch();
  const name = "a.one-1.0.0.unsigned.pmmod";
  assert.equal(readUnsignedDir(join(dir, "absent"), cat, 100).size, 0, "no build folder is no build");
  assert.equal(readUnsignedDir(dir, cat, 100).size, 0);
  writeFileSync(join(dir, name), "bytes");
  assert.equal(readUnsignedDir(dir, cat, 100).get(name).toString(), "bytes");
  assert.throws(() => readUnsignedDir(dir, cat, 3), /larger than 3 bytes/);
  writeFileSync(join(dir, "b.two-1.0.0.unsigned.pmmod"), "x");
  assert.throws(() => readUnsignedDir(dir, cat, 100), /not the build of a catalogue entry/);
  // A symlink under the right name, to a real file: refused.
  const other = scratch();
  writeFileSync(join(other, "real"), "bytes");
  symlinkSync(join(other, "real"), join(other, name));
  assert.throws(() => readUnsignedDir(other, cat, 100), /can't be opened as a plain file/);
  // A subfolder.
  const sub = scratch();
  mkdirSync(join(sub, "nested"));
  assert.throws(() => readUnsignedDir(sub, cat, 100), /not the build of a catalogue entry/);
  // The folder is a file.
  assert.throws(() => readUnsignedDir(join(dir, name), cat, 100), /isn't a plain folder/);
});
