// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The live index pair, read through the authenticated GitHub API (`gh release download`) and not through
// the public download URL. The next seq is "the live seq + 1", and PM treats the same seq with other bytes
// as permanent Equivocation, so the value it is derived from must not come from a CDN that can still
// serve the previous pair right after an upload. (The packages and the read-back at the end of the run
// still use the public URLs: those are checked by signature or sha256, and a stale answer only fails.)
//
// Three outcomes:
//   null                      there is no `index` release at all: a first publish (seq 1)
//   { json, signature }       the pair as the release holds it; the caller verifies it
//   a refusal                 the release exists but is missing an asset, or the download failed. That is
//                             NEVER a first publish: PM refuses any seq below one it has seen, so
//                             restarting at 1 would lock every installed PM out. See the README,
//                             "A run failed", for putting the pair back.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ghOk, releaseAssets } from "./gh.mjs";
import { INDEX_CAP, INDEX_FILE, INDEX_SIGNATURE_FILE, INDEX_TAG, refuse, SIGNATURE_CAP } from "./rules.mjs";

/** What scripts/live-index.mjs leaves in its folder when there is no `index` release at all. */
export const NO_INDEX_MARKER = "NO-INDEX-RELEASE";

export const TORN_HELP =
  "put the pair back from the failed run's `signed-index` artifact (README, \"A run failed\"); " +
  "never delete the release or its tag, and never publish over it";

/**
 * @param {object} p
 * @param {(args: string[]) => Promise<{code: number, stdout: string, stderr: string}>} p.gh
 * @param {string} p.repo owner/repo
 */
export async function readLiveIndex({ gh, repo }) {
  const names = await releaseAssets(gh, repo, INDEX_TAG);
  if (names === null) return null;
  const have = [INDEX_FILE, INDEX_SIGNATURE_FILE].filter((n) => names.includes(n));
  if (have.length !== 2) {
    refuse(
      `the ${INDEX_TAG} release exists but ${have.length === 0 ? "holds neither index.json nor index.json.minisig" : `lacks ${[INDEX_FILE, INDEX_SIGNATURE_FILE].find((n) => !have.includes(n))}`}: ` +
        `an interrupted replacement, not a first publish (seq is never reset). ${TORN_HELP}`,
    );
  }
  const dir = mkdtempSync(join(tmpdir(), "pm-mods-live-"));
  try {
    await ghOk(gh, ["release", "download", INDEX_TAG, "--repo", repo, "--pattern", INDEX_FILE, "--pattern", INDEX_SIGNATURE_FILE, "--dir", dir, "--clobber"]);
    const read = (name, cap) => {
      const bytes = readFileSync(join(dir, name));
      if (bytes.length > cap) refuse(`the live ${name} is larger than ${cap} bytes`);
      return bytes;
    };
    return { json: read(INDEX_FILE, INDEX_CAP), signature: read(INDEX_SIGNATURE_FILE, SIGNATURE_CAP) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
