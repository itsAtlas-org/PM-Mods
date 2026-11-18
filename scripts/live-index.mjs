// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The sign job's step before the signing step (it holds GH_TOKEN and NO key): read the live index pair
// through the GitHub API and leave it in DIR for sign.mjs --live DIR. The signing step then needs no
// network for the seq and the key never meets a `gh` call.
//
//   node scripts/live-index.mjs DIR
//
// Env: GH_TOKEN, GITHUB_REPOSITORY (owner/repo).
// DIR gets index.json + index.json.minisig, or only NO-INDEX-RELEASE when the `index` release does not
// exist yet (a first publish). A release that is missing an asset is refused here, before any signing.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { realGh } from "./lib/gh.mjs";
import { NO_INDEX_MARKER, readLiveIndex } from "./lib/live.mjs";
import { INDEX_FILE, INDEX_SIGNATURE_FILE } from "./lib/rules.mjs";

/** Write the live pair (or the marker) into `dir`; returns "first" or "live". */
export async function fetchLive({ dir, repo, gh }) {
  if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo)) throw new Error("GITHUB_REPOSITORY isn't owner/repo");
  const live = await readLiveIndex({ gh, repo });
  mkdirSync(dir, { recursive: true });
  if (!live) {
    writeFileSync(join(dir, NO_INDEX_MARKER), "");
    return "first";
  }
  writeFileSync(join(dir, INDEX_FILE), live.json);
  writeFileSync(join(dir, INDEX_SIGNATURE_FILE), live.signature);
  return "live";
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: live-index.mjs DIR");
    process.exit(1);
  }
  fetchLive({ dir, repo: process.env.GITHUB_REPOSITORY ?? "", gh: realGh })
    .then((what) => console.log(what === "first" ? "no index release yet: a first publish" : "read the live index pair"))
    .catch((e) => {
      console.error(`live-index: ${e.message}`);
      process.exit(1);
    });
}
