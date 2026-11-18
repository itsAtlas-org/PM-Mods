// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The sign job's upload step: put what sign.mjs wrote (DIR/plan.json, new packages, index.json and its
// signature) on the GitHub releases of this repo. It holds no signing key, only the job's token.
//
//   node scripts/publish.mjs DIR
//
// Env: GH_TOKEN, GITHUB_REPOSITORY (owner/repo), GITHUB_SHA (the commit a new tag points at).
//
// Rules:
//  - Packages first, the index last, so the index never lists a package that isn't there yet.
//  - A package release is <id>-v<version> with the one asset <id>-<version>.pmmod. A missing release is
//    created (and so is its tag, the first time); a release without its asset gets the asset (never
//    --clobber); an asset that is already there must be byte-identical to ours or the run fails. A
//    published version is burned: tags are protected, and the fix for a wrong one is the next version.
//  - The `index` release holds index.json and index.json.minisig. Its tag is created on first use and never
//    moved (the ruleset forbids it), so the assets are replaced instead. Never make that release immutable.
//  - `gh` is run with execFile and an argument list: no shell, nothing from the plan reaches one.
//  - The package steps are safe to re-run after a half-finished publish: each is "make it so", none is
//    "do it again". The index step is NOT atomic: `gh release upload --clobber` deletes an asset and then
//    uploads its replacement, so a failure in between leaves the live pair torn (a new index.json with the
//    old signature, or one file missing). Three defences: the replacement is retried (a transient error is
//    the likely cause); the workflow keeps the pair it is about to upload as the `signed-index` artifact
//    BEFORE this step runs, so it can be put back by hand (README, "A run failed"); and the next run reads
//    the live pair through the API and refuses a torn one (live.mjs), never treating it as a first publish.
//  - Just before the index is replaced, the live pair is read again through the API and must be exactly
//    seq - 1 (the seq this run signed on top of). If another publish got there first, nothing is replaced:
//    PM treats one seq with two different index files as permanent Equivocation.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ghOk, realGh, releaseAssets } from "./lib/gh.mjs";
import { pinnedPublicKeys } from "./lib/keys.mjs";
import { verifyIndex } from "./lib/index.mjs";
import { readLiveIndex, TORN_HELP } from "./lib/live.mjs";
import { getPublic } from "./lib/net.mjs";
import { INDEX_FILE, INDEX_SIGNATURE_FILE, INDEX_TAG, refuse, RELEASE_DOWNLOAD_PREFIX } from "./lib/rules.mjs";

export { realGh };
const PACKAGE_CAP = 32 << 20;
const sha256 = (b) => createHash("sha256").update(b).digest("hex");

const NOTES = "Signed by the Atlas mod signing key. Built from the commit pinned in catalogue.json by the Publish workflow.";
const INDEX_NOTES =
  "The signed mod index PM reads. The assets on this release are replaced on every publish; the tag itself never moves.";

const TAG = /^[A-Za-z0-9][A-Za-z0-9._-]*-v[0-9][A-Za-z0-9.+-]*$/;
const ASSET = /^[A-Za-z0-9][A-Za-z0-9._-]*\.pmmod$/;

const INDEX_ATTEMPTS = 3;

/** Make the `index` release hold our pair: create it, or replace its assets. Retried; see the header. */
async function putIndex({ gh, repo, sha, files, log, sleep }) {
  let last = "";
  for (let attempt = 1; attempt <= INDEX_ATTEMPTS; attempt++) {
    const assets = await releaseAssets(gh, repo, INDEX_TAG);
    const args =
      assets === null
        ? ["release", "create", INDEX_TAG, ...files, "--repo", repo, "--target", sha, "--latest=false", "--title", "Signed index", "--notes", INDEX_NOTES]
        : ["release", "upload", INDEX_TAG, ...files, "--repo", repo, "--clobber"];
    const r = await gh(args);
    if (r.code === 0) {
      log(assets === null ? `created release ${INDEX_TAG}` : `replaced the assets of release ${INDEX_TAG}`);
      return;
    }
    last = r.stderr.trim() || `exit ${r.code}`;
    log(`attempt ${attempt} of ${INDEX_ATTEMPTS} at the ${INDEX_TAG} release failed: ${last}`);
    if (attempt < INDEX_ATTEMPTS) await sleep(attempt * 5000);
  }
  refuse(
    `the ${INDEX_TAG} release could not be written after ${INDEX_ATTEMPTS} attempts (${last}). The live pair may be incomplete now; ` +
      `${TORN_HELP}`,
  );
}

/** The live pair must be seq - 1 (verified under the pinned keys); anything else means another publish ran. */
async function assertLiveSeq({ live, publicKeys, seq }) {
  const pair = await live();
  let liveSeq = 0;
  if (pair) {
    try {
      liveSeq = verifyIndex(pair.json, pair.signature, publicKeys).parsed.seq;
    } catch (e) {
      refuse(`the live index doesn't verify (${e.message}); nothing was replaced`);
    }
  }
  if (liveSeq !== seq - 1) {
    refuse(`this run signed index seq ${seq} on top of seq ${seq - 1}, but the live index is ${pair ? `seq ${liveSeq}` : "absent"}: another publish got there first. Nothing was replaced; run Publish again`);
  }
}

/**
 * @param {object} p
 * @param {string} p.dir sign.mjs's --out folder
 * @param {string} p.repo owner/repo
 * @param {string} p.sha the commit a new tag points at
 * @param {(args: string[]) => Promise<{code: number, stdout: string, stderr: string}>} p.gh
 * @param {(url: string) => Promise<Buffer|null>} p.read a public GET (for comparing an asset already published)
 * @param {() => Promise<{json: Buffer, signature: Buffer}|null>} [p.live] the live index pair through the API
 * @param {object[]} [p.publicKeys] the pinned keys the live pair is verified under
 * @param {(ms: number) => Promise<void>} [p.sleep]
 * @param {(s: string) => void} p.log
 */
export async function publish({
  dir,
  repo,
  sha,
  gh,
  read,
  log = console.log,
  live = () => readLiveIndex({ gh, repo }),
  publicKeys = pinnedPublicKeys(),
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
}) {
  if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo)) refuse("GITHUB_REPOSITORY isn't owner/repo");
  if (!/^[0-9a-f]{40}$/.test(sha)) refuse("GITHUB_SHA isn't a commit");
  const plan = JSON.parse(readFileSync(join(dir, "plan.json"), "utf8"));
  const indexBytes = readFileSync(join(dir, INDEX_FILE));
  if (sha256(indexBytes) !== plan.indexSha256) refuse("index.json isn't the one the plan describes");

  for (const p of plan.packages) {
    if (!TAG.test(p.tag) || !ASSET.test(p.asset) || basename(p.asset) !== p.asset) refuse("the plan names a release or file it shouldn't");
    if (!p.fresh) continue; // already published, and sign.mjs re-verified it
    const file = join(dir, p.asset);
    const bytes = readFileSync(file);
    if (sha256(bytes) !== p.sha256) refuse(`${p.asset} isn't the one the plan describes`);
    const assets = await releaseAssets(gh, repo, p.tag);
    if (assets === null) {
      await ghOk(gh, ["release", "create", p.tag, file, "--repo", repo, "--target", sha, "--latest=false", "--title", p.tag, "--notes", NOTES]);
      log(`created release ${p.tag}`);
    } else if (!assets.includes(p.asset)) {
      await ghOk(gh, ["release", "upload", p.tag, file, "--repo", repo]);
      log(`added ${p.asset} to the existing release ${p.tag}`);
    } else {
      const there = await read(`${RELEASE_DOWNLOAD_PREFIX}${p.tag}/${p.asset}`);
      if (!there || sha256(there) !== p.sha256) {
        refuse(`${p.tag} already has a ${p.asset} that isn't ours; a published version is burned, bump the version`);
      }
      log(`${p.tag} already holds exactly this package`);
    }
  }

  const files = [join(dir, INDEX_FILE), join(dir, INDEX_SIGNATURE_FILE)];
  await assertLiveSeq({ live, publicKeys, seq: plan.seq });
  await putIndex({ gh, repo, sha, files, log, sleep });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: publish.mjs DIR");
    process.exit(1);
  }
  publish({
    dir,
    repo: process.env.GITHUB_REPOSITORY ?? "",
    sha: process.env.GITHUB_SHA ?? "",
    gh: realGh,
    read: (url) => getPublic(url, PACKAGE_CAP),
  }).catch((e) => {
    console.error(`publish: ${e.message}`);
    process.exit(1);
  });
}
