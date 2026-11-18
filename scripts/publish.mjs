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
//  - Safe to re-run after a half-finished publish: every step is "make it so", none is "do it again".

import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { getPublic } from "./lib/net.mjs";
import { INDEX_FILE, INDEX_SIGNATURE_FILE, INDEX_TAG, refuse, RELEASE_DOWNLOAD_PREFIX } from "./lib/rules.mjs";

const run = promisify(execFile);
const PACKAGE_CAP = 32 << 20;
const sha256 = (b) => createHash("sha256").update(b).digest("hex");

const NOTES = "Signed by the Atlas mod signing key. Built from the commit pinned in catalogue.json by the Publish workflow.";
const INDEX_NOTES =
  "The signed mod index PM reads. The assets on this release are replaced on every publish; the tag itself never moves.";

/** The real `gh`: resolves to {code, stdout, stderr} and never rejects on a non-zero exit. */
export async function realGh(args, env = process.env) {
  try {
    const { stdout, stderr } = await run("gh", args, { env, maxBuffer: 1 << 24 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    if (typeof e.code === "number") return { code: e.code, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
    throw e;
  }
}

/** The assets of a release (a list of names), or null when there is no such release. */
async function releaseAssets(gh, repo, tag) {
  const r = await gh(["release", "view", tag, "--repo", repo, "--json", "assets"]);
  if (r.code === 0) return JSON.parse(r.stdout).assets.map((a) => a.name);
  if (/release not found/i.test(r.stderr)) return null;
  refuse(`gh release view ${tag} failed: ${r.stderr.trim() || `exit ${r.code}`}`);
}

async function ghOk(gh, args) {
  const r = await gh(args);
  if (r.code !== 0) refuse(`gh ${args.slice(0, 2).join(" ")} failed: ${r.stderr.trim() || `exit ${r.code}`}`);
}

const TAG = /^[A-Za-z0-9][A-Za-z0-9._-]*-v[0-9][A-Za-z0-9.+-]*$/;
const ASSET = /^[A-Za-z0-9][A-Za-z0-9._-]*\.pmmod$/;

/**
 * @param {object} p
 * @param {string} p.dir sign.mjs's --out folder
 * @param {string} p.repo owner/repo
 * @param {string} p.sha the commit a new tag points at
 * @param {(args: string[]) => Promise<{code: number, stdout: string, stderr: string}>} p.gh
 * @param {(url: string) => Promise<Buffer|null>} p.read a public GET (for comparing an asset already published)
 * @param {(s: string) => void} p.log
 */
export async function publish({ dir, repo, sha, gh, read, log = console.log }) {
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
  const assets = await releaseAssets(gh, repo, INDEX_TAG);
  if (assets === null) {
    await ghOk(gh, ["release", "create", INDEX_TAG, ...files, "--repo", repo, "--target", sha, "--latest=false", "--title", "Signed index", "--notes", INDEX_NOTES]);
    log(`created release ${INDEX_TAG}`);
  } else {
    await ghOk(gh, ["release", "upload", INDEX_TAG, ...files, "--repo", repo, "--clobber"]);
    log(`replaced the assets of release ${INDEX_TAG}`);
  }
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
