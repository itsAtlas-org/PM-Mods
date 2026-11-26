// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Verify what is published (or a local folder laid out the same way), under the two pinned keys. No
// secrets needed; read-only.
//
//   node scripts/verify-published.mjs            reads the public release URLs
//   node scripts/verify-published.mjs --dir D    reads D/index.json, D/index.json.minisig, D/<id>-<version>.pmmod
//   node scripts/verify-published.mjs --plan P   also requires the live index to be the one P (sign.mjs's
//                                                plan.json) describes, retrying for up to 10 minutes while a cache
//                                                still serves the old one (the publish workflow's last step)
//
// Prints the seq (PM's MIN_INDEX_SEQ is raised to it in the release that ships the mods, never above it),
// the expiry and one line per mod; with GITHUB_STEP_SUMMARY set it writes the same to the job summary.
// Exit 1 on the first thing that doesn't verify.

import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { pinnedPublicKeys } from "./lib/keys.mjs";
import { getPublic } from "./lib/net.mjs";
import { verifyPublished } from "./lib/published.mjs";
import {
  INDEX_CAP,
  INDEX_FILE,
  INDEX_SIGNATURE_FILE,
  INDEX_SIGNATURE_URL,
  INDEX_URL,
  packageAsset,
  SIGNATURE_CAP,
} from "./lib/rules.mjs";

const PACKAGE_CAP = 32 << 20;
/** How long the publish step waits for GitHub to serve what was just uploaded. A new release asset's
 *  download URL can answer 404 for more than a minute after the upload succeeded (1.0.1 and 1.0.2 both
 *  did), so the old 6 x 10 s window went red on a publish that had worked. */
export const READ_BACK_BUDGET_MS = 10 * 60_000;

/** The wait before try `attempt + 1`: 10 s at first, growing to a minute, so a quick cache is caught
 *  quickly and a slow one is not hammered. */
export function waitBefore(attempt) {
  return Math.min(60_000, 10_000 * Math.ceil(attempt / 2));
}
const arg = (argv, name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);

/** Null when the verified read-back `out` is the publish `plan` describes; otherwise what differs. */
export function planFault(out, plan) {
  if (out.seq !== plan.seq) return `the live index is seq ${out.seq}, the plan says ${plan.seq}`;
  if (out.indexSha256 !== plan.indexSha256) return "the live index.json isn't the one that was just uploaded";
  return null;
}

async function main(argv) {
  const dir = arg(argv, "--dir");
  const planPath = arg(argv, "--plan");
  const plan = planPath ? JSON.parse(readFileSync(planPath, "utf8")) : null;
  const local = (name) => (existsSync(join(dir, name)) ? readFileSync(join(dir, name)) : null);
  const getIndex = async () => {
    const json = dir ? local(INDEX_FILE) : await getPublic(INDEX_URL, INDEX_CAP);
    if (!json) return null;
    const signature = dir ? local(INDEX_SIGNATURE_FILE) : await getPublic(INDEX_SIGNATURE_URL, SIGNATURE_CAP);
    if (!signature) throw new Error("index.json is there but index.json.minisig isn't");
    return { json, signature };
  };
  const getPackage = (m) => (dir ? local(packageAsset(m.id, m.version)) : getPublic(m.url, PACKAGE_CAP));

  let out;
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    try {
      out = await verifyPublished({ getIndex, getPackage, publicKeys: pinnedPublicKeys() });
      const fault = plan ? planFault(out, plan) : null;
      if (fault) throw new Error(fault);
      break;
    } catch (e) {
      // Only a plan is waited for: right after an upload a cache can still serve the previous pair.
      const wait = waitBefore(attempt);
      if (!plan || Date.now() - started + wait > READ_BACK_BUDGET_MS) throw e;
      console.log(`attempt ${attempt}: ${e.message}; trying again in ${wait / 1000}s`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  const lines = [
    `index OK: seq ${out.seq}, signed by ${out.signer}, issued ${out.issued.toISOString()}, expires ${out.expires.toISOString()}`,
    `blacklist entries: ${out.blacklist}`,
    ...out.rows.map((r) => `${r.id} ${r.version}  ${r.sha256}  signed by ${r.signer}`),
  ];
  console.log(lines.join("\n"));
  if (process.env.GITHUB_STEP_SUMMARY) {
    const table = ["| mod | version | signed sha256 | signer |", "| --- | --- | --- | --- |"];
    for (const r of out.rows) table.push(`| ${r.id} | ${r.version} | \`${r.sha256}\` | ${r.signer} |`);
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `### Published index\n\nseq **${out.seq}**, expires ${out.expires.toISOString()}, ${out.blacklist} blacklist entr${out.blacklist === 1 ? "y" : "ies"}\n\n${table.join("\n")}\n`,
    );
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(`verify-published: ${e.message}`);
    process.exit(1);
  });
}
