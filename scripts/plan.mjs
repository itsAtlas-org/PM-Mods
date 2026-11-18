// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The plan job: which catalogue entries still need building and signing. An entry is pending when its
// package isn't served at its public release URL yet, the same test the sign job applies (so the two
// can't disagree). Read-only: public GETs, no token.
//
//   node scripts/plan.mjs
//
// Writes to $GITHUB_OUTPUT (when set):  pending=<JSON array of entries, one line>   empty=<true|false>
// and a table to $GITHUB_STEP_SUMMARY. `empty` is true when the catalogue has no entries at all, so a
// push of the empty catalogue doesn't ask for a signing approval to publish an index of nothing.

import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseCatalogue } from "./lib/catalogue.mjs";
import { getPublic } from "./lib/net.mjs";
import { packageUrl, releaseTag } from "./lib/rules.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE_CAP = 32 << 20;

/** The entries whose package `exists(entry)` says isn't published, in catalogue order. */
export async function pendingEntries(catalogue, exists) {
  const pending = [];
  for (const entry of catalogue) if (!(await exists(entry))) pending.push(entry);
  return pending;
}

/** The two workflow outputs for a plan. The JSON is one line, so the output file's format can't be broken. */
export function outputsFor(catalogue, pending) {
  return `pending=${JSON.stringify(pending)}\nempty=${catalogue.length === 0}\n`;
}

async function main() {
  const catalogue = parseCatalogue(readFileSync(join(root, "catalogue.json"), "utf8"));
  const pending = await pendingEntries(
    catalogue,
    async (e) => (await getPublic(packageUrl(e.id, e.version), PACKAGE_CAP)) !== null,
  );
  const lines = [`${catalogue.length} catalogue entr${catalogue.length === 1 ? "y" : "ies"}, ${pending.length} to build and sign`, ""];
  if (catalogue.length > 0) {
    lines.push("| release | state |", "| --- | --- |");
    for (const e of catalogue) lines.push(`| ${releaseTag(e.id, e.version)} | ${pending.includes(e) ? "pending" : "published"} |`);
  }
  console.log(lines.join("\n"));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, outputsFor(catalogue, pending));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`plan: ${e.message}`);
    process.exit(1);
  });
}
