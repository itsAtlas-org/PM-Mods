// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The repo gates, run by the dry-run workflow on every pull request (and by hand):
//
//   node scripts/check.mjs [--base <commit>]
//
//  - catalogue.json and blacklist.json parse under the strict validators (the same code the sign job uses);
//  - with --base, catalogue.json only ever GROWS: an existing entry may not change or go (a published
//    version is burned, and each entry is the record of what was signed). The entries added over the base
//    are written to $GITHUB_OUTPUT as `added=<JSON array>` for the rebuild job to build and compare;
//  - the workflows keep their security shape (lib/gates.mjs);
//  - no key, package, signature, build output or dependency manifest is tracked; SPDX headers are there.
//
// Exit 1 with every problem listed. Read-only.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { appendedEntries, parseBlacklist, parseCatalogue } from "./lib/catalogue.mjs";
import { spdxProblems, trackedFileProblems, workflowProblems } from "./lib/gates.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

/** catalogue.json as it was at `base`; `[]` when the file didn't exist there. A base that isn't a commit throws. */
export function catalogueAt(base) {
  if (!base || base.startsWith("-")) throw new Error(`--base ${JSON.stringify(base)} isn't a commit`);
  git("rev-parse", "--verify", `${base}^{commit}`);
  try {
    git("cat-file", "-e", `${base}:catalogue.json`);
  } catch {
    return [];
  }
  return parseCatalogue(git("show", `${base}:catalogue.json`));
}

function main(argv) {
  const problems = [];
  const baseAt = argv.indexOf("--base");
  const base = baseAt >= 0 ? argv[baseAt + 1] : null;

  const tracked = git("ls-files", "-z").split("\0").filter(Boolean);
  const read = (f) => readFileSync(join(root, f), "utf8");

  let added = [];
  try {
    const current = parseCatalogue(read("catalogue.json"));
    parseBlacklist(read("blacklist.json"));
    if (base) added = appendedEntries(catalogueAt(base), current);
  } catch (e) {
    problems.push(e.message);
  }

  const workflows = tracked.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f));
  // The floor: a scanner that finds nothing would pass everything.
  for (const need of ["publish.yml", "dry-run.yml"]) {
    if (!workflows.includes(`.github/workflows/${need}`)) problems.push(`.github/workflows/${need} is missing`);
  }
  for (const f of workflows) problems.push(...workflowProblems(f.split("/").pop(), read(f)));
  problems.push(...trackedFileProblems(tracked));
  problems.push(...spdxProblems(tracked.filter((f) => !f.startsWith("test/vectors/") || f.endsWith(".md")), read));

  if (problems.length) {
    console.error(`check: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join("\n")}`);
    process.exit(1);
  }
  console.log(`check OK: ${tracked.length} tracked files, ${workflows.length} workflows${base ? `, ${added.length} catalogue entr${added.length === 1 ? "y" : "ies"} added over ${base.slice(0, 7)}` : ""}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `added=${JSON.stringify(added)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`check: ${e.message}`);
    process.exit(1);
  }
}
