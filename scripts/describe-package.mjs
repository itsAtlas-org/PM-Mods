// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// What is inside a .pmmod: one line per file with its size and sha256, and the sha256 of the whole file.
// For finding the first difference when a rebuild does not match the recorded sha256; run it on your
// local build and on the CI one and compare. Read-only, offline.
//
//   node scripts/describe-package.mjs FILE.pmmod [--table]     --table prints Markdown table rows only

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { readZip } from "./lib/zip.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");

/** Rows [path, bytes, sha256] for a package's files, in archive order. */
export function describePackage(bytes) {
  return [...readZip(bytes)].map(([path, data]) => [path, data.length, sha(data)]);
}

function main(argv) {
  const file = argv.find((a) => !a.startsWith("--"));
  if (!file) throw new Error("usage: describe-package.mjs FILE.pmmod [--table]");
  const bytes = readFileSync(file);
  const rows = describePackage(bytes);
  if (argv.includes("--table")) {
    for (const [path, size, hash] of rows) console.log(`| \`${path}\` | ${size} | \`${hash}\` |`);
    return;
  }
  console.log(`${sha(bytes)}  ${file}`);
  for (const [path, size, hash] of rows) console.log(`  ${hash}  ${String(size).padStart(9)}  ${path}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error(`describe-package: ${e.message}`);
    process.exit(1);
  }
}
