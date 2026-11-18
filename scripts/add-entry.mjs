// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Add one catalogue entry without hand-writing JSON. Reads the mod's manifest.json at the pinned commit
// from raw.githubusercontent.com (a read-only GET), fills tier, author, repo, path and licence from it,
// and writes catalogue.json sorted. The two values that cannot come from the source tree are the ones
// you pass: the commit the build ran at, and the sha256 `just build-mods` printed for the .pmmod.
//
//   node scripts/add-entry.mjs ID VERSION COMMIT SHA256 [--repo owner/repo] [--path dir]
//
// --repo defaults to itsAtlas-org/Personal-Manager and --path to mods/ID, which is where first-party
// mods live; a second-party mod names its own.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { catalogueEntryFault, parseCatalogue, serializeCatalogue } from "./lib/catalogue.mjs";
import { getPublic } from "./lib/net.mjs";
import { LICENCE, refuse, releaseTag } from "./lib/rules.mjs";
import { parseStrictJson } from "./lib/strict-json.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The catalogue entry for a source manifest (parsed) and what the caller passes in. Pure. */
export function entryFromManifest(manifest, { id, version, commit, unsignedSha256, repo, path }) {
  const publisher = manifest && manifest.publisher;
  if (!publisher || typeof publisher !== "object") refuse("the manifest has no publisher");
  if (manifest.id !== id) refuse(`the manifest's id is ${manifest.id}, not ${id}`);
  if (manifest.version !== version) refuse(`the manifest's version is ${manifest.version}, not ${version}`);
  if (publisher.sourceRepo !== repo) refuse(`the manifest's sourceRepo is ${publisher.sourceRepo}, not ${repo}`);
  const entry = {
    id,
    version,
    tier: publisher.tier,
    author: publisher.author,
    repo,
    commit,
    path,
    unsignedSha256,
    licence: manifest.licence ?? LICENCE,
  };
  const fault = catalogueEntryFault(entry);
  if (fault) refuse(`${id} ${version}: ${fault}`);
  return entry;
}

/** The catalogue's text with `entry` added; refuses a version that is already there. */
export function withEntry(text, entry) {
  const entries = parseCatalogue(text);
  const tag = releaseTag(entry.id, entry.version);
  if (entries.some((e) => releaseTag(e.id, e.version) === tag)) refuse(`${tag} is already in the catalogue`);
  const next = serializeCatalogue([...entries, entry]);
  parseCatalogue(next);
  return next;
}

async function main(argv) {
  const positional = [];
  const flags = new Map();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) flags.set(argv[i], argv[++i]);
    else positional.push(argv[i]);
  }
  if (positional.length !== 4) refuse("usage: add-entry.mjs ID VERSION COMMIT SHA256 [--repo owner/repo] [--path dir]");
  const [id, version, commit, unsignedSha256] = positional;
  const repo = flags.get("--repo") ?? "itsAtlas-org/Personal-Manager";
  const path = flags.get("--path") ?? `mods/${id}`;
  const url = `https://raw.githubusercontent.com/${repo}/${commit}/${path}/manifest.json`;
  const bytes = await getPublic(url, 256 << 10);
  if (!bytes) refuse(`${url} doesn't exist: check the commit, repo and path`);
  const manifest = parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  const entry = entryFromManifest(manifest, { id, version, commit, unsignedSha256, repo, path });
  const file = join(root, "catalogue.json");
  writeFileSync(file, withEntry(readFileSync(file, "utf8"), entry));
  console.log(`added ${releaseTag(id, version)} to catalogue.json`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(`add-entry: ${e.message}`);
    process.exit(1);
  });
}
