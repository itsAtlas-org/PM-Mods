// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The pull-request rehearsal of the sign job, with a throwaway key made right here (never a real one,
// no secrets): the same library path as sign.mjs, in scratch, treating the entries that have a build in
// DIR as the whole catalogue and nothing as published. It signs each package, builds the index, signs it,
// and reads every file back under the throwaway public key as PM will. It proves the pipeline, not the
// real key (that is what `sign.mjs --key-check-only` is for).
//
//   node scripts/dry-run.mjs --unsigned DIR [--catalogue FILE] [--blacklist FILE] [--keep OUT]
//   (DIR as for sign.mjs; the two files default to the repo's own)

import { mkdirSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseBlacklist, parseCatalogue } from "./lib/catalogue.mjs";
import { generateKey, loadSecretKey, parsePublicKey } from "./lib/minisign.mjs";
import { prepareRelease } from "./lib/pipeline.mjs";
import { verifyPublished } from "./lib/published.mjs";
import { packageAsset } from "./lib/rules.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (argv, name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);

async function main(argv) {
  const unsignedDir = arg(argv, "--unsigned");
  if (!unsignedDir) throw new Error("--unsigned DIR is needed");
  const generated = generateKey({ password: "dry-run" });
  const key = loadSecretKey(generated.secretBase64, "dry-run");
  const publicKeys = [{ ...parsePublicKey(generated.publicLine), role: "main" }];

  const pathOf = (e) => join(unsignedDir, `${e.id}-${e.version}.unsigned.pmmod`);
  const all = parseCatalogue(readFileSync(arg(argv, "--catalogue") ?? join(root, "catalogue.json"), "utf8"));
  const catalogue = all.filter((e) => existsSync(pathOf(e)));
  const blacklist = parseBlacklist(readFileSync(arg(argv, "--blacklist") ?? join(root, "blacklist.json"), "utf8"));
  console.log(`dry run: ${catalogue.length} of ${all.length} catalogue entries have a build here`);

  const result = await prepareRelease({
    catalogue,
    blacklist,
    key,
    publicKeys,
    now: new Date(),
    readUnsigned: async (e) => readFileSync(pathOf(e)),
    fetchPackage: async () => null,
    fetchLiveIndex: async () => null,
  });
  const files = new Map(result.packages.map((p) => [packageAsset(p.entry.id, p.entry.version), p.bytes]));
  const out = await verifyPublished({
    getIndex: async () => ({ json: result.index.bytes, signature: result.index.signature }),
    getPackage: async (m) => files.get(packageAsset(m.id, m.version)) ?? null,
    publicKeys,
  });
  console.log(`dry run OK: index seq ${out.seq}, ${out.rows.length} mod(s) signed and read back under a throwaway key`);
  const keep = arg(argv, "--keep");
  if (keep) {
    mkdirSync(keep, { recursive: true });
    for (const [name, bytes] of files) writeFileSync(join(keep, name), bytes);
    writeFileSync(join(keep, "index.json"), result.index.bytes);
    writeFileSync(join(keep, "index.json.minisig"), result.index.signature);
    writeFileSync(join(keep, "throwaway.pub"), generated.publicText);
  }
}

main(process.argv.slice(2)).catch((e) => {
  console.error(`dry-run: ${e.message}`);
  process.exit(1);
});
