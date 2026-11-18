// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Verify what is published (or a local folder laid out the same way), under the two pinned keys. No
// secrets needed; read-only.
//
//   node scripts/verify-published.mjs            reads the public release URLs
//   node scripts/verify-published.mjs --dir D    reads D/index.json, D/index.json.minisig, D/<id>-<version>.pmmod
//
// Prints the seq (PM's MIN_INDEX_SEQ is raised to it in the release that ships the mods, never above it),
// the expiry and one line per mod. Exit 1 on the first thing that doesn't verify.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

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

async function main(argv) {
  const dirAt = argv.indexOf("--dir");
  const dir = dirAt >= 0 ? argv[dirAt + 1] : null;
  const local = (name) => (existsSync(join(dir, name)) ? readFileSync(join(dir, name)) : null);
  const getIndex = async () => {
    const json = dir ? local(INDEX_FILE) : await getPublic(INDEX_URL, INDEX_CAP);
    if (!json) return null;
    const signature = dir ? local(INDEX_SIGNATURE_FILE) : await getPublic(INDEX_SIGNATURE_URL, SIGNATURE_CAP);
    if (!signature) throw new Error("index.json is there but index.json.minisig isn't");
    return { json, signature };
  };
  const getPackage = (m) => (dir ? local(packageAsset(m.id, m.version)) : getPublic(m.url, PACKAGE_CAP));
  const out = await verifyPublished({ getIndex, getPackage, publicKeys: pinnedPublicKeys() });
  console.log(`index OK: seq ${out.seq}, signed by ${out.signer}, issued ${out.issued.toISOString()}, expires ${out.expires.toISOString()}`);
  console.log(`blacklist entries: ${out.blacklist}`);
  for (const r of out.rows) console.log(`${r.id} ${r.version}  ${r.sha256}  signed by ${r.signer}`);
}

main(process.argv.slice(2)).catch((e) => {
  console.error(`verify-published: ${e.message}`);
  process.exit(1);
});
