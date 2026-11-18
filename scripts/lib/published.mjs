// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Read-back verification of a published index and its packages, under the pinned keys, the way PM
// reads them: the index pair first, then every entry's package against the entry. Reads are passed in
// (public URLs, or a local folder), so it needs no secret and runs the same in the job and on a laptop.

import { createHash } from "node:crypto";

import { verifyIndex } from "./index.mjs";
import { verifyPackage } from "./package.mjs";
import { refuse } from "./rules.mjs";

/**
 * @param {object} p
 * @param {() => Promise<{json: Buffer, signature: Buffer}|null>} p.getIndex
 * @param {(entry) => Promise<Buffer|null>} p.getPackage entry is the index's mod entry
 * @param {object[]} p.publicKeys pinned keys with roles
 * @returns rows describing what verified
 */
export async function verifyPublished({ getIndex, getPackage, publicKeys }) {
  const pair = await getIndex();
  if (!pair) refuse("no index is published");
  const { parsed, signer } = verifyIndex(pair.json, pair.signature, publicKeys);
  const rows = [];
  for (const m of parsed.mods) {
    const bytes = await getPackage(m);
    if (!bytes) refuse(`${m.id} ${m.version}: the index lists it, but ${m.url} isn't there`);
    const v = verifyPackage(bytes, publicKeys);
    if (v.sha256 !== m.sha256) refuse(`${m.id} ${m.version}: the file is ${v.sha256}, the index says ${m.sha256}`);
    for (const [what, fromIndex, fromPackage] of [
      ["id", m.id, v.facts.id],
      ["version", m.version, v.facts.version],
      ["tier", m.tier, v.facts.tier],
      ["author", m.author, v.facts.author],
      ["sourceRepo", m.sourceRepo, v.facts.sourceRepo],
      ["commit", m.commit, v.facts.commit],
      ["api", m.api, v.facts.api],
      ["name", m.name, v.facts.name],
      ["description", m.description, v.facts.description],
      ["permissions", m.permissions.join(), v.facts.permissions.join()],
    ]) {
      if (fromIndex !== fromPackage) refuse(`${m.id} ${m.version}: the index's ${what} isn't the package's`);
    }
    rows.push({ id: m.id, version: m.version, sha256: m.sha256, signer: v.signer.id });
  }
  return {
    indexSha256: createHash("sha256").update(pair.json).digest("hex"),
    seq: parsed.seq,
    issued: parsed.issued,
    expires: parsed.expires,
    signer: signer.id,
    rows,
    blacklist: parsed.blacklist.length,
  };
}
