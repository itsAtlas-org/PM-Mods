// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The sign job's logic as one function of its inputs, with every read passed in (so tests and the dry
// run use fakes and an ephemeral key, and sign.mjs passes the real reads). Stateless by design:
//
//   index = f(catalogue, blacklist, what is already published, the live index's seq)
//
// Signing is deterministic (Ed25519) and the writer is deterministic, so re-running after a half-finished
// publish produces the same bytes for a package, and a published package taken apart and put back
// together without its signature must equal what the catalogue pinned.

import { signIndex, buildIndex, indexEntryFor, validityWindow, verifyIndex } from "./index.mjs";
import { latestPerId } from "./catalogue.mjs";
import { signPackage, verifyPackage } from "./package.mjs";
import { MAX_SEQ, refuse, releaseTag } from "./rules.mjs";
import { signPrehashed, verifySignature } from "./minisign.mjs";

/** The key the job signs with must be the MAIN key of `publicKeys`, id and public half. */
export function assertMainKey(key, publicKeys) {
  const main = publicKeys.find((k) => k.role === "main");
  if (!main) refuse("no main key is pinned");
  if (key.id !== main.id || !key.raw.equals(main.raw)) {
    const rollover = publicKeys.find((k) => k.role === "rollover");
    refuse(
      rollover && key.id === rollover.id
        ? `the signing key is the rollover key ${key.id}, which never signs in CI`
        : `the signing key is ${key.id}, not the pinned main key ${main.id}`,
    );
  }
  return main;
}

/** `key_check_only`: the key decrypts, is the pinned main key, and signs something the pinned key verifies. */
export function checkKey(key, publicKeys) {
  const main = assertMainKey(key, publicKeys);
  const probe = Buffer.from("atlas mod signing key check");
  const signature = signPrehashed(key, probe, "pmkeycheck:1");
  verifySignature(probe, signature, [main]);
  return main.id;
}

/**
 * @param {object} p
 * @param {object[]} p.catalogue parsed catalogue entries
 * @param {object[]} p.blacklist parsed blacklist entries
 * @param {(entry) => Promise<Buffer|null>} p.readUnsigned the pre-sign build output for an entry, or null
 * @param {(entry) => Promise<Buffer|null>} p.fetchPackage the published signed package, or null if absent
 * @param {() => Promise<{json: Buffer, signature: Buffer}|null>} p.fetchLiveIndex the live index pair, or null (404)
 * @param {Date} p.now
 * @param {object} p.key a loaded secret key (minisign.loadSecretKey)
 * @param {object[]} p.publicKeys the pinned keys, each with `role`
 * @param {boolean} [p.skipUnbuilt] leave out a pending entry that has no build (instead of refusing), so one
 *   entry that can't be built doesn't stop the index's monthly renewal or an emergency blacklist. Set only
 *   when the build job is already red (the run fails loudly regardless); the entry stays pending and
 *   `skipped` lists it. A build that exists but doesn't match the catalogue is still a refusal.
 */
export async function prepareRelease({
  catalogue,
  blacklist,
  readUnsigned,
  fetchPackage,
  fetchLiveIndex,
  now,
  key,
  publicKeys,
  skipUnbuilt = false,
}) {
  assertMainKey(key, publicKeys);

  // Packages: a published version is re-verified and never re-signed; a pending one is signed fresh.
  const packages = [];
  const skipped = [];
  for (const entry of catalogue) {
    const tag = releaseTag(entry.id, entry.version);
    const published = await fetchPackage(entry);
    if (published) {
      const v = verifyPackage(published, publicKeys, entry);
      packages.push({ entry, tag, bytes: published, sha256: v.sha256, facts: v.facts, fresh: false });
      continue;
    }
    const unsigned = await readUnsigned(entry);
    if (!unsigned) {
      if (!skipUnbuilt) refuse(`${tag} isn't published and there is no build of it to sign`);
      skipped.push(entry);
      continue;
    }
    const signed = signPackage(unsigned, entry, key, publicKeys);
    packages.push({ entry, tag, bytes: signed.bytes, sha256: signed.sha256, facts: signed.facts, fresh: true });
  }

  // seq: one above the live, verified index. An index that exists but doesn't verify stops the job:
  // PM refuses a lower seq, so restarting at 1 would lock every installed PM out.
  let seq = 1;
  const live = await fetchLiveIndex();
  if (live) {
    let verified;
    try {
      verified = verifyIndex(live.json, live.signature, publicKeys);
    } catch (e) {
      refuse(`the live index doesn't verify (${e.message}); refusing to publish over it`);
    }
    if (verified.parsed.revokedKeyIds.length > 0) {
      refuse("the live index revokes a key; only the rollover key may sign that, so CI must not replace it");
    }
    seq = verified.parsed.seq + 1;
  }
  if (seq > MAX_SEQ) refuse("the index seq would pass 2^53 - 1");

  // The index offers the highest version of each id among what is signed or already published.
  if (packages.length === 0 && skipped.length > 0) refuse("no catalogue entry is published or built, so there is nothing to put in an index");
  const bySha = new Map(packages.map((p) => [p.tag, p]));
  const mods = latestPerId(packages.map((p) => p.entry)).map((entry) => {
    const p = bySha.get(releaseTag(entry.id, entry.version));
    return indexEntryFor(p.facts, p.sha256);
  });
  const { issued, expires } = validityWindow(now);
  const built = buildIndex({ seq, issued, expires, mods, blacklist });
  const signature = signIndex(key, built.bytes, built.parsed);
  // Read the pair back as PM will, under the pinned keys, before anything leaves this process.
  verifyIndex(built.bytes, signature, publicKeys);
  return {
    packages,
    index: { bytes: built.bytes, signature, comment: built.comment, parsed: built.parsed },
    seq,
    skipped,
  };
}
