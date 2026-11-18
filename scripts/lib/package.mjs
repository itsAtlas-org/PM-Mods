// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// A .pmmod package, from the sign job's side: read the PRE-SIGN package that PM's pack-mod.mjs wrote
// (LICENCE.txt, NOTICE.txt, app/**, manifest.json, pmmod/checksums.json, no signature), check it against
// the catalogue entry that pins it, build the trusted comment, sign pmmod/checksums.json's exact bytes
// (package.rs:488), add pmmod/signature.minisig, and check the result the way PM will.
//
// The pre-sign checks here are not PM's whole manifest validation (pack-mod --verify in the build job
// and PM at install do that); they are the ones a signature makes a CLAIM about, plus the ones the
// index entry needs so that it can never be refused whole.

import { createHash } from "node:crypto";

import { signPrehashed, verifySignature } from "./minisign.mjs";
import {
  apiCommentForm,
  isAllZeroCommit,
  isCommit,
  isSha256,
  isSourceRepo,
  LICENCE,
  modIdFault,
  PACKAGE_COMMENT_KEYS,
  parseVersionName,
  PERMISSIONS,
  plainTextFault,
  quote,
  refuse,
  SIGNATURE_CAP,
  tierFault,
} from "./rules.mjs";
import { parseStrictJson } from "./strict-json.mjs";
import { CHECKSUMS, checkPath, LICENCE_FILE, MANIFEST, readZip, SIGNATURE, writeZip } from "./zip.mjs";

export const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
// ignoreBOM: keep a leading U+FEFF so the JSON parser refuses it, as serde_json does.
const utf8 = (bytes) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);

const jsonOf = (bytes, what) => {
  try {
    return parseStrictJson(utf8(bytes));
  } catch (e) {
    refuse(`${what}: ${e.message}`);
  }
};

/** `checksums.json`: sorted, no repeats, every path a package path outside `pmmod/` (package.rs). */
export function parseChecksums(bytes) {
  const bad = (why) => refuse(`its checksums are malformed (${why})`);
  const raw = jsonOf(bytes, "its checksums");
  if (!isObject(raw) || Object.keys(raw).sort().join() !== "files,format") bad("unexpected fields");
  if (raw.format !== 1) bad("unknown format");
  if (!Array.isArray(raw.files)) bad("files must be a list");
  const out = new Map();
  let previous = null;
  for (const item of raw.files) {
    if (!isObject(item) || Object.keys(item).sort().join() !== "path,sha256") bad("unexpected fields");
    if (typeof item.path !== "string" || typeof item.sha256 !== "string") bad("not text");
    checkPath(item.path);
    if (item.path.startsWith("pmmod/")) bad(`${quote(item.path)} can't be listed`);
    if (previous !== null && Buffer.compare(Buffer.from(previous), Buffer.from(item.path)) >= 0) {
      bad("not sorted, or a path is listed twice");
    }
    previous = item.path;
    if (!isSha256(item.sha256)) bad(`${quote(item.path)}'s sha256`);
    out.set(item.path, item.sha256);
  }
  for (const required of [MANIFEST, LICENCE_FILE]) {
    if (!out.has(required)) refuse(`it has no ${required}`);
  }
  return out;
}

/**
 * Open a package and check what holds it together: the zip, checksums.json, every file's sha256, that
 * the files are exactly those listed, and that a signature entry is there when `signed` and only then.
 */
export function inspectPackage(bytes, { signed }) {
  const entries = readZip(bytes);
  for (const required of [MANIFEST, CHECKSUMS]) {
    if (!entries.has(required)) refuse(`it has no ${required}`);
  }
  const hasSignature = entries.has(SIGNATURE);
  if (signed && !hasSignature) refuse("it isn't signed");
  if (!signed && hasSignature) refuse("it is already signed");
  const checksumsBytes = entries.get(CHECKSUMS);
  const checksums = parseChecksums(checksumsBytes);
  const files = [...entries.keys()].filter((p) => !p.startsWith("pmmod/"));
  for (const p of entries.keys()) {
    if (p.startsWith("pmmod/") && p !== CHECKSUMS && p !== SIGNATURE) refuse(`${quote(p)} isn't a package file`);
  }
  if (files.length !== checksums.size || files.some((p) => !checksums.has(p))) {
    refuse("the files in it aren't exactly the files its checksums list");
  }
  for (const [path, sha] of checksums) {
    if (sha256Hex(entries.get(path)) !== sha) refuse(`${quote(path)} doesn't match its checksum`);
  }
  let licence = "";
  try {
    licence = utf8(entries.get(LICENCE_FILE));
  } catch {
    // refused below, with the Rust wording
  }
  if (!(licence.includes("GNU AFFERO GENERAL PUBLIC LICENSE") && licence.includes("Version 3"))) {
    refuse(`its ${LICENCE_FILE} isn't the GNU AGPL, version 3`);
  }
  const manifest = jsonOf(entries.get(MANIFEST), "its manifest");
  return { entries, checksumsBytes, checksums, manifest, signature: signed ? entries.get(SIGNATURE) : null };
}

/**
 * What a manifest says that a signature or an index entry repeats. Refuses anything PM would refuse the
 * index entry or the trusted comment for; the rest of the manifest is pack-mod's and PM's to check.
 */
export function manifestFacts(m) {
  const bad = (why) => refuse(`its manifest is invalid (${why})`);
  if (!isObject(m)) bad("not an object");
  const text = (v, what) => {
    if (typeof v !== "string") bad(`${what} must be text`);
    return v;
  };
  const id = text(m.id, "id");
  const idFault = modIdFault(id);
  if (idFault) bad(`id ${idFault}`);
  const name = text(m.name, "name");
  const description = text(m.description, "description");
  const version = text(m.version, "version");
  if (!parseVersionName(version)) bad(`version ${quote(version)} isn't a plain lowercase semver`);
  for (const [what, fault] of [
    ["name", plainTextFault(name, 40, false, false)],
    ["description", plainTextFault(description, 280, true, true)],
  ]) {
    if (fault) bad(`${what} ${fault}`);
  }
  const api = apiCommentForm(m.apiVersion);
  if (!api) bad('apiVersion must be {"min": "M.m", "target": "M.m"} with min <= target');
  if (!isObject(m.publisher)) bad("publisher must be an object");
  const { tier, author, sourceRepo, commit } = m.publisher;
  const tierProblem = tierFault(id, tier);
  if (tierProblem) bad(tierProblem);
  const authorFault = plainTextFault(author, 64, false, false);
  if (authorFault) bad(`publisher.author ${authorFault}`);
  if (!isSourceRepo(sourceRepo)) bad("publisher.sourceRepo must be owner/repo");
  if (!isCommit(commit)) bad("publisher.commit must be 40 lowercase hex digits");
  if (m.licence !== LICENCE) bad(`licence must be ${LICENCE}`);
  const permissions = [];
  if ("permissions" in m) {
    if (!Array.isArray(m.permissions)) bad("permissions must be a list");
    for (const p of m.permissions) {
      if (!isObject(p) || typeof p.id !== "string") bad("a permission needs an id");
      if (!PERMISSIONS.includes(p.id)) bad(`unknown permission ${quote(p.id)}`);
      if (permissions.includes(p.id)) bad(`${quote(p.id)} is listed twice`);
      permissions.push(p.id);
    }
  }
  permissions.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return { id, name, description, version, tier, author, sourceRepo, commit, api, licence: m.licence, permissions };
}

/** The signed description of a package: eight TAB-joined `key:value` fields, in PM's order. */
export function trustedCommentFor(facts) {
  const values = [
    "1",
    facts.id,
    facts.version,
    facts.tier,
    facts.author,
    facts.sourceRepo,
    facts.commit,
    facts.api,
  ];
  values.forEach((v, n) => {
    if (typeof v !== "string" || v === "" || /\p{Cc}/u.test(v)) {
      refuse(`${PACKAGE_COMMENT_KEYS[n]} is empty or has a control character, so it can't be signed`);
    }
  });
  return PACKAGE_COMMENT_KEYS.map((k, n) => `${k}:${values[n]}`).join("\t");
}

/** package.rs `TrustedComment::parse`. */
export function parsePackageComment(comment) {
  const bad = (why) => refuse(`its signed description is malformed (${why})`);
  const parts = comment.split("\t");
  if (parts.length !== PACKAGE_COMMENT_KEYS.length) bad("wrong number of fields");
  const values = parts.map((part, n) => {
    const prefix = `${PACKAGE_COMMENT_KEYS[n]}:`;
    if (!part.startsWith(prefix)) bad(`expected ${PACKAGE_COMMENT_KEYS[n]}`);
    const value = part.slice(prefix.length);
    if (value === "" || /\p{Cc}/u.test(value)) bad(`${PACKAGE_COMMENT_KEYS[n]} is empty or has a control character`);
    return value;
  });
  if (values[0] !== "1") bad("not a mod's signature");
  if (values[3] !== "first" && values[3] !== "second") bad("tier");
  if (!isCommit(values[6])) bad("commit isn't 40 lowercase hex digits");
  return {
    id: values[1],
    version: values[2],
    tier: values[3],
    author: values[4],
    sourceRepo: values[5],
    commit: values[6],
    api: values[7],
  };
}

const FACT_KEYS = ["id", "version", "tier", "author", "sourceRepo", "commit", "api"];

/** Every field the comment carries equals the manifest's, exactly (package.rs `check_against`). */
export function checkCommentAgainstFacts(comment, facts) {
  for (const k of FACT_KEYS) {
    if (comment[k] !== facts[k]) refuse(`its manifest's ${k} isn't the one that was signed`);
  }
}

/** The manifest's claims equal what the catalogue pinned for this version. */
export function checkFactsAgainstEntry(facts, entry) {
  const pairs = [
    ["id", facts.id, entry.id],
    ["version", facts.version, entry.version],
    ["tier", facts.tier, entry.tier],
    ["author", facts.author, entry.author],
    ["sourceRepo", facts.sourceRepo, entry.repo],
    ["commit", facts.commit, entry.commit],
    ["licence", facts.licence, entry.licence],
  ];
  for (const [what, inPackage, pinned] of pairs) {
    if (inPackage !== pinned) {
      refuse(`${entry.id} ${entry.version}: the manifest's ${what} is ${quote(inPackage)}, the catalogue pins ${quote(pinned)}`);
    }
  }
  if (isAllZeroCommit(facts.commit)) refuse("the commit is the all-zero placeholder");
}

/**
 * Sign a pre-sign package for its catalogue `entry`: `key` is a loaded secret key, `publicKeys` the
 * keys the result must verify under (the pinned ones). Returns the signed bytes and what they claim.
 */
export function signPackage(unsignedBytes, entry, key, publicKeys) {
  if (sha256Hex(unsignedBytes) !== entry.unsignedSha256) {
    refuse(
      `${entry.id} ${entry.version}: the package built here is ${sha256Hex(unsignedBytes)}, not the ${entry.unsignedSha256} the catalogue records`,
    );
  }
  const { entries, checksumsBytes, manifest } = inspectPackage(unsignedBytes, { signed: false });
  const facts = manifestFacts(manifest);
  checkFactsAgainstEntry(facts, entry);
  const comment = trustedCommentFor(facts);
  const signature = signPrehashed(key, checksumsBytes, comment);
  if (signature.length > SIGNATURE_CAP) refuse("the signature is too large");
  const signedEntries = new Map(entries);
  signedEntries.set(SIGNATURE, signature);
  const bytes = writeZip(signedEntries);
  // Read it back as PM will, and require that taking the signature off gives the pinned bytes again.
  const back = verifyPackage(bytes, publicKeys, entry);
  return { bytes, sha256: sha256Hex(bytes), facts, comment, signer: back.signer };
}

/**
 * Verify a signed package under `publicKeys`: the signature over checksums.json, the trusted comment
 * against the manifest, and (with `entry`) against the catalogue, and that the package minus its
 * signature entry hashes to the unsigned sha256 the catalogue pinned.
 */
export function verifyPackage(bytes, publicKeys, entry = null) {
  const { entries, checksumsBytes, manifest, signature } = inspectPackage(bytes, { signed: true });
  if (signature.length > SIGNATURE_CAP) refuse("its signature is too large");
  const verified = verifySignature(checksumsBytes, signature, publicKeys);
  const comment = parsePackageComment(verified.trustedComment);
  const facts = manifestFacts(manifest);
  checkCommentAgainstFacts(comment, facts);
  const unsignedEntries = new Map(entries);
  unsignedEntries.delete(SIGNATURE);
  const unsigned = writeZip(unsignedEntries);
  const unsignedSha256 = sha256Hex(unsigned);
  if (entry) {
    checkFactsAgainstEntry(facts, entry);
    if (unsignedSha256 !== entry.unsignedSha256) {
      refuse(
        `${entry.id} ${entry.version}: without its signature the package is ${unsignedSha256}, not the ${entry.unsignedSha256} the catalogue records`,
      );
    }
  }
  return {
    facts,
    comment: verified.trustedComment,
    signer: verified.key,
    unsigned,
    unsignedSha256,
    sha256: sha256Hex(bytes),
  };
}
