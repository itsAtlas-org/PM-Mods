// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// index.json and its signature, as PM's src-tauri/src/mods/index.rs reads them (format 1). The writer
// below makes the bytes ONCE; the signature is over exactly those bytes; and `parseIndex` is a strict
// mirror of PM's `parse_index` that the writer's own output must pass before anything is signed.
//
// PM refuses an index WHOLE (unknown field, a mod out of order, a wrong url, a bad name...), and then
// the blacklist cannot ship either, so this mirror is the guard that matters. The pinned vector copied
// from index.rs (test/vectors/) and a table of refusals keep it in step with the Rust.
//
// The trusted comment is tab-separated: `pmindex:1`, `seq:N`, `expires:T`, then `revoke:ID` per revoked
// key. PM rebuilds it from the JSON and refuses a signature whose comment differs (CommentMismatch).

import { signPrehashed, verifySignature } from "./minisign.mjs";
import {
  blacklistEntryFault,
  canonicalBlacklistEntry,
  compareBytes,
  INDEX_CAP,
  isApiRange,
  isCommit,
  isSha256,
  isSourceRepo,
  LICENCE,
  MAX_BLACKLIST,
  MAX_MODS,
  MAX_REVOKED,
  MAX_SEQ,
  MAX_VALIDITY_DAYS,
  modIdFault,
  packageUrl,
  parseTime,
  parseVersionName,
  PERMISSIONS,
  plainTextFault,
  quote,
  Refusal,
  refuse,
  SIGNATURE_CAP,
  tierFault,
  timeText,
  VALIDITY_DAYS,
} from "./rules.mjs";
import { parseStrictJson } from "./strict-json.mjs";

export const INDEX_FORMAT = 1;
export const COMMENT_TAG = "pmindex";
const DAY_MS = 86_400_000;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

const field = (detail) => refuse(`the mod index was refused: ${detail}`, "field");

/** `pmindex:1 TAB seq:N TAB expires:T` and a `revoke:ID` for each revoked id, in order. */
export function indexTrustedComment({ seq, expires, revokedKeyIds }) {
  const exp = typeof expires === "string" ? expires : timeText(expires);
  let out = `${COMMENT_TAG}:${INDEX_FORMAT}\tseq:${seq}\texpires:${exp}`;
  for (const id of revokedKeyIds) out += `\trevoke:${id}`;
  return out;
}

/** The index entry for a mod's latest package: from the manifest's facts and the SIGNED file's sha256. */
export function indexEntryFor(facts, signedSha256) {
  return {
    id: facts.id,
    name: facts.name,
    description: facts.description,
    tier: facts.tier,
    author: facts.author,
    version: facts.version,
    api: facts.api,
    url: packageUrl(facts.id, facts.version),
    sha256: signedSha256,
    permissions: [...facts.permissions],
    sourceRepo: facts.sourceRepo,
    commit: facts.commit,
    licence: facts.licence,
  };
}

const ENTRY_KEYS = [
  "id",
  "name",
  "description",
  "tier",
  "author",
  "version",
  "api",
  "url",
  "sha256",
  "permissions",
  "sourceRepo",
  "commit",
  "licence",
];

function checkEntry(r) {
  if (!isObject(r)) field("a mod entry must be an object");
  for (const k of Object.keys(r)) if (!ENTRY_KEYS.includes(k)) field(`unknown field ${quote(k)} in a mod entry`);
  for (const k of ENTRY_KEYS) if (!(k in r)) field(`a mod entry has no ${k}`);
  for (const k of ENTRY_KEYS) {
    if (k !== "permissions" && typeof r[k] !== "string") field(`${k} must be text`);
  }
  const idFault = modIdFault(r.id);
  if (idFault) field(`mod ${quote(r.id)}: id ${idFault}`);
  const at = (what) => `${r.id}'s ${what}`;
  for (const [what, fault] of [
    ["name", plainTextFault(r.name, 40, false, false)],
    ["description", plainTextFault(r.description, 280, true, true)],
  ]) {
    if (fault) field(`${at(what)} ${fault}`);
  }
  const tierProblem = tierFault(r.id, r.tier);
  if (tierProblem) field(`${r.id}: ${tierProblem}`);
  const authorFault = plainTextFault(r.author, 64, false, false);
  if (authorFault) field(`${at("author")} ${authorFault}`);
  if (!parseVersionName(r.version)) field(`${at("version")} ${quote(r.version)}`);
  if (!isApiRange(r.api)) field(`${at("api range")} ${quote(r.api)}`);
  if (r.url !== packageUrl(r.id, r.version)) field(`${at("url")} isn't where PM-Mods publishes that version`);
  if (!isSha256(r.sha256)) field(at("sha256"));
  if (!Array.isArray(r.permissions)) field(`${at("permissions")} must be a list`);
  let previous = null;
  for (const p of r.permissions) {
    if (typeof p !== "string" || !PERMISSIONS.includes(p)) field(`${at("permission")} ${quote(p)}`);
    if (previous !== null && compareBytes(previous, p) >= 0) {
      field(at("permissions aren't ascending, or repeat one"));
    }
    previous = p;
  }
  if (!isSourceRepo(r.sourceRepo)) field(at("sourceRepo"));
  if (!isCommit(r.commit)) field(at("commit"));
  if (r.licence !== LICENCE) field(`${at("licence")} must be ${LICENCE}`);
}

const keyIdOk = (s) => typeof s === "string" && /^[0-9A-F]{16}$/.test(s);

/**
 * index.rs `parse_index`, on a parsed object. Returns {seq, issued, expires, revokedKeyIds, mods,
 * blacklist} with the times as Dates. Throws a Refusal (`field`/`format`) on the first fault.
 */
export function checkIndexObject(raw) {
  if (!isObject(raw)) field("index.json must be an object");
  const keys = ["format", "seq", "issued", "expires", "revokedKeyIds", "mods", "blacklist"];
  for (const k of Object.keys(raw)) if (!keys.includes(k)) field(`unknown field ${quote(k)}`);
  for (const k of keys) if (!(k in raw)) field(`index.json has no ${k}`);
  if (raw.format !== INDEX_FORMAT) refuse(`index.json is format ${quote(raw.format)}, and this PM reads 1`, "format");
  if (!Number.isInteger(raw.seq) || raw.seq < 1 || raw.seq > MAX_SEQ) field(`seq ${quote(raw.seq)} is out of range`);
  const issued = parseTime(raw.issued);
  if (!issued) field(`issued ${quote(raw.issued)}`);
  const expires = parseTime(raw.expires);
  if (!expires) field(`expires ${quote(raw.expires)}`);
  if (expires <= issued) field("it expires before it was issued");
  if (expires - issued > MAX_VALIDITY_DAYS * DAY_MS) {
    field(`it claims to stay good for more than ${MAX_VALIDITY_DAYS} days`);
  }
  if (!Array.isArray(raw.revokedKeyIds)) field("revokedKeyIds must be a list");
  if (raw.revokedKeyIds.length > MAX_REVOKED) field("it revokes too many keys");
  let last = null;
  for (const id of raw.revokedKeyIds) {
    if (!keyIdOk(id)) field(`key id ${quote(id)}`);
    // PM orders ids as the u64 they spell; 16 uppercase hex digits order the same as their text.
    if (last !== null && last >= id) field("revokedKeyIds isn't ascending, or names a key twice");
    last = id;
  }
  if (!Array.isArray(raw.mods)) field("mods must be a list");
  if (raw.mods.length > MAX_MODS) field("it lists too many mods");
  raw.mods.forEach((m, n) => {
    checkEntry(m);
    if (n > 0 && compareBytes(raw.mods[n - 1].id, m.id) >= 0) {
      field("mods isn't ascending by id, or lists a mod twice");
    }
  });
  if (!Array.isArray(raw.blacklist)) field("blacklist must be a list");
  if (raw.blacklist.length > MAX_BLACKLIST) field("its blacklist is too long");
  raw.blacklist.forEach((e, n) => {
    const fault = blacklistEntryFault(e);
    if (fault) field(`blacklist entry ${n + 1}: ${fault}`);
  });
  return {
    seq: raw.seq,
    issued,
    expires,
    revokedKeyIds: raw.revokedKeyIds,
    mods: raw.mods,
    blacklist: raw.blacklist,
  };
}

/** The bytes of an index.json, strictly: size cap, UTF-8, JSON that repeats no key, then the rules. */
export function parseIndex(bytes) {
  if (bytes.length > INDEX_CAP) refuse("index.json is too large", "too-large");
  let raw;
  try {
    raw = parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch (e) {
    refuse(`index.json is malformed (${e.message})`, "json");
  }
  return checkIndexObject(raw);
}

/** issued = now to the second (UTC); expires = issued + 60 days (Bobby's cadence; PM's cap is 120). */
export function validityWindow(now) {
  const issued = new Date(Math.floor(now.getTime() / 1000) * 1000);
  return { issued, expires: new Date(issued.getTime() + VALIDITY_DAYS * DAY_MS) };
}

/**
 * The index: format, seq, issued, expires, revokedKeyIds, mods, blacklist, in PM's order, two-space
 * JSON and a final LF. `mods` entries come from indexEntryFor and are sorted here by id. Returns the
 * bytes (write them once), the trusted comment, and the parsed index; refuses its own output if PM's
 * mirror would.
 */
export function buildIndex({ seq, issued, expires, mods, blacklist, revokedKeyIds = [] }) {
  const object = {
    format: INDEX_FORMAT,
    seq,
    issued: timeText(issued),
    expires: timeText(expires),
    revokedKeyIds: [...revokedKeyIds],
    mods: [...mods].sort((a, b) => compareBytes(a.id, b.id)),
    blacklist: blacklist.map(canonicalBlacklistEntry),
  };
  const bytes = Buffer.from(`${JSON.stringify(object, null, 2)}\n`, "utf8");
  const parsed = parseIndex(bytes);
  return { bytes, comment: indexTrustedComment(parsed), parsed };
}

/** Sign index.json's exact bytes with the index trusted comment. */
export function signIndex(key, bytes, parsed) {
  const signature = signPrehashed(key, bytes, indexTrustedComment(parsed), "signature from Atlas mod key");
  if (signature.length > SIGNATURE_CAP) refuse("the index signature is too large");
  return signature;
}

/**
 * index.rs `verify_index`: both files against `publicKeys` (each from parsePublicKey with a `role` of
 * main or rollover), in PM's order: sizes, signature, the comment's tag, the JSON, the comment against
 * the JSON, then who may revoke what. Returns the parsed index and who signed.
 */
export function verifyIndex(bytes, signature, publicKeys) {
  if (bytes.length > INDEX_CAP) refuse("index.json is too large", "too-large");
  if (signature.length > SIGNATURE_CAP) refuse("its signature is too large", "too-large");
  const verified = verifySignature(bytes, signature, publicKeys);
  if (verified.trustedComment.split("\t")[0] !== `${COMMENT_TAG}:${INDEX_FORMAT}`) {
    refuse("its signature isn't an index's", "trusted-comment");
  }
  const parsed = parseIndex(bytes);
  if (verified.trustedComment !== indexTrustedComment(parsed)) {
    refuse("its signed seq, expiry or revocations aren't the ones in index.json", "comment-mismatch");
  }
  for (const id of parsed.revokedKeyIds) {
    const held = publicKeys.find((k) => k.id === id);
    if (held && held.role === "rollover") refuse(`it revokes the rollover key ${id}, which nothing may revoke`, "revocation");
    if (held && verified.key.role !== "rollover") {
      refuse(`it revokes ${id}, and only the rollover key may revoke a key`, "revocation");
    }
  }
  return { parsed, signer: verified.key };
}

export { Refusal };
