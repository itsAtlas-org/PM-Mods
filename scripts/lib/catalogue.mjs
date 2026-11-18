// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalogue.json and blacklist.json: the two files a human edits, checked strictly. Unknown fields are
// refused, as PM refuses them in the index.
//
// catalogue.json is APPEND-ONLY history of what has been published: one entry per (mod id, version),
// each pinning the source commit and the sha256 of the unsigned package that Bobby built locally. The
// sign job signs nothing else, and the index lists the highest version of each id.
//
//   { "format": 1, "mods": [ { id, version, tier, author, repo, commit, path, unsignedSha256, licence } ] }
//
// blacklist.json is `{ "format": 1, "entries": [...] }` with exactly the index's blacklist entry shape.

import { parseStrictJson } from "./strict-json.mjs";
import {
  blacklistEntryFault,
  canonicalBlacklistEntry,
  compareBytes,
  compareVersions,
  isCommit,
  isSha256,
  isSourceRepo,
  LICENCE,
  MAX_BLACKLIST,
  MAX_MODS,
  modIdFault,
  parseVersionName,
  plainTextFault,
  quote,
  refuse,
  releaseTag,
  tierFault,
} from "./rules.mjs";

export const CATALOGUE_FIELDS = [
  "id",
  "version",
  "tier",
  "author",
  "repo",
  "commit",
  "path",
  "unsignedSha256",
  "licence",
];

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** A path inside the source repo: relative, forward slashes, no `..`, nothing odd. */
export function sourcePathFault(p) {
  if (typeof p !== "string" || p === "") return "isn't a path";
  if (p.length > 200) return "is too long";
  if (p.startsWith("/") || p.endsWith("/")) return "must be relative, with no trailing slash";
  if (!/^[A-Za-z0-9._+/-]+$/.test(p)) return "has a character a path here may not";
  for (const part of p.split("/")) {
    if (part === "" || part === "." || part === "..") return "has an empty or dot part";
  }
  return null;
}

/** Null when `e` is a catalogue entry; otherwise what is wrong with it. */
export function catalogueEntryFault(e) {
  if (!isObject(e)) return "an entry must be an object";
  for (const k of Object.keys(e)) if (!CATALOGUE_FIELDS.includes(k)) return `unknown field ${quote(k)}`;
  for (const k of CATALOGUE_FIELDS) {
    if (!(k in e)) return `no ${k}`;
    if (typeof e[k] !== "string") return `${k} must be text`;
  }
  const id = modIdFault(e.id);
  if (id) return `id ${quote(e.id)} ${id}`;
  if (!parseVersionName(e.version)) return `version ${quote(e.version)} isn't a plain lowercase semver`;
  const tier = tierFault(e.id, e.tier);
  if (tier) return tier;
  const author = plainTextFault(e.author, 64, false, false);
  if (author) return `author ${author}`;
  if (!isSourceRepo(e.repo)) return `repo ${quote(e.repo)} must be owner/repo`;
  if (!isCommit(e.commit)) return "commit must be 40 lowercase hex digits";
  if (/^0{40}$/.test(e.commit)) return "commit is the all-zero placeholder";
  const path = sourcePathFault(e.path);
  if (path) return `path ${path}`;
  if (!isSha256(e.unsignedSha256)) return "unsignedSha256 must be 64 lowercase hex digits";
  if (e.licence !== LICENCE) return `licence must be ${LICENCE}`;
  return null;
}

const canonicalEntry = (e) => Object.fromEntries(CATALOGUE_FIELDS.map((k) => [k, e[k]]));

/** Order of the file: id by byte order, then version by semver precedence. */
export const compareEntries = (a, b) => compareBytes(a.id, b.id) || compareVersions(a.version, b.version);

/** Parse and check catalogue.json's text. Returns the entries (canonical key order). */
export function parseCatalogue(text) {
  let raw;
  try {
    raw = parseStrictJson(text);
  } catch (e) {
    refuse(`catalogue.json: ${e.message}`);
  }
  if (!isObject(raw) || Object.keys(raw).sort().join() !== "format,mods") {
    refuse('catalogue.json must be {"format": 1, "mods": [...]} and nothing else');
  }
  if (raw.format !== 1) refuse("catalogue.json: unknown format");
  if (!Array.isArray(raw.mods)) refuse("catalogue.json: mods must be a list");
  const entries = [];
  const tags = new Set();
  for (const e of raw.mods) {
    const fault = catalogueEntryFault(e);
    if (fault) refuse(`catalogue.json: ${isObject(e) && typeof e.id === "string" ? `${e.id}: ` : ""}${fault}`);
    const tag = releaseTag(e.id, e.version);
    if (tags.has(tag)) refuse(`catalogue.json: ${tag} is listed twice`);
    tags.add(tag);
    const previous = entries[entries.length - 1];
    if (previous && compareEntries(previous, e) >= 0) {
      refuse(`catalogue.json: ${tag} is out of order (ascending by id, then version)`);
    }
    entries.push(canonicalEntry(e));
  }
  // The index lists one mod per id, and PM refuses an index of more than MAX_MODS of them.
  if (new Set(entries.map((e) => e.id)).size > MAX_MODS) refuse("catalogue.json lists too many mods");
  return entries;
}

export function serializeCatalogue(entries) {
  const sorted = [...entries].sort(compareEntries).map(canonicalEntry);
  return `${JSON.stringify({ format: 1, mods: sorted }, null, 2)}\n`;
}

/** Parse and check blacklist.json's text. Returns the entries in the index's key order. */
export function parseBlacklist(text) {
  let raw;
  try {
    raw = parseStrictJson(text);
  } catch (e) {
    refuse(`blacklist.json: ${e.message}`);
  }
  if (!isObject(raw) || Object.keys(raw).sort().join() !== "entries,format") {
    refuse('blacklist.json must be {"format": 1, "entries": [...]} and nothing else');
  }
  if (raw.format !== 1) refuse("blacklist.json: unknown format");
  if (!Array.isArray(raw.entries)) refuse("blacklist.json: entries must be a list");
  if (raw.entries.length > MAX_BLACKLIST) refuse("blacklist.json is too long");
  return raw.entries.map((e, n) => {
    const fault = blacklistEntryFault(e);
    if (fault) refuse(`blacklist.json: entry ${n + 1}: ${fault}`);
    return canonicalBlacklistEntry(e);
  });
}

export function serializeBlacklist(entries) {
  return `${JSON.stringify({ format: 1, entries }, null, 2)}\n`;
}

const entryKey = (e) => JSON.stringify(canonicalEntry(e));

/** The entries of `base` that `current` drops or alters (compared as the canonical entry). */
export function changedOrRemoved(base, current) {
  const kept = new Map(current.map((e) => [releaseTag(e.id, e.version), entryKey(e)]));
  return base.filter((e) => kept.get(releaseTag(e.id, e.version)) !== entryKey(e));
}

/**
 * The entries `current` asks to be built over `base` (both parsed): the ones it adds, plus the ones it
 * amends. Entries are append-only history of what was SIGNED, so changing or removing an existing entry is
 * refused, with one exception: a release that was never published has no history to protect, and an entry
 * that can't be built or signed would otherwise sit pending forever (the publish run is red every time).
 * `unpublished` is the set of release tags the caller has confirmed are not on the public releases (a GET
 * of the asset URL answered 404); it is empty by default, so nothing is editable unless the caller says so.
 */
export function appendedEntries(base, current, { unpublished = new Set() } = {}) {
  const amended = new Set();
  for (const e of changedOrRemoved(base, current)) {
    const tag = releaseTag(e.id, e.version);
    const now = current.find((c) => releaseTag(c.id, c.version) === tag);
    if (!unpublished.has(tag)) {
      refuse(`catalogue.json: ${tag} was ${now ? "changed" : "removed"}; entries are append-only history`);
    }
    if (now) amended.add(tag);
  }
  const had = new Set(base.map((e) => releaseTag(e.id, e.version)));
  return current.filter((e) => !had.has(releaseTag(e.id, e.version)) || amended.has(releaseTag(e.id, e.version)));
}

/** Per id, the entry with the highest version (what the index lists). */
export function latestPerId(entries) {
  const best = new Map();
  for (const e of entries) {
    const b = best.get(e.id);
    if (!b || compareVersions(e.version, b.version) > 0) best.set(e.id, e);
  }
  return [...best.values()].sort((a, b) => compareBytes(a.id, b.id));
}
