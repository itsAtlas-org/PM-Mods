// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The rules PM applies to a mod package and to the signed index, written once in JavaScript for the
// sign job. TWO IMPLEMENTATIONS OF ONE FORMAT: PM's Rust (src-tauri/src/mods/{ids,package,index,disk}.rs)
// is the verifier that counts, and refuses a bad index WHOLE, so a bug here would block the blacklist as
// well as installs. Everything below is therefore as strict as the Rust or stricter, never looser; the
// pinned vector in test/vectors and the table-driven refusals in test/ hold the two together, and the
// Rust cross-check (README) is the check that PM itself reads what this writes.

export class Refusal extends Error {
  constructor(message, code = "refused") {
    super(message);
    this.code = code;
  }
}
export const refuse = (message, code) => {
  throw new Refusal(message, code);
};

/** A value as an error message shows it: quoted, cut and escaped, so it can't fake the text round it. */
export const quote = (s) => {
  const t = String(s);
  return JSON.stringify(t.length > 80 ? `${t.slice(0, 80)}…` : t);
};

/** Byte-order comparison of two strings (Rust's `str` order; JS's default is UTF-16 units). */
export const compareBytes = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

// ---- Constants, pinned to PM's sources by test/rules.test.mjs -------------------------------------

export const LICENCE = "AGPL-3.0-or-later";
export const PM_MODS_REPO = "itsAtlas-org/PM-Mods";
export const RELEASE_DOWNLOAD_PREFIX = `https://github.com/${PM_MODS_REPO}/releases/download/`;
export const INDEX_TAG = "index";
export const INDEX_FILE = "index.json";
export const INDEX_SIGNATURE_FILE = "index.json.minisig";
export const INDEX_URL = `${RELEASE_DOWNLOAD_PREFIX}${INDEX_TAG}/${INDEX_FILE}`;
export const INDEX_SIGNATURE_URL = `${RELEASE_DOWNLOAD_PREFIX}${INDEX_TAG}/${INDEX_SIGNATURE_FILE}`;
export const INDEX_CAP = 1 << 20;
export const SIGNATURE_CAP = 4 << 10;
export const MAX_MODS = 1000;
export const MAX_BLACKLIST = 1000;
export const MAX_REVOKED = 16;
export const MAX_SEQ = Number.MAX_SAFE_INTEGER; // (1 << 53) - 1
export const MAX_VALIDITY_DAYS = 120;
/** Bobby's cadence (index.rs): the index is good for 60 days, and the monthly run renews it. */
export const VALIDITY_DAYS = 60;
export const MAX_VERSION_LEN = 64;
export const PERMISSIONS = [
  "storage",
  "ui.tab",
  "notify",
  "projects.read",
  "tasks.read",
  "documents.meta",
  "documents.vectors",
  "documents.text",
  "calendar.read",
  "calendar.details",
  "tasks.write",
  "milestones.write",
  "documents.write",
  "ai",
  "internet",
  "links",
];
export const PACKAGE_COMMENT_KEYS = [
  "pmmod",
  "id",
  "version",
  "tier",
  "author",
  "sourceRepo",
  "commit",
  "api",
];

// ---- Small grammars ---------------------------------------------------------------------------------

export const isCommit = (s) => typeof s === "string" && /^[0-9a-f]{40}$/.test(s);
export const isSha256 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
export const isAllZeroCommit = (s) => /^0{40}$/.test(s);

const isWord = (s, max, extra, upper) =>
  typeof s === "string" &&
  s.length > 0 &&
  Buffer.byteLength(s) <= max &&
  [...s].every(
    (c) =>
      (c >= "a" && c <= "z") ||
      (c >= "0" && c <= "9") ||
      (upper && c >= "A" && c <= "Z") ||
      extra.includes(c),
  );

/** package.rs `is_source_repo`: `owner/repo`. */
export function isSourceRepo(s) {
  if (typeof s !== "string") return false;
  const at = s.indexOf("/");
  if (at < 0) return false;
  const owner = s.slice(0, at);
  const repo = s.slice(at + 1);
  return (
    isWord(owner, 39, "-", true) &&
    !owner.startsWith("-") &&
    isWord(repo, 100, "._-", true) &&
    repo !== "." &&
    repo !== ".."
  );
}

/** `M.m` with no leading zeros, as a manifest's apiVersion and the trusted comment write it. */
export function parseMajorMinor(s) {
  const m = typeof s === "string" ? /^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$/.exec(s) : null;
  return m ? [Number(m[1]), Number(m[2])] : null;
}

/** `MIN-TARGET` (package.rs `ApiRange::comment_form`), from a manifest's apiVersion; null if invalid. */
export function apiCommentForm(apiVersion) {
  if (apiVersion === null || typeof apiVersion !== "object") return null;
  const min = parseMajorMinor(apiVersion.min);
  const target = parseMajorMinor(apiVersion.target);
  if (!min || !target) return null;
  if (min[0] > target[0] || (min[0] === target[0] && min[1] > target[1])) return null;
  return `${apiVersion.min}-${apiVersion.target}`;
}

export function isApiRange(s) {
  if (typeof s !== "string") return false;
  const at = s.indexOf("-");
  if (at < 0) return false;
  const min = parseMajorMinor(s.slice(0, at));
  const target = parseMajorMinor(s.slice(at + 1));
  return !!min && !!target && (min[0] < target[0] || (min[0] === target[0] && min[1] <= target[1]));
}

// ---- Mod ids (ids.rs) -------------------------------------------------------------------------------

export function isDeviceName(component) {
  const lower = component.split(".")[0].toLowerCase();
  if (["con", "prn", "aux", "nul", "conin$", "conout$"].includes(lower)) return true;
  return /^(com|lpt)[0-9]$/.test(lower);
}

/** `ModId::parse`: two to five dot-separated parts, no device names. Returns an error text or null. */
export function modIdFault(id) {
  if (typeof id !== "string") return "isn't text";
  const segments = id.split(".");
  if (segments.length < 2 || segments.length > 5) {
    return "isn't two to five dot-separated parts";
  }
  for (const seg of segments) {
    if (!/^[a-z][a-z0-9-]{0,30}$/.test(seg)) {
      return "has a part that isn't a lowercase letter then up to 30 lowercase letters, digits or hyphens";
    }
  }
  if (segments.some(isDeviceName)) return "uses a name Windows reserves for a device";
  return null;
}

export const isReservedId = (id) => id.slice(0, 6).toLowerCase() === "atlas.";

/** `ids::check_tier` for the two signed tiers: `atlas.` is first party's, and only there. */
export function tierFault(id, tier) {
  if (tier !== "first" && tier !== "second") return "tier must be first or second";
  const reserved = isReservedId(id);
  if (reserved && tier === "first") return null;
  if (!reserved && tier === "second") return null;
  return reserved
    ? 'only Atlas\'s own mods may use an id starting "atlas."'
    : 'an Atlas mod\'s id must start "atlas."';
}

// ---- Versions (disk.rs `VersionName`, the semver crate's order) -------------------------------------

const SEMVER =
  /^(0|[1-9]\d{0,17})\.(0|[1-9]\d{0,17})\.(0|[1-9]\d{0,17})(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$/;

/**
 * `VersionName::parse`: canonical semver, lowercase, no build metadata, at most 64 bytes. Returns
 * the parsed version or null.
 */
export function parseVersionName(s) {
  if (typeof s !== "string" || s.length > MAX_VERSION_LEN) return null;
  if (!/^[a-z0-9.-]+$/.test(s)) return null;
  const m = SEMVER.exec(s);
  if (!m) return null;
  return {
    text: s,
    major: BigInt(m[1]),
    minor: BigInt(m[2]),
    patch: BigInt(m[3]),
    pre: m[4] === undefined ? [] : m[4].split("."),
  };
}

const cmpBig = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Semver precedence (semver crate `Ord`): numeric identifiers sort below alphanumeric ones. */
export function compareVersions(a, b) {
  const x = typeof a === "string" ? parseVersionName(a) : a;
  const y = typeof b === "string" ? parseVersionName(b) : b;
  if (!x || !y) throw new Refusal("not a version");
  for (const k of ["major", "minor", "patch"]) {
    const c = cmpBig(x[k], y[k]);
    if (c) return c;
  }
  if (x.pre.length === 0 && y.pre.length === 0) return 0;
  if (x.pre.length === 0) return 1;
  if (y.pre.length === 0) return -1;
  const n = Math.max(x.pre.length, y.pre.length);
  for (let i = 0; i < n; i++) {
    if (i >= x.pre.length) return -1;
    if (i >= y.pre.length) return 1;
    const p = x.pre[i];
    const q = y.pre[i];
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn) {
      const c = cmpBig(BigInt(p), BigInt(q));
      if (c) return c;
    } else if (pn) return -1;
    else if (qn) return 1;
    else {
      const c = compareBytes(p, q);
      if (c) return c;
    }
  }
  return 0;
}

// ---- Plain text (package.rs `plain_text_fault`) -----------------------------------------------------

/** Format and direction characters, zero-width ones, fillers, variation selectors and tags. */
const INVISIBLE = [
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x061c, 0x061c],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180b, 0x180f],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff0, 0xfffb],
  [0xe0000, 0xe0fff],
];
/** package.rs `MAX_STACKED_MARKS`. Node's `\p{M}` is a newer Unicode than Rust's, so stricter only. */
export const MAX_STACKED_MARKS = 4;
const MARK_RUN = new RegExp(`\\p{M}{${MAX_STACKED_MARKS + 1}}`, "u");

/** Null when `s` is acceptable; otherwise what is wrong, in package.rs's words. */
export function plainTextFault(s, maxChars, newlines, mayBeEmpty) {
  if (typeof s !== "string") return "isn't text";
  if (!s.isWellFormed()) return "has a hidden or control character";
  if (s === "") return mayBeEmpty ? null : "is empty";
  if ([...s].length > maxChars) return `is longer than ${maxChars} characters`;
  if (s.trim() !== s) return "starts or ends with a space";
  for (const ch of s) {
    const allowed = ch === " " || (newlines && ch === "\n");
    const cp = ch.codePointAt(0);
    if (
      (/\s/u.test(ch) && !allowed) ||
      (/\p{Cc}/u.test(ch) && !allowed) ||
      INVISIBLE.some(([lo, hi]) => cp >= lo && cp <= hi)
    ) {
      return "has a hidden or control character";
    }
  }
  if (MARK_RUN.test(s)) return "has too many accent marks stacked on one letter";
  return null;
}

// ---- Times (index.rs `time_text`, `parse_time`) -----------------------------------------------------

/** `YYYY-MM-DDTHH:MM:SSZ` of a Date (milliseconds dropped). */
export const timeText = (date) => `${date.toISOString().slice(0, 19)}Z`;

/** The inverse, refusing every other spelling; null if it isn't one. */
export function parseTime(s) {
  if (typeof s !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(s)) return null;
  const t = new Date(s);
  return Number.isNaN(t.getTime()) || timeText(t) !== s ? null : t;
}

// ---- Package and index URLs -------------------------------------------------------------------------

export const releaseTag = (id, version) => `${id}-v${version}`;
export const packageAsset = (id, version) => `${id}-${version}.pmmod`;
/** index.rs `package_url`. */
export const packageUrl = (id, version) =>
  `${RELEASE_DOWNLOAD_PREFIX}${releaseTag(id, version)}/${packageAsset(id, version)}`;

// ---- Blacklist entries (index.rs `parse_blacklist_entry`, `VersionRange`) ---------------------------

/** index.rs `VersionRange::parse`: null if it isn't one. */
export function parseVersionRange(s) {
  if (typeof s !== "string") return null;
  if (s === "*") return { lower: null, upper: null };
  if (s.startsWith("=")) {
    const v = parseVersionName(s.slice(1));
    return v ? { lower: [v, true], upper: [v, true] } : null;
  }
  const bound = (t) => {
    for (const [prefix, kind, inclusive] of [
      [">=", "lower", true],
      [">", "lower", false],
      ["<=", "upper", true],
      ["<", "upper", false],
    ]) {
      if (t.startsWith(prefix)) {
        const v = parseVersionName(t.slice(prefix.length));
        return v ? { kind, v, inclusive } : null;
      }
    }
    return null;
  };
  const comma = s.indexOf(", ");
  const first = bound(comma < 0 ? s : s.slice(0, comma));
  if (!first) return null;
  if (comma < 0) {
    return first.kind === "lower"
      ? { lower: [first.v, first.inclusive], upper: null }
      : { lower: null, upper: [first.v, first.inclusive] };
  }
  const second = bound(s.slice(comma + 2));
  if (!second || first.kind !== "lower" || second.kind !== "upper") return null;
  if (compareVersions(first.v, second.v) >= 0) return null;
  return { lower: [first.v, first.inclusive], upper: [second.v, second.inclusive] };
}

/** `VersionRange::lies_below`: the whole range is under `v` (a range with no upper bound never is). */
export function rangeLiesBelow(range, v) {
  if (!range.upper) return false;
  const c = compareVersions(v, range.upper[0]);
  return c > 0 || (!range.upper[1] && c === 0);
}

const BLACKLIST_KEYS = ["id", "versions", "sha256", "action", "reason", "fixedIn"];

/** Null when the entry is one PM accepts; otherwise what is wrong. */
export function blacklistEntryFault(e) {
  if (e === null || typeof e !== "object" || Array.isArray(e)) return "an entry must be an object";
  for (const k of Object.keys(e)) {
    if (!BLACKLIST_KEYS.includes(k)) return `unknown field ${quote(k)}`;
  }
  const has = (k) => k in e;
  let range = null;
  if (has("id") && has("versions") && !has("sha256")) {
    if (typeof e.id !== "string") return "id must be text";
    const fault = modIdFault(e.id);
    if (fault) return `id ${quote(e.id)} ${fault}`;
    range = parseVersionRange(e.versions);
    if (!range) return `versions ${quote(e.versions)} isn't a version range`;
  } else if (has("sha256") && !has("id") && !has("versions")) {
    if (!isSha256(e.sha256)) return `sha256 ${quote(e.sha256)}`;
  } else {
    return "an entry names an id with its versions, or a sha256, and not both";
  }
  if (e.action !== "paused" && e.action !== "removed") return `action ${quote(e.action)}`;
  const reason = plainTextFault(e.reason, 280, false, false);
  if (reason) return `reason ${reason}`;
  if (has("fixedIn")) {
    if (e.action !== "paused") return "only a pause names the version that fixes it";
    const v = parseVersionName(e.fixedIn);
    if (!v) return `fixedIn ${quote(e.fixedIn)}`;
    if (range && !rangeLiesBelow(range, v)) {
      return `fixedIn ${quote(e.fixedIn)} isn't above the versions it pauses`;
    }
  }
  return null;
}

/** The entry as the index writes it: PM's key order, nothing else. */
export function canonicalBlacklistEntry(e) {
  const out = {};
  for (const k of BLACKLIST_KEYS) if (k in e) out[k] = e[k];
  return out;
}
