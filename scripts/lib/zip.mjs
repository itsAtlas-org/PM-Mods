// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The .pmmod zip: ONE writer and a strict reader. The writer produces exactly what PM's
// scripts/pack-mod.mjs `writeZip` produces (entries sorted by byte order, STORED, DOS time 1980-01-01,
// creator Unix with mode 0644, no extra fields or comment), so a package packed by pack-mod, signed here
// (a `pmmod/signature.minisig` entry added) and written again is byte-for-byte what pack-mod's own
// `attach` makes, and removing that entry gives back the unsigned bytes the catalogue pinned.
// test/zip.test.mjs compares the two when a PM checkout is supplied (PM_CHECKOUT).
//
// Adapted from pack-mod.mjs (same licence, same author), not imported: the sign job runs no code from
// the PM checkout. Two differences, both stricter: the reader takes STORED entries only (the packer
// never deflates), and the CRC is a table here, so no Node version's zlib matters.

import { compareBytes, quote, refuse } from "./rules.mjs";

export const MANIFEST = "manifest.json";
export const LICENCE_FILE = "LICENCE.txt";
export const NOTICE_FILE = "NOTICE.txt";
export const CHECKSUMS = "pmmod/checksums.json";
export const SIGNATURE = "pmmod/signature.minisig";
export const APP_DIR = "app/";
export const PATH_CAP = 200;
export const COMPONENT_CAP = 100;
export const DEPTH_CAP = 16;
export const LIMITS = { file: 32 << 20, entries: 4096, entry: 16 << 20, total: 64 << 20 };

// ---- CRC-32 -----------------------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ---- Paths (package.rs `check_path`, ids.rs `is_device_name`) ---------------------------------------

const isDeviceName = (component) => {
  const lower = component.split(".")[0].toLowerCase();
  return ["con", "prn", "aux", "nul", "conin$", "conout$"].includes(lower) || /^(com|lpt)[0-9]$/.test(lower);
};

export function checkPath(path) {
  const bad = (why) => refuse(`${quote(path)} isn't allowed in a mod (${why})`);
  if (path === "") bad("empty name");
  if (Buffer.byteLength(path) > PATH_CAP) bad("name too long");
  if (path.startsWith("/")) bad("absolute path");
  if (path.includes("\\")) bad("backslash");
  if (path.includes(":")) bad("colon");
  const components = path.split("/");
  if (components.length > DEPTH_CAP) bad("too deep");
  for (const c of components) {
    if (c === "") bad("empty folder name");
    if (c === "." || c === "..") bad("dot segment");
    if (Buffer.byteLength(c) > COMPONENT_CAP) bad("name too long");
    if (c.endsWith(".") || c.endsWith(" ")) bad("trailing dot or space");
    if (!/^[A-Za-z0-9._+-]+$/.test(c)) bad("character");
    if (isDeviceName(c)) bad("device name");
  }
  const inLayout =
    [MANIFEST, LICENCE_FILE, NOTICE_FILE, CHECKSUMS, SIGNATURE].includes(path) || path.startsWith(APP_DIR);
  if (!inLayout) bad("outside the package layout");
}

/** No two names equal after ASCII case-folding, and no file whose folded name is also a folder. */
export function checkCaseCollisions(names) {
  const folded = new Map();
  for (const name of names) {
    const key = name.replace(/[A-Z]/g, (c) => c.toLowerCase());
    if (folded.has(key)) {
      refuse(`${quote(folded.get(key))} and ${quote(name)} are the same file on Windows and macOS`);
    }
    folded.set(key, name);
  }
  for (const name of names) {
    const lower = name.replace(/[A-Z]/g, (c) => c.toLowerCase());
    for (let i = lower.indexOf("/"); i !== -1; i = lower.indexOf("/", i + 1)) {
      if (folded.has(lower.slice(0, i))) {
        refuse(`${quote(folded.get(lower.slice(0, i)))} is a file and a folder`);
      }
    }
  }
}

// ---- The writer -------------------------------------------------------------------------------------

const DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01
const DOS_TIME = 0;
const MADE_BY_UNIX = (3 << 8) | 20;
const FILE_MODE = (0o100644 << 16) >>> 0;

/** Entries (path to bytes) as a zip, in path order. The only writer. */
export function writeZip(entries) {
  const names = [...entries.keys()].sort(compareBytes);
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const name of names) {
    const data = entries.get(name);
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(10, 4); // needed: stored
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(MADE_BY_UNIX, 4);
    central.writeUInt16LE(10, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE(FILE_MODE, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

// ---- The reader -------------------------------------------------------------------------------------

/**
 * Read a zip the way package.rs opens one: a single archive from byte 0 with nothing before, between
 * or after its entries, one entry per name, regular files only, caps enforced. Stricter than the Rust
 * reader: stored entries only, no extra fields, comments, data descriptors or zip64, none of which the
 * writer emits. Returns a Map (path to bytes) in archive order.
 */
export function readZip(buf, limits = LIMITS) {
  const bad = (why) => refuse(`it isn't a readable zip (${why})`);
  if (buf.length > limits.file) refuse("the file is too large");
  if (buf.length < 22 || buf.readUInt32LE(buf.length - 22) !== 0x06054b50) bad("no end record");
  const end = buf.length - 22;
  const count = buf.readUInt16LE(end + 10);
  const dirSize = buf.readUInt32LE(end + 12);
  const dirOffset = buf.readUInt32LE(end + 16);
  if (
    buf.readUInt16LE(end + 4) !== 0 ||
    buf.readUInt16LE(end + 6) !== 0 ||
    buf.readUInt16LE(end + 8) !== count ||
    buf.readUInt16LE(end + 20) !== 0 ||
    count === 0xffff ||
    dirSize === 0xffffffff ||
    dirOffset === 0xffffffff
  ) {
    bad("multi-disk, zip64 or commented archives aren't allowed");
  }
  if (dirOffset + dirSize !== end) bad("the directory doesn't end where the end record starts");
  if (count > limits.entries) refuse("it holds too many files");

  const entries = [];
  let at = dirOffset;
  let expectedOffset = 0;
  let total = 0;
  const seen = new Set();
  for (let n = 0; n < count; n++) {
    if (at + 46 > end || buf.readUInt32LE(at) !== 0x02014b50) bad("a directory entry is damaged");
    const madeBy = buf.readUInt16LE(at + 4);
    const flags = buf.readUInt16LE(at + 8);
    const method = buf.readUInt16LE(at + 10);
    const crc = buf.readUInt32LE(at + 16);
    const csize = buf.readUInt32LE(at + 20);
    const usize = buf.readUInt32LE(at + 24);
    const nameLen = buf.readUInt16LE(at + 28);
    const extraLen = buf.readUInt16LE(at + 30);
    const commentLen = buf.readUInt16LE(at + 32);
    const external = buf.readUInt32LE(at + 38);
    const localOffset = buf.readUInt32LE(at + 42);
    if (at + 46 + nameLen > end) bad("a directory entry is damaged");
    const nameBytes = buf.subarray(at + 46, at + 46 + nameLen);
    let name;
    try {
      name = new TextDecoder("utf-8", { fatal: true }).decode(nameBytes);
    } catch {
      refuse(`${quote(nameBytes.toString("latin1"))} isn't a plain file name`);
    }
    if (extraLen !== 0 || commentLen !== 0) bad("extra fields and comments aren't allowed");
    if (name.endsWith("/") || (external & 0x10) !== 0) refuse(`${quote(name)} is a folder entry`);
    if (madeBy >> 8 === 3) {
      const type = (external >>> 16) & 0o170000;
      if (type !== 0 && type !== 0o100000) refuse(`${quote(name)} isn't a plain file`);
    }
    checkPath(name);
    if (seen.has(name)) bad("it names one file twice");
    seen.add(name);
    if (flags !== 0) bad("a flag that isn't allowed");
    if (method !== 0) refuse(`${quote(name)} isn't stored`);
    if (usize > limits.entry) refuse(`${quote(name)} is too large`);
    total += usize;
    if (total > limits.total) refuse("its files are too large together");
    if (csize !== usize) bad("a stored entry's sizes disagree");

    // The local header agrees with the directory, and the entries tile the file with no gap.
    if (localOffset !== expectedOffset) bad("entries overlap or leave a gap");
    if (localOffset + 30 + nameLen > dirOffset || buf.readUInt32LE(localOffset) !== 0x04034b50) {
      bad("a local header is damaged");
    }
    const localName = buf.subarray(localOffset + 30, localOffset + 30 + nameLen);
    if (
      !localName.equals(nameBytes) ||
      buf.readUInt16LE(localOffset + 28) !== 0 ||
      buf.readUInt16LE(localOffset + 6) !== flags ||
      buf.readUInt16LE(localOffset + 8) !== method ||
      buf.readUInt32LE(localOffset + 14) !== crc ||
      buf.readUInt32LE(localOffset + 18) !== csize ||
      buf.readUInt32LE(localOffset + 22) !== usize
    ) {
      bad("its zip headers don't agree");
    }
    const dataStart = localOffset + 30 + nameLen;
    if (dataStart + csize > dirOffset) bad("an entry runs into the directory");
    expectedOffset = dataStart + csize;
    const data = Buffer.from(buf.subarray(dataStart, dataStart + csize));
    if (crc32(data) !== crc) refuse(`${quote(name)} couldn't be read (damaged)`);
    entries.push([name, data]);
    at += 46 + nameLen;
  }
  if (at !== end) bad("the directory has trailing bytes");
  if (expectedOffset !== dirOffset) bad("bytes between the entries and the directory");
  checkCaseCollisions(entries.map(([name]) => name));
  return new Map(entries);
}
