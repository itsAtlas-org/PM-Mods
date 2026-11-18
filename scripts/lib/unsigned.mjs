// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Reading the build job's output in the sign job. The folder is what actions/download-artifact extracted
// from artifacts that were uploaded by jobs running code from the pinned source commits, so nothing in
// it is trusted: this reads ONLY the files the catalogue names (<id>-<version>.unsigned.pmmod), each as
// a plain regular file (opened with O_NOFOLLOW and checked on the open descriptor, so a symlink, a
// device or a directory is refused, not followed), within a size cap. Anything else in the folder is a
// refusal. The caller then checks the sha256 against the catalogue before any parse (package.mjs).
//
// The folder is also meant to live outside the checkout ($RUNNER_TEMP), so even a hostile extraction
// can't replace the scripts that run with the key; this is the second layer.

import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from "node:fs";
import { join } from "node:path";

import { refuse } from "./rules.mjs";

export const UNSIGNED_SUFFIX = ".unsigned.pmmod";
export const unsignedName = (e) => `${e.id}-${e.version}${UNSIGNED_SUFFIX}`;

/**
 * @param {string} dir the download folder (it need not exist: no build)
 * @param {{id: string, version: string}[]} catalogue
 * @param {number} cap largest file accepted, in bytes
 * @returns {Map<string, Buffer>} file name -> bytes
 */
export function readUnsignedDir(dir, catalogue, cap) {
  const out = new Map();
  let top;
  try {
    top = lstatSync(dir);
  } catch (e) {
    if (e.code === "ENOENT") return out;
    throw e;
  }
  if (!top.isDirectory()) refuse(`${dir} isn't a plain folder`);
  const expected = new Set(catalogue.map(unsignedName));
  for (const name of readdirSync(dir)) {
    if (!expected.has(name)) refuse(`${name} is in the build output and is not the build of a catalogue entry`);
    const path = join(dir, name);
    let fd;
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (e) {
      refuse(`${name} can't be opened as a plain file (${e.code ?? e.message})`);
    }
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) refuse(`${name} isn't a regular file`);
      if (st.size > cap) refuse(`${name} is larger than ${cap} bytes`);
      const bytes = Buffer.alloc(st.size);
      let at = 0;
      while (at < bytes.length) {
        const n = readSync(fd, bytes, at, bytes.length - at, at);
        if (n === 0) break;
        at += n;
      }
      if (at !== bytes.length) refuse(`${name} changed while it was read`);
      out.set(name, bytes);
    } finally {
      closeSync(fd);
    }
  }
  return out;
}
