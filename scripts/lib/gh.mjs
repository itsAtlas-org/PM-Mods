// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// `gh` as the publish step and the live-index reader use it: execFile with an argument list (no shell,
// nothing from a plan reaches one), and a result instead of a rejection for a non-zero exit. The callers
// take `gh` as a parameter, so tests pass a recording fake.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { refuse } from "./rules.mjs";

const run = promisify(execFile);

/** The real `gh`: resolves to {code, stdout, stderr} and never rejects on a non-zero exit. */
export async function realGh(args, env = process.env) {
  try {
    const { stdout, stderr } = await run("gh", args, { env, maxBuffer: 1 << 24 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    if (typeof e.code === "number") return { code: e.code, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
    throw e;
  }
}

/** The assets of a release (a list of names), or null when there is no such release. */
export async function releaseAssets(gh, repo, tag) {
  const r = await gh(["release", "view", tag, "--repo", repo, "--json", "assets"]);
  if (r.code === 0) return JSON.parse(r.stdout).assets.map((a) => a.name);
  if (/release not found/i.test(r.stderr)) return null;
  refuse(`gh release view ${tag} failed: ${r.stderr.trim() || `exit ${r.code}`}`);
}

/** Run `gh` and refuse on a non-zero exit. */
export async function ghOk(gh, args) {
  const r = await gh(args);
  if (r.code !== 0) refuse(`gh ${args.slice(0, 2).join(" ")} failed: ${r.stderr.trim() || `exit ${r.code}`}`);
  return r;
}
