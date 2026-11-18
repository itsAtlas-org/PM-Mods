// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The sign job's one step that holds the secrets (the publish workflow runs it in the mod-signing
// environment). Zero dependencies, no code from the PM checkout.
//
//   node scripts/sign.mjs --unsigned DIR --out DIR    sign what the catalogue pins, build and sign the index
//   node scripts/sign.mjs --key-check-only            decrypt the key, require it is the pinned MAIN key,
//                                                      sign a probe and verify it; writes nothing
//
// Env: ATLAS_MOD_SIGNING_KEY (the key file as `tauri signer generate` writes it, base64) and
// ATLAS_MOD_SIGNING_KEY_PASSWORD. Nothing here widens trust: the two public keys are pinned in
// lib/keys.mjs and the main key is the only one this signs with (the rollover key is offline).
// DIR/<id>-<version>.unsigned.pmmod is the build job's output for each catalogue entry not yet published.
// The output folder gets, for each NEW package, <id>-<version>.pmmod, plus index.json, index.json.minisig
// and plan.json; an existing file is never overwritten.

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

import { parseBlacklist, parseCatalogue } from "./lib/catalogue.mjs";
import { pinnedPublicKeys } from "./lib/keys.mjs";
import { loadSecretKey } from "./lib/minisign.mjs";
import { getPublic } from "./lib/net.mjs";
import { checkKey, prepareRelease } from "./lib/pipeline.mjs";
import {
  INDEX_CAP,
  INDEX_SIGNATURE_URL,
  INDEX_URL,
  packageAsset,
  packageUrl,
  SIGNATURE_CAP,
} from "./lib/rules.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE_CAP = 32 << 20;

/** A refusal of the job's own (bad input, wrong key); the CLI prints it and exits 1. */
class SignError extends Error {}
const fail = (message) => {
  throw new SignError(message);
};

const arg = (argv, name) => {
  const at = argv.indexOf(name);
  return at >= 0 ? argv[at + 1] : null;
};

/**
 * The job. The defaults are the real ones; a test passes its own `env`, `publicKeys` (an ephemeral ring),
 * `get` (reads of the public URLs) and `now`. The CLI below passes none of them, and no flag changes them.
 */
export async function signMain(
  argv,
  { env = process.env, publicKeys = pinnedPublicKeys(), get = getPublic, now = new Date(), log = console.log, catalogueDir = root } = {},
) {
  if (Number(process.versions.node.split(".")[0]) < 20) fail("Node 20 or newer is needed");
  if (!crypto.getHashes().includes("blake2b512")) fail("this Node's OpenSSL has no blake2b512");
  const secret = env.ATLAS_MOD_SIGNING_KEY;
  const password = env.ATLAS_MOD_SIGNING_KEY_PASSWORD;
  if (!secret || password === undefined) fail("ATLAS_MOD_SIGNING_KEY and ATLAS_MOD_SIGNING_KEY_PASSWORD are needed");
  const key = loadSecretKey(secret, password);

  if (argv.includes("--key-check-only")) {
    log(`key OK ${checkKey(key, publicKeys)}`);
    return;
  }

  const unsignedDir = arg(argv, "--unsigned");
  const outDir = arg(argv, "--out");
  if (!unsignedDir || !outDir) fail("--unsigned DIR and --out DIR are needed");
  const catalogue = parseCatalogue(readFileSync(join(catalogueDir, "catalogue.json"), "utf8"));
  const blacklist = parseBlacklist(readFileSync(join(catalogueDir, "blacklist.json"), "utf8"));

  const result = await prepareRelease({
    catalogue,
    blacklist,
    key,
    publicKeys,
    now,
    readUnsigned: async (e) => {
      const path = join(unsignedDir, `${e.id}-${e.version}.unsigned.pmmod`);
      return existsSync(path) ? readFileSync(path) : null;
    },
    fetchPackage: (e) => get(packageUrl(e.id, e.version), PACKAGE_CAP),
    fetchLiveIndex: async () => {
      const json = await get(INDEX_URL, INDEX_CAP);
      if (!json) return null;
      const signature = await get(INDEX_SIGNATURE_URL, SIGNATURE_CAP);
      if (!signature) throw new Error("index.json is published but index.json.minisig isn't");
      return { json, signature };
    },
  });

  mkdirSync(outDir, { recursive: true });
  const write = (name, bytes) => {
    const path = join(outDir, name);
    if (existsSync(path)) fail(`${path} already exists`);
    writeFileSync(path, bytes);
  };
  for (const p of result.packages) if (p.fresh) write(packageAsset(p.entry.id, p.entry.version), p.bytes);
  write("index.json", result.index.bytes);
  write("index.json.minisig", result.index.signature);
  const plan = {
    seq: result.seq,
    expires: result.index.parsed.expires.toISOString(),
    indexSha256: createHash("sha256").update(result.index.bytes).digest("hex"),
    packages: result.packages.map((p) => ({ tag: p.tag, asset: packageAsset(p.entry.id, p.entry.version), fresh: p.fresh, sha256: p.sha256 })),
  };
  write("plan.json", `${JSON.stringify(plan, null, 2)}\n`);

  const lines = [`index seq ${plan.seq}, expires ${plan.expires}`, ""];
  lines.push("| release | new | signed sha256 |", "| --- | --- | --- |");
  for (const p of plan.packages) lines.push(`| ${p.tag} | ${p.fresh ? "yes" : "no"} | \`${p.sha256}\` |`);
  log(lines.join("\n"));
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${lines.join("\n")}\n`);
  return plan;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  signMain(process.argv.slice(2)).catch((e) => {
    console.error(`sign: ${e.message}`);
    process.exit(1);
  });
}
