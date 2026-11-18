<!--
SPDX-FileCopyrightText: 2026 Bobby Yu
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# PM-Mods

The signed mod catalogue for [Personal Manager](https://github.com/itsAtlas-org/Personal-Manager). PM installs
mods only as signed `.pmmod` packages listed in a signed `index.json`, both served from this repo's
releases. This repo holds what gets published and the zero-dependency tooling (Node built-ins only) that
signs it.

**State of this branch.** The signing and index tooling is here and tested. The GitHub workflows
(`publish.yml`, `dry-run.yml`), `plan.mjs`, `publish.mjs`, `build-mod.sh` and the repo gates (`check.mjs`)
are the next step; nothing in `scripts/` talks to GitHub except two read-only GETs of public release URLs.

## What is in it

| File | What it does |
| --- | --- |
| `catalogue.json` | Append-only history of published mod versions. Each entry pins id, version, tier, author, repo, commit, path, `unsignedSha256` and licence. Checked strictly; unknown fields are refused. |
| `blacklist.json` | `{"format":1,"entries":[...]}` with exactly the index's blacklist entry shape. |
| `scripts/lib/minisign.mjs` | Reads the encrypted key `npx tauri signer generate` writes (scrypt + BLAKE2b-256 checksum), signs prehashed (`ED`) with a trusted comment, verifies the way PM's `check_minisign` does. |
| `scripts/lib/zip.mjs` | The `.pmmod` zip writer (byte-identical to PM's `pack-mod.mjs`) and a strict reader. |
| `scripts/lib/package.mjs` | Reads a pre-sign package, checks it against its catalogue entry, builds the trusted comment, signs `pmmod/checksums.json`'s exact bytes, adds `pmmod/signature.minisig`, verifies. |
| `scripts/lib/index.mjs` | Builds `index.json` (PM's key order, two-space JSON, final LF), its trusted comment, signs it, and mirrors PM's `parse_index` + `verify_index`. |
| `scripts/lib/rules.mjs` | PM's rules in JavaScript: mod ids, version names and semver order, plain text, times, URLs, blacklist grammar. |
| `scripts/lib/keys.mjs` | The two pinned Atlas public keys (main `95B83457064D517B`, rollover `993CE0152A3E4E8C`). |
| `scripts/lib/pipeline.mjs` | The sign job as one function: next seq from the verified live index, sign pending packages, re-verify published ones, build and sign the index. |
| `scripts/sign.mjs` | The one step that holds the secrets. `--key-check-only` decrypts the key, requires it to be the pinned main key, signs a probe and verifies it. |
| `scripts/dry-run.mjs` | The same path with a throwaway key it makes itself (no secrets), for pull requests. |
| `scripts/verify-published.mjs` | Reads the public URLs (or `--dir`) and verifies everything under the pinned keys; prints seq and expiry. |
| `scripts/add-entry.mjs` | `node scripts/add-entry.mjs ID VERSION COMMIT SHA256` writes a catalogue entry from the manifest at that commit. |

The catalogue records the sha256 of the **pre-sign** `.pmmod` that `just build-mods` prints in PM. The
index's `sha256` is a different value (the signed file) and is computed by the sign job. Signing is
deterministic, so removing a published package's signature entry gives back exactly the pinned bytes.

## Tests

```sh
node --test "test/*.test.mjs"
PM_CHECKOUT=/path/to/Personal-Manager node --test "test/*.test.mjs"   # also pins PM's constants and keys, and
                                                                      # compares our zip writer with pack-mod's attach
```

`test/vectors/` holds PM's pinned index vector (copied from `index.rs`) and an index signed by a throwaway
key that PM's own verifier accepted (public key only; no secret is ever committed).

## Cross-check with PM (how the format was proven against the real verifier)

1. `npx tauri signer generate --ci -w scratch.key -p <test password>` from a PM checkout: a throwaway key.
2. Pack `mods/atlas.map` with PM's own `node scripts/pack-mod.mjs mods/atlas.map --commit <40 hex> --out scratch.pmmod`.
3. Sign that package and an index listing it with `lib/pipeline.mjs` and the throwaway key, treated as the main key.
4. Copy PM to a scratch folder, append a `#[cfg(test)]` test that reads those files and calls
   `index::verify_index` and `package::verify` with the throwaway public key as the dev test key, run it with
   `cargo test --offline --lib xcheck`. Negative controls (changed byte, changed signed comment, embedded Atlas
   keys alone) must refuse. PM's tree itself is never edited.

Repeat this when PM's index or package format changes. The mirror in `rules.mjs` can drift from the Rust.

## Rules this tooling keeps

- The main key signs; the rollover key never goes into CI (`sign.mjs` refuses it). `revokedKeyIds` is `[]` in CI
  and a live index that carries a revocation is never replaced by it.
- A published version is burned: an existing release asset is verified, never re-signed or replaced.
- An index that exists but does not verify stops the job; seq is never reset to 1.
- Never commit a key, a `.pmmod` or anything from `signed/` or `unsigned/` (`.gitignore` is not a boundary; the tree is public).
