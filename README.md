<!--
SPDX-FileCopyrightText: 2026 Bobby Yu
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# PM-Mods

The signed mod catalogue for [Personal Manager](https://github.com/itsAtlas-org/Personal-Manager). PM installs
mods only as signed `.pmmod` packages listed in a signed `index.json`, both served from this repo's
releases. This repo holds what gets published and the zero-dependency tooling (Node built-ins only) that
signs it.

Everything that signs runs in one GitHub Actions job, in the `mod-signing` environment, after Bobby approves it.
Nothing else in this repo can sign, and the Personal-Manager repo holds no mod secret.

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
| `scripts/plan.mjs` | Plan job: which catalogue entries aren't published yet (a public GET of each release asset, the same test the sign job applies). |
| `scripts/build-mod.sh` | Build job: builds one entry from the source repo at its pinned commit the way PM's `just build-mods` does, packs it, verifies it, prints its sha256 against the recorded one with a per-file table. |
| `scripts/publish.mjs` | Sign job, after signing: creates the releases and replaces the `index` assets with `gh`. Never overwrites a package. |
| `scripts/describe-package.mjs` | Lists the files of a `.pmmod` with sizes and sha256s: for finding the difference when a rebuild doesn't match. |
| `scripts/check.mjs` + `scripts/lib/gates.mjs` | The repo gates the dry run runs: strict catalogue and blacklist, append-only catalogue, workflow security shape, action pins, no keys or packages tracked, SPDX headers. |
| `.github/workflows/publish.yml` | Plan, build (no secrets), sign (environment `mod-signing`). |
| `.github/workflows/dry-run.yml` | Every pull request: tests, gates, rebuild of the entries it adds, throwaway-key signing rehearsal, zizmor. No secrets, no environment. |
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

## The workflows

**Publish** (`publish.yml`) runs on a push to `main` that changes `catalogue.json` or `blacklist.json`, on the
1st of each month (the index expires after 60 days, so it is re-signed monthly), and by hand.

1. `plan` (read-only) lists the catalogue entries whose release doesn't exist yet. An empty catalogue means there
   is nothing to publish, so no signing approval is asked for.
2. `build` (read-only token, **no secrets**, one matrix job per pending entry) checks out this repo into `tools/` and
   the source repo at the entry's pinned commit into `src/`, runs `npm ci --ignore-scripts`, then
   `scripts/build-mod.sh`, and uploads the unsigned package. It shares no cache with the sign job.
3. `sign` (environment `mod-signing`, `main` only, the **only** job with `contents: write`) runs no npm and nothing
   from the source checkout. The one step that holds the two secrets, `scripts/sign.mjs`, recomputes everything
   about each package (its sha256 must equal `unsignedSha256`; its structure, manifest and checksums are
   re-read), signs with the trusted comment PM expects, builds `index.json` with `seq` one above the live verified
   index and `expires` 60 days out, and signs it. `publish.mjs` then creates the `<id>-v<version>` releases and
   replaces the assets of the `index` release; `verify-published.mjs` reads the public URLs back under the pinned
   keys and requires the live index to be the one just uploaded.

A manual run with **key_check_only** decrypts the key, requires it to be the pinned main key, signs a probe and
verifies it with the pinned public key, and uploads nothing.

**Dry run** (`dry-run.yml`, `pull_request` only) runs the tests, `check.mjs`, an index build with the real
blacklist, a rebuild of each entry the PR adds (the sha256 must **MATCH** the recorded one; the summary lists every
file's sha256), a full signing rehearsal under a key generated inside the job, and zizmor.

## Publishing, step by step (Bobby)

One time, after this branch's PR is open:

1. Let the dry run go green and merge the PR.
2. Turn on CodeQL default setup (spec section 7 step 7; code scanning needs something to scan, so it comes after
   this merge):
   ```
   gh api -X PATCH repos/itsAtlas-org/PM-Mods/code-scanning/default-setup -f state=configured
   ```
3. **Check the key before anything real.** Actions, Publish, Run workflow on `main`, tick `key_check_only`,
   approve the `mod-signing` run. Expect the log line `key OK 95B83457064D517B`. If it says the password is wrong,
   the secret has to be set again: no trailing newline in `ATLAS_MOD_SIGNING_KEY_PASSWORD`, and the key secret is the
   key file's one line of base64 (`tr -d '\n' < key | gh secret set ...`). Run this again after any change to
   `.github/` or `scripts/`, and after merging a Dependabot bump of the action pins.

Then, for each mod version (the first one is `atlas.map`):

4. In Personal-Manager, at the commit you want published, run `just build-mods` and copy two things from its
   output: the commit (`git rev-parse HEAD`) and the `sha256  file` line for
   `mods/<id>/dist/<id>-<version>.pmmod`. That is the sha256 of the **unsigned** package; it is the value you
   recorded from your own build, and CI must reproduce it. The commit has to be fetchable from the source repo
   (a pushed PR head works, a commit on `main` is best: it is the reviewed record).
5. Here: `node scripts/add-entry.mjs <id> <version> <commit> <sha256>`. It reads the manifest at that commit
   (one read-only GET) and writes `catalogue.json`; you paste no JSON. Open a PR with just that change.
6. Wait for the dry run. The **Rebuild** job must say `MATCH` for your entry. Then merge.
7. The merge starts Publish. Open the run, check the plan and the build's MATCH line, and **approve the
   `mod-signing` deployment**. The summary shows the release, the signed sha256 and the index seq and expiry.
8. Check it independently from your own machine (no secrets needed):
   `node scripts/verify-published.mjs`. It prints the **seq**.
9. PM side: raise `MIN_INDEX_SEQ` to the printed seq in the PM release that ships the mods (never above it), and
   only now merge the PM PR that removes the built-in Map in favour of the Document Map mod.

## Running it afterwards

- **Monthly.** The cron re-signs on the 1st. GitHub switches scheduled workflows off after 60 days without repo
  activity and an index lives 60 days, so put a monthly reminder in your calendar and, if the cron looks stale,
  run Publish by hand (Run workflow, key_check_only off). Two missed months and PM reports "safety list not
  checked since".
- **Emergency blacklist.** Edit `blacklist.json` (`{"format":1,"entries":[...]}`, the index's blacklist shape: either
  `id` + `versions` or `sha256`, then `action` `paused` or `removed`, and a one-line `reason`), open a PR, merge
  it, approve the run. The dry run builds an index with it first, so a malformed entry fails the PR instead of
  failing the index PM would refuse whole.
- **A new version of a mod** is a new catalogue entry (steps 4 to 9). Entries are append-only: `check.mjs` refuses a
  PR that changes or removes an existing one.
- **A burned version.** Once a release `<id>-v<version>` exists its package is final: tags can't be moved or deleted
  (the ruleset forbids it) and the pipeline refuses to replace an asset. A wrong package is fixed by the **next
  version**, plus a blacklist entry if installs of the old one must stop.
- **A mismatch.** If the build says `MISMATCH`, the build in CI isn't the build you recorded. Run
  `node scripts/describe-package.mjs <your .pmmod>` and compare it with the per-file table in the run summary:
  the first file whose sha256 differs is the cause (a different Node or OS making different bundle bytes, a
  dependency that moved, a different commit). Fix the cause. Recording CI's sha256 instead is a last resort
  because it weakens the check from "CI reproduced what I built" to "I read what CI built"; that is your call.
- **Key trouble.** The rollover key never goes into CI and no rollover signer is built here. `revokedKeyIds` is
  always `[]` from CI, and a live index that carries a revocation is never replaced by it. Rotating or revoking is
  an offline job, to be written when it is needed.

## Never

- Never move, delete or re-create a tag (`index` or `<id>-v<version>`); the ruleset forbids it, and PM's clients
  and the burned-version rule rely on it.
- Never make the `index` release immutable (Settings, "Immutable releases" stays **off**): the pipeline replaces its
  assets on every publish and can't otherwise.
- Never add a secret, an environment or `pull_request_target` to the dry run, and never reference the signing
  secrets from any other step. `check.mjs` fails the PR if you do.
- Never run Publish from a branch other than `main` (the jobs refuse, and so does the environment).
- Never commit a key, a `.pmmod` or a signature other than the test vectors.
- Never add npm, a dependency or another action to the sign job.

## Things that are yours to decide (nothing here touches them)

- GitHub's "require actions to be pinned to a full commit SHA" setting (off today; the gate in `check.mjs` already
  enforces it for this repo's own workflows).
- One required approval on pull requests, or a CODEOWNERS file for `scripts/` and `.github/`. The `mod-signing`
  environment is limited to `main`, but `main` needs a PR with **0** approvals, so a merged change to `scripts/` or
  the workflows runs with the key. Reviewing those diffs is the control.
- The 60-day expiry and monthly cadence (the format allows up to 120 days).
