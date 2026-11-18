#!/bin/sh
# SPDX-FileCopyrightText: 2026 Bobby Yu
# SPDX-License-Identifier: AGPL-3.0-or-later

# The build job's one command (and the pull-request rebuild's): build ONE catalogue entry from the
# Personal-Manager checkout at its pinned commit and pack it, the way PM's `just build-mods` does
# (justfile: vite build, pack-mod --commit, pack-mod --verify), minus `--stage`, which only feeds the
# developer-mode folder loader. Mirrors that recipe on purpose: if PM changes it, change this.
#
# Layout (the workflow makes it): ./tools = this repo, ./src = the source repo at the pinned commit.
# Run from the folder that holds both:   sh tools/scripts/build-mod.sh
#
# Env (set by the workflow from the catalogue entry; never interpolated into a command):
#   MOD_ID MOD_VERSION MOD_PATH MOD_COMMIT MOD_SHA256
# Writes out/<id>-<version>.unsigned.pmmod, prints its sha256, and FAILS when that is not MOD_SHA256 (the
# value recorded from the maintainer's own local build). The sign job recomputes everything itself; this
# step's checks are a courtesy that fails early and prints a per-file table so a difference can be found.
#
# No secrets are present in the job that runs this. It runs code from the pinned source commit
# (npm ci --ignore-scripts, vite and its config, pack-mod.mjs): the job's token is read-only, and its
# output is only ever treated as bytes by the sign job.

set -eu

fail() {
  printf 'build-mod: %s\n' "$1" >&2
  exit 1
}

: "${MOD_ID:?}" "${MOD_VERSION:?}" "${MOD_PATH:?}" "${MOD_COMMIT:?}" "${MOD_SHA256:?}"

# Shapes (the catalogue check already holds the entry to these; they decide a file name and a path here).
case "$MOD_ID" in *[!A-Za-z0-9._-]* | "") fail "MOD_ID has a character a mod id may not" ;; esac
case "$MOD_VERSION" in *[!A-Za-z0-9.+-]* | "") fail "MOD_VERSION has a character a version may not" ;; esac
case "$MOD_PATH" in /* | *..* | *[!A-Za-z0-9._/+-]* | "") fail "MOD_PATH must be a plain relative path" ;; esac
case "$MOD_COMMIT" in *[!0-9a-f]* | "") fail "MOD_COMMIT must be lowercase hex" ;; esac
[ "${#MOD_COMMIT}" -eq 40 ] || fail "MOD_COMMIT must be 40 hex digits"
case "$MOD_SHA256" in *[!0-9a-f]* | "") fail "MOD_SHA256 must be lowercase hex" ;; esac
[ "${#MOD_SHA256}" -eq 64 ] || fail "MOD_SHA256 must be 64 hex digits"

here=$(pwd)
tools="$here/tools"
out="$here/out"
[ -d "$tools/scripts" ] || fail "no ./tools checkout of PM-Mods here"
[ -d "$here/src/.git" ] || fail "no ./src checkout of the source repo here"
cd "$here/src"

head=$(git rev-parse HEAD)
[ "$head" = "$MOD_COMMIT" ] || fail "the source checkout is at $head, not the pinned $MOD_COMMIT"
[ -f "$MOD_PATH/manifest.json" ] || fail "no $MOD_PATH/manifest.json at that commit"
[ -f mods/vite.config.ts ] || fail "no mods/vite.config.ts: only a mod built the way Personal-Manager builds its own can be built here"
[ -f scripts/pack-mod.mjs ] || fail "no scripts/pack-mod.mjs at that commit"

npm ci --ignore-scripts --no-audit --no-fund
PM_MOD_DIR="$MOD_PATH" npx vite build --config mods/vite.config.ts

mkdir -p "$out"
file="$out/$MOD_ID-$MOD_VERSION.unsigned.pmmod"
[ ! -e "$file" ] || fail "$file already exists"
node scripts/pack-mod.mjs "$MOD_PATH" --commit "$MOD_COMMIT" --out "$file"
node scripts/pack-mod.mjs --verify "$file"

got=$(sha256sum "$file")
got=${got%% *}
{
  printf '### %s %s\n\n' "$MOD_ID" "$MOD_VERSION"
  printf 'commit `%s`\n\n' "$MOD_COMMIT"
  printf 'recorded `%s`\n\n' "$MOD_SHA256"
  printf 'rebuilt  `%s`\n\n' "$got"
  if [ "$got" = "$MOD_SHA256" ]; then
    printf '**MATCH**\n\n'
  else
    printf '**MISMATCH**: the build here is not the build that was recorded. Compare the files below with\n'
    printf '`node scripts/describe-package.mjs <your local .pmmod>` and find the first one that differs.\n\n'
  fi
  printf '| file | bytes | sha256 |\n| --- | --- | --- |\n'
  node "$tools/scripts/describe-package.mjs" "$file" --table
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

[ "$got" = "$MOD_SHA256" ] || fail "MISMATCH: $got is not the recorded $MOD_SHA256"
printf 'build-mod: %s %s MATCH %s\n' "$MOD_ID" "$MOD_VERSION" "$got"
