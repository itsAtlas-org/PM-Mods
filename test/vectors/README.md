<!--
SPDX-FileCopyrightText: 2026 Bobby Yu
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Test vectors

- `pm-index-vector.json` and `pm-index-vector.comment.txt`: copied byte for byte from PM's
  `src-tauri/src/mods/index.rs` (`the_index_format_and_its_trusted_comment_are_pinned`). The JSON has no
  trailing newline; the comment has tabs.
- `throwaway-index.json`, `throwaway-index.json.minisig`, `throwaway.pub`: an index and its signature made
  by this repo's tooling with a THROWAWAY key (made with `npx tauri signer generate`, a test password, in a
  scratch folder, secret destroyed, never committed). PM's own `verify_index` and `package::verify` accepted
  this pair with `throwaway.pub` trusted as the dev test key (see the README, "Cross-check with PM"). Only
  the public key is here, so it can verify and cannot sign. It is not an Atlas key and PM trusts it nowhere.

- `tauri-signer.pub`, `tauri-signer-message.txt`, `tauri-signer-message.txt.sig`: a throwaway key made by
  `npx tauri signer generate` (test password, scratch folder) and a file signed by `npx tauri signer sign` with
  it: the `.pub` and `.sig` exactly as Tauri writes them (base64 of the minisign text). They pin that this
  repo's verifier takes what a real rsign2 signer writes. `tauri-signer-package.bin` is a signed package
  (`atlas.map` 1.1.0, the helpers' fixture) signed by this repo's tooling with the same key; PM's own
  `package::verify` accepted it with `tauri-signer.pub` as the trusted key, and `minisign-verify` (PM's verifier
  crate) accepted the message signature (the README's cross-check procedure, run 2026-11-18). The `.bin`
  extension is deliberate: `*.pmmod` is never committed. The key's SECRET is not committed, not even encrypted
  under a published password: that rule has no exception. The encrypted-key layout `loadSecretKey` reads is
  instead checked live against the Tauri CLI by `test/real-signer.test.mjs` when `TAURI_CLI` is set.
