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
