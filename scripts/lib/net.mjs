// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Reading the public release URLs. No token, no cookies: the repo is public and every byte read here is
// checked by signature or sha256 before it is used, so the host is not the trust root. A generic
// User-Agent only (nothing about the person or the project beyond the repo being read).

import { refuse } from "./rules.mjs";

const USER_AGENT = "PM-mods-pipeline/1";

/** GET a public https URL. Returns the bytes, or null on 404. Anything else that isn't 200 throws. */
export async function getPublic(url, maxBytes) {
  if (!url.startsWith("https://")) refuse(`${url} isn't https`);
  const res = await fetch(url, { redirect: "follow", headers: { "user-agent": USER_AGENT } });
  if (res.status === 404) return null;
  if (res.status !== 200) refuse(`${url} answered ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  if (bytes.length > maxBytes) refuse(`${url} is larger than ${maxBytes} bytes`);
  return bytes;
}
