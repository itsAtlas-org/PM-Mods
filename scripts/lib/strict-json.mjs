// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// Strict JSON, as PM's scripts/pack-mod.mjs reads a manifest: the one place this repo parses JSON it did
// not write itself (a package's manifest and checksums, a published index). Copied from pack-mod.mjs
// (same licence, same author) because the sign job runs no code from the PM checkout.

import { quote, refuse } from "./rules.mjs";

/**
 * JSON that refuses what serde_json refuses and JSON.parse forgives: a repeated key (JSON.parse keeps
 * the last, so a manifest could say one thing to a reader and another to PM), a byte-order mark, a
 * lone surrogate escape, trailing text. Objects have no prototype, so a `__proto__` key is data.
 */
export function parseStrictJson(text) {
  let i = 0;
  const fail = (why) => refuse(`not valid JSON (${why} at ${i})`);
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const string = () => {
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i++];
      if (c === '"') return out;
      if (c.charCodeAt(0) < 0x20) fail("control character in string");
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = text[i++];
      const simple = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (e in simple) out += simple[e];
      else if (e === "u") {
        const hex = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
        i += 4;
        out += String.fromCharCode(parseInt(hex, 16));
      } else fail("bad escape");
    }
  };
  const value = (depth) => {
    if (depth > 64) fail("nested too deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected a key");
        const key = string();
        if (key in obj) fail(`the key ${quote(key)} is repeated`);
        ws();
        if (text[i++] !== ":") fail("expected a colon");
        obj[key] = value(depth + 1);
        ws();
        const next = text[i++];
        if (next === "}") return obj;
        if (next !== ",") fail("expected a comma or a closing brace");
      }
    }
    if (c === "[") {
      i++;
      const arr = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        ws();
        const next = text[i++];
        if (next === "]") return arr;
        if (next !== ",") fail("expected a comma or a closing bracket");
      }
    }
    if (c === '"') return string();
    const literal = /^(true|false|null|-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!literal) fail("unexpected character");
    i += literal[0].length;
    return literal[0] === "true"
      ? true
      : literal[0] === "false"
        ? false
        : literal[0] === "null"
          ? null
          : Number(literal[0]);
  };
  const result = value(0);
  ws();
  if (i !== text.length) fail("text after the value");
  // A lone surrogate (an escape or a raw one) is not a Unicode string serde would accept.
  const walk = (v) => {
    if (typeof v === "string") {
      if (!v.isWellFormed()) refuse("not valid JSON (a lone surrogate)");
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        walk(k);
        walk(x);
      }
    }
  };
  walk(result);
  return result;
}
