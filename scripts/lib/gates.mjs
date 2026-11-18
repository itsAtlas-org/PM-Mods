// SPDX-FileCopyrightText: 2026 Bobby Yu
// SPDX-License-Identifier: AGPL-3.0-or-later

// The repo's own gates, as pure functions of text (scripts/check.mjs feeds them the tree). They hold the
// two workflows to the security shape they were written with, so a later edit that quietly widens it
// fails the pull request instead of landing:
//
//  - every `uses:` is a 40-hex commit SHA with a `# vX.Y.Z` comment (the logic of PM's check-action-pins);
//  - no pull_request_target; the dry run is `pull_request` only, with no secret and no environment;
//  - the two secrets appear only in the ONE step of the sign job, which is the only job with an
//    environment and the only one that may write;
//  - the sign job runs no npm and uses only checkout, download-artifact and upload-artifact, never checks out
//    another repo, and extracts the build artifacts outside the checkout (under ${{ runner.temp }});
//  - the top-level permissions are {} and every job states its own;
//  - no `${{ }}` inside a `run:` (untrusted input goes through env);
//  - every checkout sets persist-credentials: false; no `-latest` runner.
//
// The workflow reader is a line scanner, not a YAML parser: it knows the two-space layout these files use,
// and the floor in check.mjs makes it a failure (not a clean pass) if it ever stops finding them.

const SHA40 = /^[0-9a-f]{40}$/;
const SIGN_STEP = "Sign with the mod-signing key";
const SIGN_JOB = "sign";
const WORKFLOW_TRIGGERS = {
  "publish.yml": ["push", "schedule", "workflow_dispatch"],
  "dry-run.yml": ["pull_request"],
};

const stripComment = (s) => s.replace(/(^|\s)#.*$/, "");

/** Every `uses:` in a workflow, with its line number and trailing comment (a YAML key, not text). */
export function findUses(text) {
  const out = [];
  for (const [i, line] of text.replace(/\r\n/g, "\n").split("\n").entries()) {
    const m = line.match(/^\s*(?:-\s+)?uses:\s*(\S+)\s*(#.*)?$/);
    if (m) out.push({ line: i + 1, ref: m[1], comment: (m[2] ?? "").trim() });
  }
  return out;
}

/** What is wrong with one `uses:` reference ([] when it meets the bar). */
export function usesProblems({ ref, comment }) {
  if (ref.startsWith("./")) return [];
  if (ref.startsWith("docker://")) return ref.includes("@sha256:") ? [] : ["a docker reference needs an image digest"];
  const at = ref.lastIndexOf("@");
  if (at === -1) return ["no version: pin it to a 40-character commit SHA"];
  const problems = [];
  if (!SHA40.test(ref.slice(at + 1))) problems.push(`pinned to "${ref.slice(at + 1)}", a tag or branch; pin the 40-character commit SHA`);
  if (!comment) problems.push('no trailing "# vX.Y.Z" comment');
  return problems;
}

/** One record per line: its indentation, text, and the top-level section, job and step it sits in. */
export function scanWorkflow(text) {
  const rows = [];
  let section = null;
  let job = null;
  let step = null;
  for (const [i, raw] of text.replace(/\r\n/g, "\n").split("\n").entries()) {
    const body = raw.trim();
    const indent = raw.length - raw.trimStart().length;
    const blank = body === "" || body.startsWith("#");
    if (!blank) {
      if (indent === 0) {
        section = body.match(/^([A-Za-z_-]+):/)?.[1] ?? null;
        job = null;
        step = null;
      } else if (section === "jobs" && indent === 2) {
        job = body.match(/^([A-Za-z0-9_-]+):/)?.[1] ?? null;
        step = null;
      } else if (section === "jobs" && indent === 6 && body.startsWith("- ")) {
        step = body.match(/^- name:\s*(.*)$/)?.[1].trim() ?? `(${body.slice(2).split(":")[0]})`;
      } else if (section === "jobs" && indent === 8 && step?.startsWith("(") && body.startsWith("name:")) {
        step = body.slice(5).trim();
      }
    }
    rows.push({ n: i + 1, indent, body, blank, section, job, step });
  }
  return rows;
}

/** Text of every `run:` (its one line, or its block), with line numbers. */
function runLines(rows) {
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    const m = rows[i].blank ? null : rows[i].body.match(/^(?:- )?run:\s*(.*)$/);
    if (!m) continue;
    const keyIndent = rows[i].body.startsWith("- ") ? rows[i].indent + 2 : rows[i].indent;
    const rest = stripComment(m[1]).trim();
    if (!/^[|>][+-]?$/.test(rest)) {
      out.push({ n: rows[i].n, text: rest, job: rows[i].job });
      continue;
    }
    for (let j = i + 1; j < rows.length && (rows[j].blank || rows[j].indent > keyIndent); j++) {
      out.push({ n: rows[j].n, text: rows[j].body, job: rows[j].job });
    }
  }
  return out;
}

/** The problems with one workflow file, as readable lines ([] when it passes). `file` is its basename. */
export function workflowProblems(file, text) {
  const rows = scanWorkflow(text);
  const live = rows.filter((r) => !r.blank).map((r) => ({ ...r, body: stripComment(r.body) }));
  const problems = [];
  const bad = (n, why) => problems.push(`${file}:${n}  ${why}`);

  for (const u of findUses(text)) for (const p of usesProblems(u)) bad(u.line, `${u.ref}: ${p}`);

  const triggers = WORKFLOW_TRIGGERS[file];
  if (!triggers) bad(1, "an unknown workflow: add its expected triggers to scripts/lib/gates.mjs");
  const onKeys = live.filter((r) => r.section === "on" && r.indent === 2).map((r) => r.body.match(/^([a-z_]+):/)?.[1]);
  if (triggers && [...onKeys].sort().join() !== triggers.join()) {
    bad(1, `triggers are ${onKeys.sort().join(", ") || "none"}, expected ${triggers.join(", ")}`);
  }
  for (const r of live) if (/\bpull_request_target\b|\bworkflow_run\b/.test(r.body)) bad(r.n, "pull_request_target and workflow_run are never used here");

  // permissions: {} at the top, a block in every job, and writes only in the sign job.
  if (!live.some((r) => r.indent === 0 && r.body === "permissions: {}")) bad(1, "the top-level permissions must be `permissions: {}`");
  const jobs = [...new Set(live.filter((r) => r.section === "jobs" && r.job).map((r) => r.job))];
  if (jobs.length === 0) bad(1, "no jobs found");
  for (const job of jobs) {
    const own = live.filter((r) => r.job === job);
    if (!own.some((r) => r.indent === 4 && r.body === "permissions:")) bad(own[0].n, `job ${job} has no permissions block`);
    const runsOn = own.find((r) => r.indent === 4 && r.body.startsWith("runs-on:"));
    if (!runsOn) bad(own[0].n, `job ${job} has no runs-on`);
    else if (/latest/.test(runsOn.body)) bad(runsOn.n, "a runner image must be pinned, not -latest");
    if (!own.some((r) => r.indent === 4 && r.body.startsWith("name:"))) bad(own[0].n, `job ${job} has no name`);
  }
  for (const r of live) {
    if (/:\s*write\b/.test(r.body) && !(file === "publish.yml" && r.job === SIGN_JOB)) bad(r.n, "only the sign job may have a write permission");
    if (r.body.startsWith("environment:") && !(file === "publish.yml" && r.job === SIGN_JOB && r.body === "environment: mod-signing")) {
      bad(r.n, "only the sign job has an environment, and it is mod-signing");
    }
    if (/\bsecrets\b/.test(r.body) && !(file === "publish.yml" && r.job === SIGN_JOB && r.step === SIGN_STEP && /\$\{\{ secrets\.ATLAS_MOD_SIGNING_KEY(_PASSWORD)? \}\}$/.test(r.body))) {
      bad(r.n, `secrets are referenced only by the two env lines of the step "${SIGN_STEP}" of the sign job in publish.yml`);
    }
  }
  if (file === "publish.yml") {
    const used = live.filter((r) => /\bsecrets\b/.test(r.body)).length;
    if (used !== 2) bad(1, `expected the 2 secret references of the sign step, found ${used}`);
    if (!live.some((r) => r.job === SIGN_JOB && r.body === "environment: mod-signing")) bad(1, "the sign job must run in the mod-signing environment");
  }

  // Untrusted input goes through env, never into a run.
  for (const l of runLines(rows)) if (l.text.includes("${{")) bad(l.n, "no ${{ }} in a run: pass it through env");

  // The sign job holds the key: no package manager, no other repo's code, only the two actions it needs.
  for (const r of live.filter((x) => x.job === SIGN_JOB && file === "publish.yml")) {
    const u = r.body.match(/^(?:- )?uses:\s*(\S+)/)?.[1];
    if (u && !/^actions\/(checkout|download-artifact|upload-artifact)@/.test(u)) {
      bad(r.n, `the sign job may use only actions/checkout, actions/download-artifact and actions/upload-artifact, not ${u}`);
    }
    if (r.body.startsWith("repository:") || r.body.startsWith("path: src") || r.body.startsWith("path: tools")) bad(r.n, "the sign job checks out this repo only");
  }
  for (const l of runLines(rows).filter((x) => x.job === SIGN_JOB && file === "publish.yml")) {
    if (/\b(npm|npx|pnpm|yarn|pip|corepack|vite)\b|(^|[\s/])(src|tools)\//.test(l.text)) bad(l.n, "the sign job runs no npm and nothing from the source checkout");
  }

  // The build artifacts are extracted outside the checkout, so they never sit beside the scripts that run
  // with the key. Every download-artifact of the sign job must say where, and say $RUNNER_TEMP.
  if (file === "publish.yml") {
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].job !== SIGN_JOB || !/^(?:- )?uses:\s*actions\/download-artifact@/.test(rows[i].body)) continue;
      const itemIndent = rows[i].body.startsWith("- ") ? rows[i].indent : rows[i].indent - 2;
      let path = null;
      for (let j = i + 1; j < rows.length && (rows[j].blank || rows[j].indent > itemIndent); j++) {
        const m = stripComment(rows[j].body).trim().match(/^path:\s*(.*)$/);
        if (m) path = m[1];
      }
      if (!path || !path.startsWith("${{ runner.temp }}/")) bad(rows[i].n, "the sign job's download-artifact must extract under ${{ runner.temp }}/, outside the checkout");
    }
  }

  // Every checkout drops the credentials.
  for (let i = 0; i < rows.length; i++) {
    if (!/^(?:- )?uses:\s*actions\/checkout@/.test(rows[i].body)) continue;
    const itemIndent = rows[i].body.startsWith("- ") ? rows[i].indent : rows[i].indent - 2;
    let ok = false;
    for (let j = i + 1; j < rows.length && (rows[j].blank || rows[j].indent > itemIndent); j++) {
      if (rows[j].body === "persist-credentials: false") ok = true;
    }
    for (let j = i - 1; j >= 0 && !ok && !rows[j].blank && rows[j].indent > itemIndent && !rows[j].body.startsWith("- "); j--) {
      if (rows[j].body === "persist-credentials: false") ok = true;
    }
    if (!ok) bad(rows[i].n, "actions/checkout must set persist-credentials: false");
  }
  return problems;
}

/** Paths that must never be tracked: keys, packages, signatures outside the test vectors, dependencies. */
export function trackedFileProblems(files) {
  const problems = [];
  for (const f of files) {
    const base = f.split("/").pop();
    if (/\.(key|pem|p12|pfx|pmmod)$/i.test(base)) problems.push(`${f}: a key or a package is never committed`);
    else if (/\.minisig$/.test(base) && !f.startsWith("test/vectors/")) problems.push(`${f}: signatures are made by the pipeline, not committed (test vectors excepted)`);
    else if (/^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(base) || f.split("/").includes("node_modules")) {
      problems.push(`${f}: this repo has no dependencies and no package manager`);
    } else if (/^(signed|unsigned|out|recovered)\//.test(f)) problems.push(`${f}: build output is never committed`);
  }
  return problems;
}

const SPDX_EXT = /\.(mjs|sh|ya?ml|md)$/;

/** Files that must open with the two-line SPDX header (anywhere in their first five lines). */
export function spdxProblems(files, read) {
  const problems = [];
  for (const f of files) {
    if (!(SPDX_EXT.test(f) || f === ".gitignore")) continue;
    const head = read(f).split("\n").slice(0, 5).join("\n");
    if (!head.includes("SPDX-FileCopyrightText: 2026 Bobby Yu") || !head.includes("SPDX-License-Identifier: AGPL-3.0-or-later")) {
      problems.push(`${f}: no SPDX header`);
    }
  }
  return problems;
}
