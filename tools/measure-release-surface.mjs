#!/usr/bin/env node
// measure-release-surface — what a stranger reads on the RELEASES page, and
// whether every claim on it is true.
//
// WHY (measured 2026-11-05, this repo):
//   The tag a stranger installs from and the page a stranger READS are two
//   different surfaces, and nothing in the repo kept them honest:
//     * The GitHub Releases page listed exactly one release, v0.1.0, tagged
//       "Latest" (published 2026-11-01). Its tag tree is the one measured
//       defective in research/install-path-v0.1.0-2026-11-05.json: the
//       manifest still carries "private": true (unpublishable) and its README
//       has no quickstart at all.
//     * Its body claims "206/206 tests" and lists what you can do "today" —
//       a claim about a tree that the repo itself measured as defective.
//     * Meanwhile v0.2.0 (tag 14f8e1c, 318/318 local, CI 41946845051
//       success, install path measured "clean" in
//       research/install-path-v0.2.0-2026-11-05.json) had NO release page
//       at all: a reader who opens Releases sees the stale tag, and a
//       reader who installs from the newest tag reads a page that does not
//       exist.
//   The install-path instrument measures the TAG; this one measures the
//   PAGE — the two can disagree, and did.
//
// WHAT IS MEASURED (per published release, plus the newest tag):
//   C1 the newest semver tag in the repo has a release page
//      -> defect missing-release-for-newest-tag
//   C2 the release GitHub marks "Latest" is the newest tag
//      -> defect stale-latest-release
//   C3 the tag TREE behind each release is publishable and stranger-usable:
//      manifest not "private": true, README carries the owner-only
//      quickstart ("umask 077"), README documents an install command, README
//      does not advertise a cargo install (this repo has no Cargo.toml),
//      README shows a client API that actually exists
//      -> defects tag-private-true, tag-no-quickstart, tag-no-install-command,
//         tag-advertises-cargo-install, tag-nonexistent-api
//   C4 the release BODY makes no claim that is false where it is checkable:
//      it names an install command for its own tag, does not advertise a
//      cargo install, does not show an API that does not exist, and states
//      at least one limit (no outside users / not an audit)
//      -> defects body-no-install-command, body-advertises-cargo-install,
//         body-nonexistent-api, body-no-limits
//
// FALSIFICATION RULES (the crates.io-403 lesson, generalized):
//   * A NETWORK failure is never an absence. If the release list cannot be
//     fetched authoritatively, the run is NO VERDICT (exit 3).
//   * The nonexistent-API rule scans CODE BLOCKS only. A prose sentence
//     that MENTIONS a wrong API (e.g. "Signerd.connect does not exist") is
//     not a claim about the API — flagging it would be a false positive.
//   * Every verdict is derived by a PURE function (derive) so the rules can
//     be pinned offline, without network.
//
// Usage: node tools/measure-release-surface.mjs [--out file]
//   Exit 0 = measured (clean or defective), 3 = no verdict.
'use strict';

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO = process.env.SIGNERD_RELEASE_REPO || 'auroraxo/signerd';
const QUICKSTART_ANCHOR = 'umask 077';
const REAL_CLIENT_API = 'signViaDaemon';
const KNOWN_ABSENT_APIS = ['Signerd.connect', 'signerd.connect'];

// ---------------------------------------------------------------- pure rules

export function semverOf(tag) {
  const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(String(tag || ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function newestSemverTag(tags) {
  let best = null;
  let bestKey = null;
  for (const t of tags || []) {
    const k = semverOf(t);
    if (!k) continue;
    if (!bestKey || k[0] > bestKey[0] || (k[0] === bestKey[0] && (k[1] > bestKey[1] || (k[1] === bestKey[1] && k[2] > bestKey[2])))) {
      best = t;
      bestKey = k;
    }
  }
  return best;
}

// GitHub marks the "Latest" badge on the most recently PUBLISHED, non-draft,
// non-prerelease release — not the highest semver. Both facts are needed:
// they disagree exactly when someone publishes an older tag later, and that
// is still a stale surface for a reader.
//
// The releases API returns newest-created first, but that is an ordering the
// caller must not have to trust: the badge is derived from the release's own
// published/created timestamp, so a reordered array cannot silently change
// the verdict.
export function latestReleaseOf(releases) {
  const published = (releases || []).filter((r) => r && !r.draft && !r.prerelease);
  if (!published.length) return null;
  const stamp = (r) => Date.parse(r.published_at || r.publishedAt || r.created_at || r.createdAt || '') || 0;
  return published
    .slice()
    .sort((a, b) => stamp(b) - stamp(a))[0];
}

// Only fenced code blocks are scanned for API claims.
export function codeBlocks(body) {
  const out = [];
  const re = /```[^\n]*\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(String(body || '')))) out.push(m[1]);
  return out;
}

export function apiClaimsIn(body) {
  const blocks = codeBlocks(body);
  const found = [];
  for (const b of blocks) {
    for (const api of KNOWN_ABSENT_APIS) {
      if (new RegExp(api.replace('.', '\\.') + '\\s*\\(').test(b)) found.push(api);
    }
  }
  return found;
}

export function bodyHasLimitStatement(body) {
  const s = String(body || '').toLowerCase();
  return (
    s.includes('no outside user') ||
    s.includes('not a professional audit') ||
    s.includes('no audit') ||
    s.includes('not audited') ||
    s.includes('user zero')
  );
}

// tree: { manifest: object|null, readme: string|null }
// body: string|null
export function releaseDefects(tag, tree, body) {
  const defects = [];
  const manifest = tree && tree.manifest;
  const readme = tree && typeof tree.readme === 'string' ? tree.readme : null;

  // --- C3: the tag tree behind the release
  if (!manifest) defects.push('tag-manifest-unreadable');
  else if (manifest.private === true) defects.push('tag-private-true');

  if (readme === null) defects.push('tag-readme-unreadable');
  else {
    if (!readme.includes(QUICKSTART_ANCHOR)) defects.push('tag-no-quickstart');
    if (!readme.includes('npm install github:auroraxo/signerd#')) defects.push('tag-no-install-command');
    if (readme.includes('cargo install')) defects.push('tag-advertises-cargo-install');
    // The README shows a client snippet; if it shows a client API, the API
    // must be one that exists in this repo's exports. Scanned in CODE
    // BLOCKS only, so prose that merely mentions a wrong API is not a
    // claim (the release-contract lesson: a naive substring rule flags its
    // own correction prose).
    const readmeClaims = apiClaimsIn(readme);
    if (readmeClaims.length) defects.push('tag-nonexistent-api');
    else if (readme.includes('require(') && !readme.includes(REAL_CLIENT_API)) defects.push('tag-nonexistent-api');
  }

  // --- C4: the release body
  const b = typeof body === 'string' ? body : null;
  if (b === null) defects.push('body-unreadable');
  else {
    // A release page must hand a stranger a working install path: an npm
    // git-tag command for ANY tag of this repo (a superseded page that
    // recommends the newer tag satisfies this; a page with no working
    // install command is the defect).
    if (!/npm install github:auroraxo\/signerd#v\d/i.test(b)) defects.push('body-no-install-command');
    if (b.includes('cargo install')) defects.push('body-advertises-cargo-install');
    const claims = apiClaimsIn(b);
    if (claims.length) defects.push('body-nonexistent-api');
    if (!bodyHasLimitStatement(b)) defects.push('body-no-limits');
  }

  return defects;
}

// releases: [{tag, body, draft, prerelease}]
// tags:    [string]  (all tags in the repo)
// trees:   { [tag]: { manifest, readme } }
export function derive({ releases, tags, trees }) {
  const out = { verdict: 'clean', defects: [], perRelease: {}, noVerdict: false, reason: null };
  const fail = (reason) => { out.noVerdict = true; out.reason = reason; out.verdict = 'no-verdict'; return out; };

  if (!Array.isArray(releases) || !Array.isArray(tags)) return fail('malformed-input');

  const newest = newestSemverTag(tags);
  out.newestTag = newest;

  const byTag = new Map();
  for (const r of releases || []) {
    if (!r || r.draft) continue;
    byTag.set(r.tag, r);
  }

  // C1 — the newest tag must have a release page
  if (newest && !byTag.has(newest)) out.defects.push('missing-release-for-newest-tag');

  // C2 — the "Latest" badge must point at the newest tag
  const latest = latestReleaseOf(releases);
  out.latestTag = latest ? latest.tag : null;
  if (latest && newest && latest.tag !== newest) out.defects.push('stale-latest-release');

  // C3/C4 — per release
  for (const r of byTag.values()) {
    const tree = (trees || {})[r.tag];
    const defects = releaseDefects(r.tag, tree, r.body);
    out.perRelease[r.tag] = { defects };
    for (const d of defects) out.defects.push(`${r.tag}:${d}`);
    // An install command that names a tag this repo does not have is a
    // false claim (the PR-#280 class: a command that cannot work).
    const m = /npm install github:auroraxo\/signerd#(v[\d.]+)/i.exec(String(r.body || ''));
    if (m && !tags.includes(m[1])) out.defects.push(`${r.tag}:body-install-tag-missing`);
  }

  if (out.defects.length) out.verdict = `defective:${out.defects.join('+')}`;
  return out;
}

// ------------------------------------------------------------- live measure

function ghApi(pathname) {
  const res = execFileSync('gh', ['api', pathname], { encoding: 'utf8', timeout: 60000 });
  return JSON.parse(res);
}

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' });
}

function gitQuiet(args) {
  try {
    return git(args);
  } catch {
    return null;
  }
}

export function measure(outPath) {
  const report = { measuredAt: new Date().toISOString(), repo: REPO, surfaces: {} };

  // 1. the release list — authoritative or nothing
  let releases;
  try {
    releases = ghApi(`repos/${REPO}/releases?per_page=100`);
  } catch (err) {
    const msg = `gh api repos/${REPO}/releases failed: ${String(err.message).split('\n')[0]}`;
    report.noVerdict = true;
    report.reason = 'release-list-unavailable';
    report.error = msg;
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
    process.stderr.write(`FATAL ${msg}\n`);
    return 3;
  }
  report.surfaces.releases = (releases || []).map((r) => ({
    tag: r.tag_name,
    draft: Boolean(r.draft),
    prerelease: Boolean(r.prerelease),
    createdAt: r.created_at,
    bodyBytes: (r.body || '').length,
  }));

  // Normalize the API shape once (tag_name -> tag, published_at -> publishedAt)
  // so the pure rules never depend on GitHub's field names.
  const norm = (releases || []).map((r) => ({
    tag: r.tag_name,
    body: typeof r.body === 'string' ? r.body : null,
    draft: Boolean(r.draft),
    prerelease: Boolean(r.prerelease),
    publishedAt: r.published_at || r.created_at,
    createdAt: r.created_at,
  }));

  // 2. all tags in the repo (offline, from the local object store)
  const tags = String(git(['tag', '-l']) || '')
    .split('\n')
    .map((t) => t.trim())
    .filter(Boolean);
  report.surfaces.tags = tags;

  // 3. the tree behind each released tag
  const trees = {};
  for (const r of releases || []) {
    if (!r || r.draft) continue;
    const tag = r.tag_name;
    let manifest = null;
    let readme = null;
    const m = gitQuiet(['show', `${tag}:package.json`]);
    if (m !== null) {
      try { manifest = JSON.parse(m); } catch { manifest = null; }
    }
    const rd = gitQuiet(['show', `${tag}:README.md`]);
    if (rd !== null) readme = rd;
    trees[tag] = {
      manifest: manifest && { version: manifest.version, private: manifest.private === true },
      readme,
      readmeBytes: readme === null ? 0 : readme.length,
    };
  }
  report.surfaces.trees = trees;

  const verdict = derive({ releases: norm, tags, trees });
  report.verdict = { verdict: verdict.verdict, defects: verdict.defects, newestTag: verdict.newestTag, latestTag: verdict.latestTag };
  report.perRelease = verdict.perRelease;
  report.noVerdict = verdict.noVerdict;
  report.reason = verdict.reason;

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify(report.verdict) + `\nartifact: ${outPath}\n`);
  return verdict.noVerdict ? 3 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const i = argv.indexOf('--out');
  const out = i >= 0 && argv[i + 1] ? argv[i + 1] : path.join(ROOT, 'research', `release-surface-${new Date().toISOString().slice(0, 10)}.json`);
  process.exit(measure(out));
}
