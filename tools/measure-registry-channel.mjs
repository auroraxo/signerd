#!/usr/bin/env node
// measure-registry-channel — does the PUBLISHED PACKAGE tell the truth to
// the person who installs it FROM the registry?
//
// WHY THIS EXISTS (measured 2026-11-12, this repo)
//   signerd@0.2.18 was published to npm on 2026-11-12 16:55Z. The tarball a
//   stranger receives from that registry carries the README of the SAME
//   tree, and that README says, in its very first Install paragraph:
//
//     "No package is published to npm yet — the artifact is ready and the
//      remaining gate is credentials (see Distribution and adoption below)
//      — so the install path that exists today is the release tag:"
//
//   The reader is holding the package that the sentence says does not
//   exist. The sentence names the artifact's own channel and denies it.
//   That is the sememe defect class (a README contradicting the measured
//   registry state) in its strongest form: the contradiction travels in
//   the tarball, so it reaches the stranger who never sees this repo.
//
//   The second face: the SAME README still tells the stranger that
//   "npm whoami returns ENEEDAUTH, no ~/.npmrc ... exists, and the secret
//   store is empty", and that "What blocks publishing is credentials, not
//   the artifact". Those were true on 2026-11-04 and are false today: the
//   package IS published and the credential path is proven.
//
// WHAT THIS MEASURES
//   The registry artifact's OWN README, read from the registry (not from
//   the working tree — the working tree can differ from what was
//   published), checked for claims that the registry itself contradicts:
//     1. a "not published to npm" denial            -> registry-contradiction
//     2. a "credentials block publishing" claim      -> registry-contradiction
//     3. the absence of a registry install command  -> missing-registry-channel
//   It also verifies the registry's OWN metadata against the claim: the
//   registry says the package exists, so a README that denies it is wrong
//   by the registry's own testimony.
//
// THE CRATES.IO-403 RULE (baked in): a network failure is NEVER written as
// an absence. If the registry cannot be reached, the run is NO VERDICT
// (exit 3), never "the package is not published".
//
// Usage: node tools/measure-registry-channel.mjs [--pkg signerd] [--out file]
//   Exit 0 = measured and consistent, 3 = no verdict.
'use strict';

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const UA = 'signerd-research/0.1 (github.com/auroraxo/signerd)';
const DEFAULT_PKG = 'signerd';

// --- pure, exported for tests -------------------------------------------

// A DENIAL is a claim that the package does not exist on npm. Matched on
// the sense, not on one exact sentence, because the sentence is what
// changes; the claim is what must not survive a publish.
//
// Measured 2026-11-12 on the published signerd@0.2.18 tarball:
//   "No package is published to npm yet"        -> denial
//   "the remaining gate is credentials"         -> denial
//   "What blocks publishing is credentials"      -> denial
//   "npm whoami returns ENEEDAUTH"               -> denial
//
// A sentence that says the opposite ("is published on npm") must NOT match,
// and neither may an unrelated sentence that merely contains the word
// "credentials". Both are pinned by the tests.
export function registryDenials(readme) {
  const text = String(readme || '');
  const lower = text.toLowerCase();
  const found = [];
  const push = (id, re) => { if (re.test(lower)) found.push(id); };

  push('denies-publication', /no package is published to npm/i);
  push('denies-publication', /not published to npm/i);
  push('denies-publication', /nothing is published to npm/i);
  // "the remaining gate is credentials" / "what blocks publishing is
  // credentials" — a credential claim only counts as a denial when it is
  // about PUBLISHING this package.
  push('credentials-block-publish', /(the remaining gate is|what blocks publishing is|publishing is blocked by)\s+credentials/i);
  push('credentials-block-publish', /credentials[- ]blocked/i);
  // The live probe's own reading of the machine: "npm whoami returns
  // ENEEDAUTH" / "no ~/.npmrc ... exists" / "the secret store is empty".
  push('credentials-block-publish', /npm whoami returns [`'"]?ENEEDAUTH/i);
  push('credentials-block-publish', /secret store is empty/i);
  // "no install channel" / "the artifact is ready" — the old sememe class.
  push('denies-publication', /no install channel/i);

  return [...new Set(found)];
}

// A registry install command: `npm install <name>` where the spec
// resolves to the REGISTRY package, in a fenced code block. A mention in
// prose is not an advertisement (same rule as cargoClaimsIn in
// measure-release-surface.mjs), and a github:/git+ URL is the git-tag
// channel, not the registry channel — it does not prove the registry path
// exists.
//
// The claim is normalized to the PACKAGE NAME (version/dist-tag/range
// stripped, scope kept), because "does the README advertise this
// package's registry channel?" is one question: `signerd@0.2.18`,
// `signerd@^0.2.0` and `signerd` all answer it. Measured 2026-11-12: the
// original rule (whole spec) read a versioned install as a DIFFERENT
// claim and R6 caught it.
export function registryInstallClaims(readme) {
  const blocks = String(readme || '').match(/```[^\n]*\n([\s\S]*?)```/g) || [];
  const found = [];
  for (const raw of blocks) {
    const body = raw.replace(/^```[^\n]*\n/, '').replace(/```$/, '');
    for (const line of body.split('\n')) {
      const m = /^\s*(?:\$|>)?\s*npm\s+install\s+(\S+)\s*$/.exec(line);
      if (!m) continue;
      const spec = m[1];
      if (/^(github:|git\+|https?:|\.\.?\/|\/|[A-Za-z]:)/.test(spec)) continue; // git-tag, URL, path — not the registry
      const name = spec.replace(/@[^@]*$/, ''); // strip version/dist-tag/range, keep scope
      if (name) found.push(name);
    }
  }
  return [...new Set(found)];
}

// The pure verdict. `registryPublished` is the REGISTRY's own testimony
// (a 200 on the exact package endpoint). The README is judged against it.
//
//   published + denial present  -> registry-contradiction  (the defect)
//   published + no registry cmd -> missing-registry-channel (the gap)
//   published + clean           -> registry-consistent
//   not published               -> registry-absent (no claim to contradict)
//   unknown / unmeasured        -> no-verdict
export function deriveVerdict({ registryPublished, registryStatus, readme }) {
  if (registryStatus !== 200) {
    return { verdict: 'no-verdict', reason: `registry-status-${registryStatus}`, denials: [], registryInstallClaims: [] };
  }
  if (!registryPublished) {
    return { verdict: 'no-verdict', reason: 'registry-published-unknown', denials: [], registryInstallClaims: [] };
  }
  const denials = registryDenials(readme);
  const claims = registryInstallClaims(readme);
  if (denials.length) {
    return { verdict: 'registry-contradiction', reason: 'readme-denies-a-published-package', denials, registryInstallClaims: claims };
  }
  if (!claims.length) {
    return { verdict: 'missing-registry-channel', reason: 'readme-advertises-no-registry-install-command', denials, registryInstallClaims: claims };
  }
  return { verdict: 'registry-consistent', reason: null, denials, registryInstallClaims: claims };
}

// --- live probe ---------------------------------------------------------

function fetchJson(url) {
  const args = ['-sS', '-A', UA, '-w', '\n%{http_code}', url];
  let out;
  try {
    out = execFileSync('curl', args, { encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
  } catch (err) {
    return { status: 0, transportError: String(err.message).slice(0, 200), json: null };
  }
  const nl = out.lastIndexOf('\n');
  const status = Number(out.slice(nl + 1).trim());
  const body = out.slice(0, nl);
  let json = null;
  try { json = JSON.parse(body); } catch { /* non-JSON body */ }
  return { status, json, body };
}

// The registry's own README for the package: npm keeps it under the
// version's `readme` field, and it is also served at the plain package
// endpoint for the latest version.
function registryReadme(pkg) {
  const r = fetchJson(`https://registry.npmjs.org/${pkg}`);
  if (r.status !== 200 || !r.json) return { status: r.status, transportError: r.transportError ?? null, readme: null, source: null, meta: null };
  const latest = r.json['dist-tags']?.latest;
  const v = r.json.versions?.[latest];
  return {
    status: r.status,
    transportError: null,
    readme: typeof v?.readme === 'string' ? v.readme : (typeof r.json.readme === 'string' ? r.json.readme : null),
    source: v?.readme ? `versions.${latest}.readme` : 'package.readme',
    meta: {
      latest,
      maintainers: (r.json.maintainers ?? []).map((m) => m.name ?? m.username ?? m.login),
      repository: v?.repository?.url ?? r.json.repository?.url ?? null,
      versions: Object.keys(r.json.versions ?? {}).length,
      publishedAt: r.json.time?.[latest] ?? null,
    },
  };
}

export function main() {
  const argv = process.argv.slice(2);
  const argOf = (flag, dflt) => {
    const i = argv.indexOf(flag);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
  };
  const pkg = argOf('--pkg', DEFAULT_PKG);
  const outFile = argOf('--out', `research/registry-channel-${pkg}-${new Date().toISOString().slice(0, 10)}.json`);

  const { status, transportError, readme, source, meta } = registryReadme(pkg);
  // 404 = the registry authoritatively says the package is absent (that is
  // a measured answer, the same rule measure-publish-readiness bakes in).
  // A transport error or a 200 that carries no README text is UNMEASURED:
  // claims can never be judged without the artifact's own words.
  const reportable = status === 200 && readme !== null;
  const verdict = reportable
    ? deriveVerdict({ registryPublished: true, registryStatus: 200, readme })
    : (status === 404
      ? { verdict: 'registry-absent', reason: 'registry-404-authoritative-absence', denials: [], registryInstallClaims: [] }
      : { verdict: 'no-verdict', reason: transportError ? `transport-${transportError}` : `registry-status-${status}${readme === null ? '-readme-absent' : ''}`, denials: [], registryInstallClaims: [] });

  const report = {
    tool: 'measure-registry-channel',
    package: pkg,
    registry: 'npm',
    registryEndpoint: `registry.npmjs.org/${pkg}`,
    registryReadmeSource: source,
    registryMeta: meta,
    readmeBytes: readme === null ? 0 : readme.length,
    denials: verdict.denials,
    registryInstallClaims: verdict.registryInstallClaims,
    verdict: verdict.verdict,
    reason: verdict.reason,
    verdictBasis: 'the registry README is judged against the registry OWN testimony (the package exists); a denial is a contradiction, never a stylistic issue',
    limits: [
      'the registry README is what a consumer installing from the registry sees; the working tree is NOT read here (it can differ from what was published)',
      'a denial is detected by CLAIM shape, not by an exact sentence; a new phrasing of the same claim is a false negative until the rule is extended',
      'the probe judges consistency, not truth of adoption: a published package can still have zero outside users',
      'exit 3 (no verdict) whenever the registry does not answer; a network failure is never recorded as an absence',
    ],
  };

  mkdirSync('research', { recursive: true });
  writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');
  console.log(`report: ${outFile}`);
  console.log(`verdict: ${report.verdict}`);
  if (report.denials.length) console.log(`denials: ${report.denials.join(', ')}`);
  if (report.registryInstallClaims.length) console.log(`registry install claims: ${report.registryInstallClaims.join(', ')}`);
  process.exit(report.verdict === 'no-verdict' ? 3 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
