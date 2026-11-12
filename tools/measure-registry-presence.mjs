#!/usr/bin/env node
// Measure signerd's presence on package REGISTRIES (crates.io, npm).
//
// WHY THIS EXISTS (measured, not argued)
// The foreign-use probe's limits section recorded "crates.io/npm outside
// scope (measured: crates.io 403, npm not found)". The crates.io 403 was
// reproduced on 2026-11-04 and is NOT a property of the registry: crates.io
// rejects requests without a User-Agent header (measured live: 403 without
// UA, 200 with UA, same endpoint, same minute). A client defect was recorded
// as a measured absence - exactly the failure class the foreign-use probe
// calls its most dangerous (D3/D7).
//
// WHAT THIS PROBE MEASURES
//   - exact-name lookups: /crates/signerd (crates.io), /signerd (npm).
//     404 is an AUTHORITATIVE absence for that exact name.
//   - search sweeps: q=signerd on crates.io, text=signerd on npm - they catch
//     packages that name signerd in their NAME or DESCRIPTION.
//   - positive controls per registry: a package known to exist (serde /
//     express). A registry whose control does not resolve is UNMEASURED,
//     never "zero hits".
//   - ownership attribution: a hit owned/maintained by the auroraxo account
//     is OWN distribution, not foreign use.
//
// VERDICTS (classes, never sentences)
//   registry-absence  - every surface measured, 0 foreign references
//   registry-presence - at least one verified foreign reference
//   no-verdict (exit 3) - any surface unmeasured; absence is withheld
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const UA = 'signerd-research/0.1 (github.com/auroraxo/signerd)';
// OWNERSHIP, measured 2026-11-12: the npm package WE published at 16:55Z
// carries the maintainer `sprintberlin` (the account `npm whoami` resolves
// to from this machine's token) while the GitHub account is `auroraxo`.
// With only `auroraxo` in this list, our OWN published package read as a
// foreign `name-collision` — the flattering-in-the-wrong-direction error
// this repo keeps hunting: a hit that points at MY project counted as
// someone else's. The npm id is an OWN id here.
//
// A repository URL field is DELIBERATELY not an ownership signal: a foreign
// package that links to `github.com/auroraxo/signerd` is a consumer
// (referenceClass=foreign-reference, test G5b), not our package. Only the
// MAINTAINER / OWNER identities decide ownership. The @zanii collision
// keeps its class (maintainer zanii).
const OWN_IDS = ['auroraxo', 'sprintberlin'];
const TARGET = 'signerd';
// What counts as pointing at MY project - anything else carrying the name is
// a collision (independent prior art), not foreign use.
const MY_MARKERS = ['auroraxo/signerd', 'github.com/auroraxo', 'codebyaurora'];

// --- pure, exported for tests -------------------------------------------

// crates.io mandates a User-Agent. A 403 from a UA-less client is OUR defect,
// never evidence of absence or presence.
export function classifyCratesStatus(status, hadUserAgent) {
  if (status === 200 || status === 404) return 'measured';
  if (status === 403 && !hadUserAgent) return 'unmeasured-client-defect';
  return 'unmeasured'; // 403 with UA (rate limit), 5xx, anything else
}

export function classifyNpmStatus(status) {
  if (status === 200 || status === 404) return 'measured';
  return 'unmeasured';
}

// name === target is a direct hit; a DIFFERENT name whose description names
// the target as a word is a candidate reference; everything else is noise.
export function classifyRegistryHit(pkg, target) {
  if (pkg.name === target) return 'exact-name';
  // word-boundary matches only: D1 (foreign-use) showed that a bare
  // substring match on a name this generic is pure noise (signerdialer...).
  const re = new RegExp(`\\b${target}\\b`, 'i');
  if (re.test(String(pkg.name ?? ''))) return 'name-mention';
  if (re.test(String(pkg.description ?? ''))) return 'description-mention';
  return 'noise';
}

export function isOwnPackage(pkg) {
  const people = [
    ...(pkg.owners ?? []).map((o) => o.login ?? o.id),
    ...(pkg.maintainers ?? []).map((m) => m.name ?? m.username),
  ].map(String);
  return people.some((p) => OWN_IDS.includes(p));
}

// A hit is only FOREIGN USE of signerd if it actually points at MY project.
// A package that merely carries the same NAME is a NAME COLLISION: it is
// prior art, not consumption. The live run found exactly this case
// (@zanii/signerd: same concept, published BEFORE my first commit, and
// referencing nothing of mine) - counting it as "foreign use" would have
// been a false positive in the direction that flatters.
export function classifyHitReference(hit, myMarkers) {
  const haystack = JSON.stringify(hit).toLowerCase();
  // `own` is the computed ownership flag the surfaces attach (exact hits);
  // a raw package object (owners/maintainers/repoUrl) is judged directly.
  // Measured 2026-11-12: with only the auroraxo id in OWN_IDS, OUR OWN
  // published package (maintainer sprintberlin) fell through both paths
  // and was classed name-collision.
  if (hit.own === true || isOwnPackage(hit)) return 'own';
  const linked = myMarkers.some((m) => haystack.includes(m.toLowerCase()));
  if (linked) return 'foreign-reference';
  if (hit.class === 'exact-name' || hit.class === 'name-mention') return 'name-collision';
  if (hit.class === 'description-mention') return 'incidental-mention';
  return 'noise';
}

// Absence is withheld unless EVERY surface measured AND every control ran.
// Control hits NEVER feed the foreign count: a control is a positive probe
// (serde/express), not a measurement of signerd references.
// Only foreign-REFERENCE hits flip the verdict to presence; name collisions
// and incidental mentions are recorded but do not claim foreign use.
export function decideVerdict(surfaces) {
  const controls = surfaces.filter((s) => s.kind === 'control');
  const measured = surfaces.filter((s) => s.kind !== 'control');
  if (measured.some((s) => s.status_class !== 'measured')) return 'no-verdict';
  if (controls.some((s) => s.status_class !== 'measured')) return 'no-verdict';
  const foreignRef = measured.flatMap((s) => s.hits ?? []).filter((h) => h.referenceClass === 'foreign-reference');
  if (foreignRef.length > 0) return 'registry-presence';
  return 'registry-absence';
}

// --- live probes ---------------------------------------------------------

function fetchJson(url, { userAgent = true } = {}) {
  const args = ['-sS', '-w', '\n%{http_code}', url];
  if (userAgent) args.splice(1, 0, '-A', UA);
  let out;
  try {
    out = execFileSync('curl', args, { encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
  } catch (err) {
    return { status: 0, transportError: String(err.message).slice(0, 200) };
  }
  const nl = out.lastIndexOf('\n');
  const status = Number(out.slice(nl + 1).trim());
  const body = out.slice(0, nl);
  let json = null;
  try { json = JSON.parse(body); } catch { /* non-JSON body */ }
  return { status, json };
}

function cratesExact(name) {
  const r = fetchJson(`https://crates.io/api/v1/crates/${name}`);
  return {
    registry: 'crates.io', kind: 'exact', name,
    endpoint: `crates.io/api/v1/crates/${name}`,
    status: r.status, status_class: classifyCratesStatus(r.status, true),
    exists: r.status === 200,
    owners: r.status === 200 ? (r.json.owners ?? []).map((o) => o.login) : [],
    description: r.status === 200 ? String(r.json.crate?.description ?? '').slice(0, 160) : '',
    hits: r.status === 200
      ? [{ name: r.json.crate?.name ?? name, class: 'exact-name', own: isOwnPackage({ owners: (r.json.owners ?? []).map((login) => ({ login })) }) }]
      : [],
  };
}

function cratesSearch(q) {
  const r = fetchJson(`https://crates.io/api/v1/crates?q=${encodeURIComponent(q)}&per_page=100`);
  const hits = r.status === 200
    ? (r.json.crates ?? [])
        .map((c) => ({
          name: c.name,
          description: String(c.description ?? '').slice(0, 160),
          class: classifyRegistryHit({ name: c.name, description: c.description }, q),
          downloads: c.downloads,
        }))
        .filter((h) => h.class !== 'noise')
        .map((h) => ({ ...h, own: false }))
    : [];
  return {
    registry: 'crates.io', kind: 'search', name: `crates.io search q=${q}`,
    endpoint: 'crates.io/api/v1/crates?q=...',
    status: r.status, status_class: classifyCratesStatus(r.status, true),
    hits,
  };
}

function npmExact(name) {
  const r = fetchJson(`https://registry.npmjs.org/${name}`);
  const maintainers = r.status === 200 ? (r.json.maintainers ?? []) : [];
  const repoUrl = r.status === 200
    ? (r.json.versions?.[r.json['dist-tags']?.latest]?.repository?.url ?? r.json.repository?.url ?? '')
    : '';
  return {
    registry: 'npm', kind: 'exact', name,
    endpoint: `registry.npmjs.org/${name}`,
    status: r.status, status_class: classifyNpmStatus(r.status),
    exists: r.status === 200,
    maintainers: maintainers.map((m) => m.name),
    repoUrl: String(repoUrl).slice(0, 160),
    description: r.status === 200 ? String(r.json.description ?? '').slice(0, 160) : '',
    hits: r.status === 200
      ? [{ name: r.json.name ?? name, class: 'exact-name', own: isOwnPackage({ maintainers, repoUrl }) }]
      : [],
  };
}

function npmSearch(q) {
  const r = fetchJson(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=250`);
  const hits = r.status === 200
    ? (r.json.objects ?? [])
        .map((o) => ({
          name: o.package.name,
          description: String(o.package.description ?? '').slice(0, 160),
          class: classifyRegistryHit({ name: o.package.name, description: o.package.description }, q),
        }))
        .filter((h) => h.class !== 'noise')
        .map((h) => ({ ...h, own: false }))
    : [];
  return {
    registry: 'npm', kind: 'search', name: `npm search text=${q}`,
    endpoint: 'registry.npmjs.org/-/v1/search',
    status: r.status, status_class: classifyNpmStatus(r.status),
    hits,
  };
}

// The defect reproduction: same crates.io search endpoint, UA absent vs
// present, measured back to back. This is the RED RUN for the old claim.
function clientDefectReproduction() {
  const without = fetchJson('https://crates.io/api/v1/crates?q=signerd&per_page=5', { userAgent: false });
  const withUa = fetchJson('https://crates.io/api/v1/crates?q=signerd&per_page=5', { userAgent: true });
  return {
    endpoint: 'crates.io/api/v1/crates?q=signerd',
    withoutUserAgent: { status: without.status, class: classifyCratesStatus(without.status, false) },
    withUserAgent: { status: withUa.status, class: classifyCratesStatus(withUa.status, true) },
    conclusion: without.status === 403 && withUa.status === 200
      ? 'the previously recorded "crates.io 403" was a missing-User-Agent client defect, not a registry state'
      : 'reproduction did not fire; the recorded claim stands unrefuted by this run',
  };
}

// --- main ----------------------------------------------------------------

export function main() {
  const controls = [
    { kind: 'control', registry: 'crates.io', ...cratesExact('serde'), expectExists: true },
    { kind: 'control', registry: 'npm', ...npmExact('express'), expectExists: true },
  ];
  const surfaces = [
    { kind: 'exact', ...cratesExact(TARGET) },
    { kind: 'search', ...cratesSearch(TARGET) },
    { kind: 'exact', ...npmExact(TARGET) },
    { kind: 'search', ...npmSearch(TARGET) },
  ];

  const all = [...controls, ...surfaces];
  // reference-class every hit against MY markers (repo slug, github owner,
  // site); the registry's own metadata is the evidence
  for (const s of surfaces) {
    for (const h of s.hits ?? []) {
      h.referenceClass = classifyHitReference(h, MY_MARKERS);
    }
  }
  const verdict = decideVerdict(all);
  const report = {
    generatedAt: new Date().toISOString(),
    what: 'does any package registry carry a package that references signerd (exact name or description mention)?',
    instrument: 'tools/measure-registry-presence.mjs',
    targets: [TARGET],
    clientDefectReproduction: clientDefectReproduction(),
    controls,
    surfaces,
    verdict,
    verdictBasis: 'only hits with referenceClass=foreign-reference count; name collisions and incidental mentions do not',
    nameCollisions: surfaces.flatMap((s) => (s.hits ?? []).filter((h) => h.referenceClass === 'name-collision').map((h) => ({ name: h.name, registry: s.registry, class: h.class }))),
    coverage: {
      measured: 'exact-name lookups + name/description search on crates.io and npm',
      notMeasured: ['blog posts', 'Discord', 'git vendors under a different name', 'pyPI', 'other registries'],
    },
    limits: [
      'a package reference is not a verified install',
      'search matches name + description only; a crate DEPENDING on signerd without naming it in either is invisible',
      'verdict withheld (exit 3) whenever any surface or control is unmeasured',
    ],
  };
  mkdirSync('research', { recursive: true });
  const day = new Date().toISOString().slice(0, 10);
  const outFile = `research/registry-presence-${day}.json`;
  writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');
  console.log(`report: ${outFile}`);
  console.log(`verdict: ${verdict}`);
  for (const s of [...controls, ...surfaces]) {
    console.log(`  ${s.registry} ${s.kind} ${s.name}: ${s.status_class}${s.hits?.length ? `, hits=${s.hits.length}` : ''}`);
  }
  process.exit(verdict === 'no-verdict' ? 3 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
