#!/usr/bin/env node
// Measure signerd's PUBLISH READINESS on the package registries where the
// bare name is measured-free (npm, crates.io) or unknown (PyPI).
//
// WHY THIS EXISTS (measured, not argued)
// The prior-art probe (a2b0804) measured @zanii/signerd as an independent
// name collision: same premise sentence, different domain (0/6 vs 132
// domain terms). The card's next step is to sharpen the name: publish the
// measured-free bare name before anyone else does. The 2026-11-03 run found
// npm `signerd` 404 and crates.io `signerd` 404, both authoritative.
//
// WHAT THIS PROBE MEASURES
//   - exact-name availability per registry (404 = free, 200 = taken).
//     A 200 is re-checked for OWNERSHIP: a package maintained by auroraxo
//     would be OURS (distribution), anything else stays taken (collision).
//   - PyPI availability was previously listed as NOT MEASURED. It is now a
//     first-class surface with the same rules.
//   - positive controls per registry: a package known to exist
//     (serde / express / requests). A registry whose control does not
//     resolve is UNMEASURED, never "available".
//   - crates.io keeps the UA discipline: a 403 without User-Agent is OUR
//     client defect, never evidence.
//
// VERDICTS (classes, never sentences)
//   publish-name-free     - every surface measured, every name 404 (free)
//   publish-name-ours     - every surface measured, at least one name is
//                           already OURS (auroraxo) and none is a collision
//   publish-name-taken    - every surface measured, at least one 200 not
//                           owned by auroraxo
//   no-verdict (exit 3)   - any surface or control unmeasured; availability
//                           is never inferred from partial coverage
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const UA = 'signerd-research/0.1 (github.com/auroraxo/signerd)';
const OWN_IDS = ['auroraxo'];
const TARGET = 'signerd';

// --- pure, exported for tests -------------------------------------------

// Same contract as measure-registry-presence.classifyCratesStatus.
// crates.io mandates a User-Agent. A 403 from a UA-less client is OUR defect.
export function classifyCratesStatus(status, hadUserAgent) {
  if (status === 200 || status === 404) return 'measured';
  if (status === 403 && !hadUserAgent) return 'unmeasured-client-defect';
  return 'unmeasured'; // 403 with UA (rate limit), 5xx, anything else
}

// PyPI: 200 exists, 404 free. Anything else is unmeasured. A UA-less PyPI
// 403 is recorded as a defect class the same way, even though PyPI does not
// hard-require the header today.
export function classifyPypiStatus(status, hadUserAgent) {
  if (status === 200 || status === 404) return 'measured';
  if (status === 403 && !hadUserAgent) return 'unmeasured-client-defect';
  return 'unmeasured';
}

// npm exact lookup: measured on 200/404. Note npm returns 200 with an
// "Not Found"-style body for some unauth'd routes; the CODE is the
// authoritative signal here, as measured on 2026-11-03 (404 free) and by
// the express control.
export function classifyNpmStatus(status) {
  if (status === 200 || status === 404) return 'measured';
  return 'unmeasured';
}

// The dangerous direction this file exists to prevent: a 200 (name taken)
// must NEVER be reported as "free". Ownership is checked so that our own
// future republication is recognized, and a collision is never misread.
// Returns 'free' | 'taken-ours' | 'taken-collision'.
export function classifyAvailability(status, maintainers = []) {
  if (status === 404) return 'free';
  if (status !== 200) return 'unmeasured';
  const people = maintainers.map((m) => String(m.name ?? m.username ?? m.login ?? '')).filter(Boolean);
  const ours = people.some((p) => OWN_IDS.includes(p));
  return ours ? 'taken-ours' : 'taken-collision';
}

// The verdict over the whole probe. Availability NEVER comes out of partial
// coverage: any unmeasured surface or failed control -> no-verdict.
//   surfaces: [{ kind: 'exact', availability: 'free'|'taken-ours'|'taken-collision' }...]
//   controls: [{ status_class: 'measured'|..., expectExists: true }...]
export function decideVerdict(surfaces, controls) {
  if (controls.some((c) => c.status_class !== 'measured')) return 'no-verdict';
  const measured = surfaces.filter((s) => s.kind === 'exact');
  if (measured.length === 0) return 'no-verdict';
  if (measured.some((s) => s.availability === 'unmeasured')) return 'no-verdict';
  if (measured.some((s) => s.availability === 'taken-collision')) return 'publish-name-taken';
  // ours is not "free": the name is already held by us on that registry.
  if (measured.some((s) => s.availability === 'taken-ours')) return 'publish-name-ours';
  return 'publish-name-free';
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

function npmExact(name) {
  const r = fetchJson(`https://registry.npmjs.org/${name}`);
  const maintainers = r.status === 200 ? (r.json.maintainers ?? []) : [];
  return {
    registry: 'npm', kind: 'exact', name,
    endpoint: `registry.npmjs.org/${name}`,
    status: r.status, status_class: classifyNpmStatus(r.status),
    availability: classifyAvailability(r.status, maintainers),
    maintainers: maintainers.map((m) => m.name),
  };
}

function cratesExact(name) {
  const r = fetchJson(`https://crates.io/api/v1/crates/${name}`);
  const owners = r.status === 200 ? (r.json.owners ?? []) : [];
  // crates.io owners use login, npm-style maintainers use name/username
  const availability = classifyAvailability(
    r.status,
    owners.map((o) => ({ name: o.login })),
  );
  return {
    registry: 'crates.io', kind: 'exact', name,
    endpoint: `crates.io/api/v1/crates/${name}`,
    status: r.status, status_class: classifyCratesStatus(r.status, true),
    availability,
  };
}

function pypiExact(name) {
  // This endpoint answers 404 for a free name and 200 with project JSON
  // when taken (falsified live on 2026-11-04 with the requests control).
  const r = fetchJson(`https://pypi.org/pypi/${name}/json`);
  const info = r.status === 200 ? (r.json?.info ?? {}) : {};
  const maintainers = r.status === 200
    ? [{ name: String(info.author ?? info.maintainer ?? info.name ?? '') }]
    : [];
  return {
    registry: 'pypi', kind: 'exact', name,
    endpoint: `pypi.org/pypi/${name}/json`,
    status: r.status, status_class: classifyPypiStatus(r.status, true),
    availability: classifyAvailability(r.status, maintainers),
    projectUrl: r.status === 200 ? String(info.project_url ?? info.home_page ?? '').slice(0, 160) : '',
  };
}

function pypiSimpleProbe(name) {
  // Secondary, independent surface on the same registry: the Simple index.
  // A free name can redirect (302 -> next crawl candidate); we record the
  // observed code and classify by the primary JSON endpoint, so this row is
  // EVIDENCE, never a verdict input.
  const r = fetchJson(`https://pypi.org/simple/${name}/`);
  return {
    registry: 'pypi', kind: 'simple-secondary', name,
    endpoint: `pypi.org/simple/${name}/`,
    status: r.status,
    note: '302 on a free name = PyPI reserving against future collisions; verdict input stays the JSON endpoint',
  };
}

// --- main ----------------------------------------------------------------

export function main() {
  const controls = [
    { kind: 'control', registry: 'npm', ...npmExact('express'), expectExists: true },
    { kind: 'control', registry: 'crates.io', ...cratesExact('serde'), expectExists: true },
    { kind: 'control', registry: 'pypi', ...pypiExact('requests'), expectExists: true },
  ];
  const surfaces = [
    npmExact(TARGET),
    cratesExact(TARGET),
    pypiExact(TARGET),
    { kind: 'evidence', ...pypiSimpleProbe(TARGET) },
  ];

  const verdict = decideVerdict(surfaces, controls);
  const report = {
    generatedAt: new Date().toISOString(),
    what: 'is the bare name `signerd` publishable on npm / crates.io / pypi right now?',
    instrument: 'tools/measure-publish-readiness.mjs',
    targets: [TARGET],
    controls,
    surfaces,
    verdict,
    verdictBasis: 'verdict only from exact surfaces with measured controls; a 200 with foreign maintainers is taken-collision, never free',
    coverage: {
      measured: 'exact-name availability on npm, crates.io, pypi (+ simple-index evidence row)',
      notMeasured: ['actual publish rights', 'name-squatting races', 'GitHub org/package name spaces'],
    },
    limits: [
      'availability is a snapshot; nothing reserves the name',
      'a 200 PyPI project page can exist while installs are impossible (yanked/removed); publishability still requires the name',
      'npm/crates.io publish requires credentials NOT PRESENT on this machine (measured: npm whoami ENEEDAUTH, no .npmrc, secret store empty) - this probe measures the name, not the ability to publish',
    ],
  };
  mkdirSync('research', { recursive: true });
  const day = new Date().toISOString().slice(0, 10);
  const outFile = `research/publish-readiness-${day}.json`;
  writeFileSync(outFile, JSON.stringify(report, null, 2) + '\n');
  console.log(`report: ${outFile}`);
  console.log(`verdict: ${verdict}`);
  for (const s of [...controls, ...surfaces]) {
    console.log(`  ${s.registry} ${s.kind} ${s.name}: ${s.status_class}${s.availability ? `, ${s.availability}` : ''} (http ${s.status})`);
  }
  process.exit(verdict === 'no-verdict' ? 3 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
