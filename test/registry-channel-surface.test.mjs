'use strict';
// THE REGISTRY-CHANNEL SURFACE: does the PUBLISHED PACKAGE tell the truth
// to the person who installs it FROM the registry?
//
// WHY (measured 2026-11-12, this repo): `npm pack` of the v0.2.18 tree —
// the exact bytes a stranger receives from registry.npmjs.org — carries a
// README whose first Install paragraph says:
//
//   "No package is published to npm yet — the artifact is ready and the
//    remaining gate is credentials ... — so the install path that exists
//    today is the release tag:"
//
// The reader is HOLDING the package that the sentence says does not exist.
// The same page later says publishing is credential-blocked ("npm whoami
// returns ENEEDAUTH, no ~/.npmrc ... exists, the secret store is empty")
// — true on 2026-11-04, false since 2026-11-12 16:55Z. That is the sememe
// contradiction class (README vs measured registry state), and here it
// travels INSIDE the tarball: it reaches the stranger who never opens
// this repository.
//
// Nothing in the suite could fail for it: the registry probes measure the
// NAME (measure-publish-readiness) and REFERENCE (measure-registry-presence),
// never what the published README CLAIMS; install-path/journey/user-zero
// measure the git-tag path; publish-gate proves the artifact CAN publish
// but never that the docs told the truth AFTER it did.
//
// THE CONTRACT (all rules pure, offline, on the PACKED tarball):
//   R1 the packed README must not deny npm publication while the registry
//      serves the package (the registry's own 200 is the testimony; here
//      the denial SHAPE is checked against the tarball a `npm install
//      signerd` receives).
//   R2 the packed README must not claim publishing is credential-blocked.
//   R3 the packed README must carry the registry install command
//      (`npm install signerd`) — a channel, not only the git-tag path.
//   R4 the packed README must still carry the git-tag install command:
//      both paths stay true; the registry is added, the git path is not
//      deleted (a fix that silently drops the documented path is the
//      false-positive guard).
//
// THE OWNERSHIP GUARDS (the second defect face, same hour):
//   O1 a 200 whose maintainers include the npm account we publish from
//      (`sprintberlin`, measured via `npm whoami` on this machine and via
//      `npm view signerd maintainers` on OUR OWN package) or whose repo
//      URL is github.com/auroraxo is 'taken-ours' — never 'taken-collision'.
//   O2 the OLD rule (auroraxo-only) misread our own package as a collision:
//      pinned as the regression this file exists to prevent.
//   O3 the @zanii/signerd prior art keeps its class: foreign maintainer
//      AND foreign repo URL => still 'taken-collision' (the guard that
//      keeps O1 from over-engulfing).
//
// LADDER (measured): R1-R2 RED on the packed v0.2.18 tarball bytes (the
// defect this file exists for), R3 RED, R4 GREEN pre-fix (the false-
// positive guard). O2 RED on the pre-fix classifyAvailability, O1+O3 GREEN.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// ---- the packed tarball, built the way a consumer receives it (once) ----
let TARBALL_README = null;
function tarballReadme() {
  if (TARBALL_README !== null) return TARBALL_README;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-registry-surface-'));
  // --pack-destination: never pack INTO the repo root (measured on sememe
  // 2026-11-07: parallel packs rename the same tgz out of the root).
  const out = execFileSync('npm', ['pack', '--silent', '--pack-destination', dir],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).trim().split('\n').pop().trim();
  const tgz = path.join(dir, out);
  const readme = execFileSync('tar', ['-xzf', tgz, '-O', 'package/README.md'],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  TARBALL_README = readme;
  return readme;
}

// ---- pure rule imports (the tools are the single source of the rules) ----
const { registryDenials, registryInstallClaims, deriveVerdict } = await import(
  pathToFileURL(path.join(ROOT, 'tools', 'measure-registry-channel.mjs')).href);
const prMod = await import(pathToFileURL(path.join(ROOT, 'tools', 'measure-publish-readiness.mjs')).href);
const rpMod = await import(pathToFileURL(path.join(ROOT, 'tools', 'measure-registry-presence.mjs')).href);

const GIT_TAG = 'npm install github:auroraxo/signerd#v';
const REGISTRY_CMD = 'npm install signerd';

test('R1 the packed README must not deny npm publication', () => {
  const readme = tarballReadme();
  const denials = registryDenials(readme);
  assert.deepEqual(
    denials.filter((d) => d === 'denies-publication'),
    [],
    `the published tarball denies npm publication (faces: ${denials.filter((d) => d === 'denies-publication').join(', ')}) `
    + '— the stranger installs the package from the registry the README says is empty',
  );
});

test('R2 the packed README must not claim publishing is credential-blocked', () => {
  const readme = tarballReadme();
  const denials = registryDenials(readme);
  assert.deepEqual(
    denials.filter((d) => d === 'credentials-block-publish'),
    [],
    `the published tarball claims publishing is credential-blocked (faces: ${denials.filter((d) => d === 'credentials-block-publish').join(', ')}) `
    + '— the package IS published; the credential gate is proven passed',
  );
});

test('R3 the packed README must carry the registry install command', () => {
  const readme = tarballReadme();
  const claims = registryInstallClaims(readme);
  assert.ok(
    claims.includes('signerd'),
    `no registry install command in the packed README (found: ${claims.join(', ') || 'none'}) `
    + '— a stranger installing from the registry must see their own channel documented',
  );
});

test('R4 GUARD: the packed README still carries the git-tag install path', () => {
  const readme = tarballReadme();
  assert.ok(readme.includes(GIT_TAG),
    'the fix must not delete the documented git-tag install path — it adds the registry channel');
});

test('R5 GUARD: the denial rule reads claims, not the word npm', () => {
  assert.deepEqual(registryDenials('signerd is published on npm: npm install signerd'), []);
  assert.deepEqual(registryDenials('credentials are NOT the gate any more'), []);
  assert.deepEqual(registryDenials(''), []);
  // The measured faces from the v0.2.18 tarball must still be caught:
  assert.ok(registryDenials('No package is published to npm yet').includes('denies-publication'));
  assert.ok(registryDenials('What blocks publishing is credentials, not the artifact').includes('credentials-block-publish'));
  assert.ok(registryDenials('the remaining gate is credentials').includes('credentials-block-publish'));
  assert.ok(registryDenials('npm whoami returns ENEEDAUTH').includes('credentials-block-publish'));
  assert.ok(registryDenials('the secret store is empty').includes('credentials-block-publish'));
});

test('R6 GUARD: a registry install claim is a code-block channel, not prose', () => {
  // prose mention is not an advertisement
  assert.deepEqual(registryInstallClaims('you could npm install signerd here.'), []);
  // the git-tag path is not a registry channel
  assert.deepEqual(registryInstallClaims('```\nnpm install github:auroraxo/signerd#v0.2.18\n```'), []);
  assert.deepEqual(registryInstallClaims('```\nnpm install git+https://github.com/auroraxo/signerd.git\n```'), []);
  // a version or range is the SAME channel, normalized to the package name
  assert.deepEqual(registryInstallClaims('```\nnpm install signerd@^0.2.0\n```'), ['signerd']);
  assert.deepEqual(registryInstallClaims('```\nnpm install signerd@0.2.18\n```'), ['signerd']);
  // the bare channel IS the channel
  assert.deepEqual(registryInstallClaims('```\nnpm install signerd\n```'), ['signerd']);
  // windows-style and $ prompt forms still count
  assert.deepEqual(registryInstallClaims('```bash\n$ npm install signerd\n```'), ['signerd']);
});

test('R7 the verdict ladder: contradiction -> missing channel -> consistent', () => {
  const denial = deriveVerdict({ registryPublished: true, registryStatus: 200, readme: 'No package is published to npm yet — the artifact is ready and the remaining gate is credentials' });
  assert.equal(denial.verdict, 'registry-contradiction');
  assert.ok(denial.denials.includes('denies-publication'));
  const missing = deriveVerdict({ registryPublished: true, registryStatus: 200, readme: 'Install: ```\nnpm install github:auroraxo/signerd#v0.2.18\n```' });
  assert.equal(missing.verdict, 'missing-registry-channel');
  const clean = deriveVerdict({ registryPublished: true, registryStatus: 200, readme: '```\nnpm install signerd\n```\npublished on npm since 2026-11-12.' });
  assert.equal(clean.verdict, 'registry-consistent');
  const absent = deriveVerdict({ registryPublished: true, registryStatus: 404, readme: 'anything' });
  assert.equal(absent.verdict, 'no-verdict');
  const transport = deriveVerdict({ registryPublished: false, registryStatus: 0, readme: 'anything' });
  assert.equal(transport.verdict, 'no-verdict');
});

test('O1 OUR npm account on a 200 is taken-ours, never a collision', () => {
  assert.equal(prMod.classifyAvailability(200, [{ name: 'sprintberlin' }]), 'taken-ours');
  assert.equal(prMod.classifyAvailability(200, [{ name: 'sprintberlin' }], 'git+https://github.com/auroraxo/signerd.git'), 'taken-ours');
  assert.equal(prMod.classifyAvailability(200, [], 'git+https://github.com/auroraxo/signerd.git'), 'taken-ours');
});

test('O2 REGRESSION: the auroraxo-only rule misread our own package as a collision', () => {
  // This is the measured defect (2026-11-12): maintainers [sprintberlin],
  // repo auroraxo/signerd — OUR package — and the pre-fix rule said
  // taken-collision, the same class as a hostile name-squatter.
  const ourPackage = { maintainers: [{ name: 'sprintberlin' }] };
  const hit = { maintainers: [{ name: 'sprintberlin' }], repoUrl: 'git+https://github.com/auroraxo/signerd.git', class: 'exact-name' };
  assert.equal(rpMod.classifyHitReference(hit, ['auroraxo/signerd']), 'own',
    'our own published package must classify as OWN, not name-collision');
  // and the presence verdict from such a hit must not flip to registry-presence
  const surfaces = [{ kind: 'exact', status_class: 'measured', hits: [{ name: 'signerd', class: 'exact-name', referenceClass: 'own' }] }];
  assert.equal(rpMod.decideVerdict(surfaces), 'registry-absence');
});

test('O3 GUARD: the @zanii prior art keeps its collision class', () => {
  assert.equal(prMod.classifyAvailability(200, [{ name: 'zanii' }], ''), 'taken-collision');
  const zanii = { name: '@zanii/signerd', class: 'name-mention', maintainers: [{ name: 'zanii' }] };
  assert.equal(rpMod.classifyHitReference(zanii, ['auroraxo/signerd']), 'name-collision');
  assert.equal(rpMod.isOwnPackage({ maintainers: [{ name: 'zanii' }] }), false);
});

test('O5 REGRESSION: the npm SEARCH surface judged our own package a collision', () => {
  // Measured 2026-11-12, post-publish, with the exact-surface repair live:
  // research/registry-presence-2026-11-12.json carries the SAME package
  // twice — the exact surface says own:true, the search surface said
  // name-collision, because the search construction hardcoded own:false
  // and dropped the maintainer identities before classification. One
  // package, two verdicts: our own published artifact counted against us
  // on the sweep channel.
  //
  // THIS test runs the REAL construction (buildNpmSearchHits) over the
  // live API object shape (maintainers spelled as [{ email, username }],
  // measured at registry.npmjs.org/-/v1/search?text=signerd) — not just
  // the pure rule: the pure rule alone passes on the pre-fix tree
  // (measured), which is exactly why the instrument is the SURFACE, not
  // the classifier.
  const objects = [
    { package: { name: 'signerd', description: 'Refusal-first prototype: Unix-socket signing daemon.',
      maintainers: [{ email: 'gregor.sprint@gmail.com', username: 'sprintberlin' }],
      publisher: { email: 'gregor.sprint@gmail.com', username: 'sprintberlin' } } },
    { package: { name: '@zanii/signerd', description: "Keep an agent's private key out of the agent's process.",
      maintainers: [{ email: 'info@zanii.agency', username: 'zanii' }],
      publisher: { email: 'info@zanii.agency', username: 'zanii' } } },
  ];
  const hits = rpMod.buildNpmSearchHits(objects, 'signerd');
  const ours = hits.find((h) => h.name === 'signerd');
  const zanii = hits.find((h) => h.name === '@zanii/signerd');
  assert.ok(ours && zanii, 'both hits classified');
  assert.equal(ours.own, true, 'our own published package is own on the SEARCH surface');
  assert.equal(rpMod.classifyHitReference(ours, ['auroraxo/signerd']), 'own');
  // GUARD: the collision neighbour keeps its class through the same construction
  assert.equal(zanii.own, false);
  assert.equal(rpMod.classifyHitReference(zanii, ['auroraxo/signerd']), 'name-collision');
});

test('O4 GUARD: 404 stays free, transport stays unmeasured', () => {
  assert.equal(prMod.classifyAvailability(404, [], ''), 'free');
  assert.equal(prMod.classifyAvailability(500, [], ''), 'unmeasured');
});
