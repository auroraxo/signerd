'use strict';

// The release-surface rules of tools/measure-release-surface.mjs are pure
// and are pinned here WITHOUT network: the instrument talks to the GitHub
// releases API, so a rule change must be provable offline.
//
// The rule that matters (the crates.io-403 lesson, generalized): a NETWORK
// failure is never an absence — an unreachable release list is NO VERDICT
// (exit 3), never "no releases" or "the page is fine".
//
// Ladder (written against the PRE-FIX tree; every new rule goes RED there):
//   T1   the measured v0.1.0-only surface -> names all three defect
//        families (missing newest-tag release, stale Latest badge, stale
//        tag tree + stale body claims)
//   T2   a clean pair (release == newest tag, good tree, honest body) ->
//        'clean'
//   T3   the "Latest" badge is derived from created order, NOT semver:
//        publishing an old tag LAST moves the badge backwards — still
//        stale-latest-release
//   T4   network/broken-input failures -> NO VERDICT, never an absence
//   T5   false-positive guard: a body that only MENTIONS a wrong API in
//        prose ("Signerd.connect does not exist") must stay clean —
//        only code blocks carry API claims (the release-contract lesson:
//        a naive substring rule flags its own correction prose)
//   T6   a body whose snippet shows a nonexistent API -> defect
//   T7   a body with no limit statement -> body-no-limits (the honest
//        "no outside users / no audit" line is part of the contract)

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const TOOL = path.resolve(__dirname, '..', 'tools', 'measure-release-surface.mjs');

// Populated in test.before: on the pre-fix tree the tool module does not
// exist, and the import failure must fail this file RED, not pass silently.
let derive;
let apiClaimsIn;
let codeBlocks;
let releaseDefects;
let latestReleaseOf;
let newestSemverTag;

test.before(async () => {
  const mod = await import(pathToFileURL(TOOL).href);
  ({ derive, apiClaimsIn, codeBlocks, releaseDefects, latestReleaseOf, newestSemverTag } = mod);
});

const goodTree = {
  manifest: { version: '0.2.0', private: false },
  readme: 'quickstart:\numask 077\nnpm install github:auroraxo/signerd#v0.2.0\nconst { signViaDaemon } = require(...)',
};
const goodBody = (tag) =>
  [
    'install: `npm install github:auroraxo/signerd#' + tag + '`',
    '```js',
    'const answer = await signViaDaemon({ socketPath, grant, wire });',
    '```',
    'Not a professional audit. No outside users yet.',
  ].join('\n');

test('T1 the measured v0.1.0-only surface is named defect by defect', () => {
  const staleBody = [
    '## What you can do with it today',
    '- Keep one key in an encrypted local keystore',
    '## Qualification state (honest)',
    '- 206/206 tests, both crash-harness modes green.',
    '- **Not a professional audit. No outside users yet. Do not point real funds at it.**',
  ].join('\n');
  const v = derive({
    releases: [
      { tag: 'v0.1.0', body: staleBody, draft: false, prerelease: false, createdAt: '2026-11-01T07:34:30Z' },
    ],
    tags: ['v0.1.0', 'v0.2.0'],
    trees: {
      // the measured v0.1.0 tree: private manifest, no quickstart, no API
      // anchor — and its README snippet shows `Signerd.connect`, an API
      // that does not exist in this repo's exports.
      'v0.1.0': {
        manifest: { version: '0.1.0', private: true },
        readme: '# signerd\n\n## Usage\n\nrun the daemon\n\n```ts\nconst signer = await Signerd.connect({ grant: "ops-24h" });\n```\n',
      },
    },
  });
  assert.strictEqual(v.noVerdict, false);
  assert.ok(v.defects.includes('missing-release-for-newest-tag'), v.defects.join(','));
  assert.ok(v.defects.includes('stale-latest-release'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-private-true'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-no-quickstart'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-no-install-command'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-nonexistent-api'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:body-no-install-command'), v.defects.join(','));
  assert.strictEqual(v.verdict, 'defective:' + v.defects.join('+'));
});

test('T2 a clean pair (newest tag released, honest body, good tree) is clean', () => {
  const v = derive({
    releases: [{ tag: 'v0.2.0', body: goodBody('v0.2.0'), draft: false, prerelease: false, createdAt: '2026-11-05T10:00:00Z' }],
    tags: ['v0.1.0', 'v0.2.0'],
    trees: { 'v0.2.0': goodTree },
  });
  assert.strictEqual(v.noVerdict, false);
  assert.deepStrictEqual(v.defects, []);
  assert.strictEqual(v.verdict, 'clean');
  assert.strictEqual(v.latestTag, 'v0.2.0');
});

test('T3 the Latest badge follows created order, not semver — old tag last still stale', () => {
  const v = derive({
    releases: [
      { tag: 'v0.2.0', body: goodBody('v0.2.0'), draft: false, prerelease: false, createdAt: '2026-11-05T10:00:00Z' },
      { tag: 'v0.1.0', body: goodBody('v0.1.0'), draft: false, prerelease: false, createdAt: '2026-11-06T10:00:00Z' },
    ],
    tags: ['v0.1.0', 'v0.2.0'],
    trees: { 'v0.2.0': goodTree, 'v0.1.0': goodTree },
  });
  assert.strictEqual(v.noVerdict, false);
  assert.ok(v.defects.includes('stale-latest-release'), v.defects.join(','));
  assert.strictEqual(latestReleaseOf(v ? null : null), null); // sanity: helper handles null
});

test('T4 a network-failed release list is NO VERDICT, never an absence', () => {
  const v = derive({ releases: null, tags: ['v0.2.0'], trees: {} });
  assert.strictEqual(v.noVerdict, true);
  assert.strictEqual(v.verdict, 'no-verdict');
  const v2 = derive({ releases: [{ tag: 'v0.2.0', body: goodBody('v0.2.0') }], tags: null, trees: {} });
  assert.strictEqual(v2.noVerdict, true);
});

test('T5 prose that only MENTIONS a wrong API is not a claim (false-positive guard)', () => {
  const prose = 'Note: `Signerd.connect` does not exist — the client API is signViaDaemon.';
  assert.deepStrictEqual(codeBlocks(prose), []);
  assert.deepStrictEqual(apiClaimsIn(prose), []);
  const v = releaseDefects('v0.2.0', goodTree, goodBody('v0.2.0') + '\n\n' + prose);
  assert.deepStrictEqual(v, []);
});

test('T6 a code block showing a nonexistent API is a defect', () => {
  const body = goodBody('v0.2.0') + '\n\n```js\nawait Signerd.connect({ socketPath });\n```';
  assert.deepStrictEqual(apiClaimsIn(body), ['Signerd.connect']);
  const v = releaseDefects('v0.2.0', goodTree, body);
  assert.ok(v.includes('body-nonexistent-api'), v.join(','));
});

test('T7 a body that claims nothing about limits loses the honest-limits gate', () => {
  const body = goodBody('v0.2.0').replace('Not a professional audit. No outside users yet.', 'Blazing fast. Production ready.');
  const v = releaseDefects('v0.2.0', goodTree, body);
  assert.ok(v.includes('body-no-limits'), v.join(','));
});

test('T8 the newest-tag rule orders semver, not string order', () => {
  assert.strictEqual(newestSemverTag(['v0.2.10', 'v0.2.9', 'v0.1.0']), 'v0.2.10');
});

// The post-fix contract (what the fix in this pulse must produce): the
// surface defects are gone, and the immutable history of the v0.1.0 tag is
// STILL named — the instrument must not be "fixed" by forgetting the past.
test('T9 a superseded-but-honest surface loses the surface defects but keeps the tag facts', () => {
  const supersededBody = [
    '**SUPERSEDED — use v0.2.0**: install `npm install github:auroraxo/signerd#v0.2.0`.',
    'The v0.1.0 tag tree carries "private": true and a README with no quickstart',
    '(measured: research/install-path-v0.1.0-2026-11-05.json).',
    'Not a professional audit. No outside users yet.',
    '',
    '---',
    '## Qualification state at publication',
    '- 206/206 tests, both crash-harness modes green.',
  ].join('\n');
  const v = derive({
    releases: [
      { tag: 'v0.1.0', body: supersededBody, draft: false, prerelease: false, createdAt: '2026-11-01T07:34:30Z' },
      { tag: 'v0.2.0', body: goodBody('v0.2.0'), draft: false, prerelease: false, createdAt: '2026-11-05T10:00:00Z' },
    ],
    tags: ['v0.1.0', 'v0.2.0'],
    trees: {
      'v0.1.0': {
        manifest: { version: '0.1.0', private: true },
        readme: '# signerd\n\nrun the daemon\n\n```ts\nconst signer = await Signerd.connect({ grant: "ops-24h" });\n```\n',
      },
      'v0.2.0': goodTree,
    },
  });
  assert.strictEqual(v.noVerdict, false);
  // surface defects resolved...
  assert.ok(!v.defects.includes('missing-release-for-newest-tag'), v.defects.join(','));
  assert.ok(!v.defects.includes('stale-latest-release'), v.defects.join(','));
  assert.ok(!v.defects.includes('v0.1.0:body-no-install-command'), v.defects.join(','));
  // ...history still named (the tag is immutable; naming it is the job):
  assert.ok(v.defects.includes('v0.1.0:tag-private-true'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-no-quickstart'), v.defects.join(','));
  assert.ok(v.defects.includes('v0.1.0:tag-nonexistent-api'), v.defects.join(','));
  assert.strictEqual(v.defects.every((d) => d.startsWith('v0.1.0:tag-')), true, v.defects.join(','));
  assert.strictEqual(v.latestTag, 'v0.2.0');
});

test('T10 an install command naming a tag this repo does not have is a false claim', () => {
  const body =
    'Install: `npm install github:auroraxo/signerd#v9.9.9`\nNot a professional audit. No outside users yet.';
  const v = derive({
    releases: [{ tag: 'v0.2.0', body, draft: false, prerelease: false, createdAt: '2026-11-05T10:00:00Z' }],
    tags: ['v0.1.0', 'v0.2.0'],
    trees: { 'v0.2.0': goodTree },
  });
  assert.strictEqual(v.noVerdict, false);
  assert.ok(v.defects.includes('v0.2.0:body-install-tag-missing'), v.defects.join(','));
});
