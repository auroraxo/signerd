'use strict';

// The publish gate that a dry-run never reaches.
//
// npm publish --dry-run does NOT exercise the real publish path: it warns
// "This command requires you to be logged in (dry-run)" and returns 0 even
// though a REAL publish would be refused. The refusal lives in
// libnpmpublish.publish(), which checks manifest.private BEFORE it touches
// the registry:
//
//   if (manifest.private) throw Object.assign(new Error(
//     "This package has been marked as private ..."), { code: 'EPRIVATE' })
//
// So a package that still carries "private": true is not merely "not
// published yet" - it CANNOT be published, and the reason a dry-run hides.
// The card's readiness probe concluded "publishing is blocked by
// credentials, not by the artifact"; that conclusion was drawn from the
// dry-run and was therefore only half true.
//
// This test pins the invariant on the REAL manifest, with the REAL publish
// function, against a REAL packed tarball - no network is needed because
// the private check runs before any registry access.
//
// Ladder:
//   A: the manifest as it stands -> must NOT be EPRIVATE (it may be
//      EPRIVATE only if the package is deliberately withheld; the invariant
//      below is what decides).
//   B: control - the same manifest with `private` set to true -> MUST be
//      EPRIVATE. This proves the gate is actually reached and that the
//      probe can see it, so A cannot pass vacuously.
//   C: control - the same manifest with `private` removed -> must NOT be
//      EPRIVATE. It will fail later (credentials, E404/E401) - a different
//      code is exactly the point: the private gate is behind us.
//
// No registry call is required for A/B/C except in C, where the failure is
// expected and its code is only checked for NOT being EPRIVATE.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const manifestPath = path.join(ROOT, 'package.json');

// Locate the real libnpmpublish that npm itself uses. If it cannot be
// found, the test refuses to pass silently: an absent probe is not a green
// probe.
//
// The PACKAGE root is required (not lib/publish.js directly): the package
// entry point exports { publish, unpublish }, while lib/publish.js exports
// the function itself. npm loads the package entry point, so that is what
// the probe must call.
function findLibnpmpublish() {
  const candidates = [];
  try {
    const npmCli = process.env.npm_execpath;
    if (npmCli) candidates.push(path.join(path.dirname(npmCli), '..', 'node_modules', 'libnpmpublish'));
  } catch {}
  candidates.push('/home/aurora/.hermes/node/lib/node_modules/npm/node_modules/libnpmpublish');
  candidates.push('/home/aurora/.local/lib/node_modules/npm/node_modules/libnpmpublish');
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'package.json'))) return candidate;
  }
  return null;
}

test('the package manifest is publishable: npm must not refuse it as private', async (t) => {
  const publishPkg = findLibnpmpublish();
  if (!publishPkg) {
    t.skip('libnpmpublish not found - cannot reach the real publish gate');
    return;
  }
  const libnpmpublish = require(publishPkg);
  const publish = typeof libnpmpublish === 'function'
    ? libnpmpublish
    : libnpmpublish.publish;
  assert.strictEqual(typeof publish, 'function',
    'libnpmpublish must expose a publish function');

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.strictEqual(typeof manifest.name, 'string');
  assert.strictEqual(manifest.name, 'signerd');

  // A real tarball, packed by the real npm. The publish function needs the
  // bytes, and packing is local.
  const packed = execFileSync('npm', ['pack', '--quiet', '--pack-destination', ROOT],
    { cwd: ROOT, encoding: 'utf8' }).trim().split('\n').pop();
  const tarball = fs.readFileSync(path.join(ROOT, packed));
  t.after(() => { try { fs.unlinkSync(path.join(ROOT, packed)); } catch {} });

  // A: the tree as it stands. The invariant: the package must not carry
  // `private: true`, because npm would refuse the publish outright.
  assert.notStrictEqual(manifest.private, true,
    'package.json still has "private": true - npm refuses to publish such a package ' +
    '(EPRIVATE) before any registry access, so `npm publish` can never succeed');

  // B: control - the gate is reached and visible.
  let bCode = 'no-throw';
  try {
    await publish({ ...manifest, private: true }, tarball, { force: true });
  } catch (err) {
    bCode = err && err.code;
  }
  assert.strictEqual(bCode, 'EPRIVATE',
    'control: a manifest with private:true must be refused with EPRIVATE');

  // C: control - with `private` gone the gate is passed; the next failure is
  // a different code (credentials / not-found), never EPRIVATE.
  const withoutPrivate = { ...manifest };
  delete withoutPrivate.private;
  let cCode = 'no-throw';
  try {
    await publish(withoutPrivate, tarball, { force: true });
  } catch (err) {
    cCode = err && err.code;
  }
  assert.notStrictEqual(cCode, 'EPRIVATE',
    'control: with `private` removed the publish must get past the private gate');
});
