'use strict';

// The verdict rules of tools/measure-install-path.mjs are pure and are
// pinned here WITHOUT network: the instrument talks to GitHub, npm and
// cargo, so a rule change must be provable offline.
//
// The rule that matters (the crates.io-403 lesson): a NETWORK failure is
// never an absence. Only an authoritative answer (GitHub/npm resolving a
// ref and naming what it contains) produces a verdict; everything else is
// NO VERDICT (exit 3).
//
// Ladder:
//   T1 the real defect pair -> npmTagPath names BOTH defects
//   T2 a clean tag -> npmTagPath 'clean'
//   T3 the cargo claim -> 'false-no-cargo-artifact' when there is no
//      Cargo.toml, and the tag-missing case is authoritative
//   T4 network failures -> NO VERDICT, never a verdict string
//   T5 a missing cargo BINARY is no-verdict, not "the claim is false"
//      (the absence of cargo on this host says nothing about the claim)

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const TOOL = path.resolve(__dirname, '..', 'tools', 'measure-install-path.mjs');

let derive;
test.before(async () => {
  ({ derive } = await import(pathToFileURL(TOOL).href));
});

const cleanClone = { attempted: true, ok: true, cargoToml: false };
const cleanNpm = (over = {}) => ({
  attempted: true, ok: true, manifest: { version: '0.2.0', private: false },
  readmeQuickstart: true, errorKind: undefined, refMissing: false, ...over,
});

test('T1 the measured v0.1.0 defect pair is named, not summarized away', () => {
  const v = derive({
    ref: 'v0.1.0',
    clone: cleanClone,
    cargo: { attempted: true, ok: false, cargoTomlMissing: true, errorKind: undefined },
    npm: cleanNpm({ manifest: { version: '0.1.0', private: true }, readmeQuickstart: false }),
  });
  assert.strictEqual(v.noVerdict, false);
  assert.strictEqual(v.npmTagPath, 'defective:private-true+readme-no-quickstart');
  assert.strictEqual(v.cargoClaim, 'false-no-cargo-artifact');
});

test('T2 a clean tag is clean on both surfaces', () => {
  const v = derive({
    ref: 'v0.2.0',
    clone: cleanClone,
    cargo: { attempted: true, ok: false, cargoTomlMissing: true, errorKind: undefined },
    npm: cleanNpm(),
  });
  assert.strictEqual(v.noVerdict, false);
  assert.strictEqual(v.npmTagPath, 'clean');
});

test('T3 a ref that resolves nowhere is authoritative on both surfaces', () => {
  const v = derive({
    ref: 'v9.9.9',
    clone: { attempted: true, ok: false, cargoToml: false, errorKind: 'ref-missing' },
    cargo: { attempted: false },
    npm: { attempted: true, ok: false, manifest: null, readmeQuickstart: false, errorKind: 'ref-missing', refMissing: true },
  });
  assert.strictEqual(v.noVerdict, false);
  assert.strictEqual(v.npmTagPath, 'tag-missing');
  assert.strictEqual(v.cargoClaim, 'tag-missing');
});

test('T4 network failures are NO VERDICT, never an absence', () => {
  const cloneNet = derive({
    ref: 'v0.2.0',
    clone: { attempted: true, ok: false, cargoToml: false, errorKind: 'network' },
    cargo: { attempted: false },
    npm: { attempted: true, ok: false, manifest: null, readmeQuickstart: false, errorKind: 'network', refMissing: false },
  });
  assert.strictEqual(cloneNet.noVerdict, true);
  assert.strictEqual(cloneNet.npmTagPath, 'unmeasured');

  const npmNet = derive({
    ref: 'v0.2.0',
    clone: cleanClone,
    cargo: { attempted: true, ok: false, cargoTomlMissing: true, errorKind: undefined },
    npm: { attempted: true, ok: false, manifest: null, readmeQuickstart: false, errorKind: 'network', refMissing: false },
  });
  assert.strictEqual(npmNet.noVerdict, true);
  assert.strictEqual(npmNet.npmTagPath, 'unmeasured');
});

test('T5 a missing cargo binary is no-verdict: the host says nothing about the claim', () => {
  const v = derive({
    ref: 'v0.2.0',
    clone: cleanClone,
    cargo: { attempted: false },
    npm: cleanNpm(),
  });
  assert.strictEqual(v.noVerdict, true);
  assert.match(v.reason, /cargo-binary-missing/);
});

test('T6 an unreadable installed manifest is no-verdict, not "clean"', () => {
  const v = derive({
    ref: 'v0.2.0',
    clone: cleanClone,
    cargo: { attempted: true, ok: false, cargoTomlMissing: true, errorKind: undefined },
    npm: cleanNpm({ manifest: null }),
  });
  assert.strictEqual(v.noVerdict, true);
  assert.match(v.reason, /npm-manifest-unreadable/);
});
