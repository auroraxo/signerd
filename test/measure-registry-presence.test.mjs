// Controls for tools/measure-registry-presence.mjs - the instrument that
// closes the registry blind spot the foreign-use probe had to leave open
// ("crates.io/npm out of scope (measured: crates.io 403 ...)").
//
// The claim being falsified: "crates.io 403" as a MEASURED ABSENCE. The 403
// was measured live on 2026-11-04: same endpoint, same minute -> 403 without
// a User-Agent header, 200 with one. A client defect had been recorded as a
// property of the registry.
//
// THE LADDER, MEASURED (not asserted):
//   - on the PRE-instrument tree (757951c / bfe48ad) this file CANNOT run:
//     the module does not exist, so the import fails - the instrument itself
//     is the fix, and the old tree had no way to classify the 403 at all
//     (it recorded the transport error as an absence).
//   - guards below pin the two dangerous directions:
//     G1 a UA-less 403 must classify as a CLIENT DEFECT (unmeasured), never
//        as an authoritative absence;
//     G2 an absence verdict is withheld whenever any surface or control is
//        unmeasured - partial coverage never becomes "registry-absence";
//     G3 npm 404 stays an authoritative absence (the one true negative);
//     G4 ownership: a package maintained by auroraxo is OWN distribution,
//        not foreign use.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyCratesStatus,
  classifyNpmStatus,
  classifyRegistryHit,
  classifyHitReference,
  isOwnPackage,
  decideVerdict,
} from '../tools/measure-registry-presence.mjs';

test('G1: crates.io 403 WITHOUT a user agent is a client defect, not an absence', () => {
  assert.equal(classifyCratesStatus(403, false), 'unmeasured-client-defect');
  // and the classifier never returns a "measured" class for it
  assert.notEqual(classifyCratesStatus(403, false), 'measured');
});

test('G1b: crates.io 403 WITH a user agent is a rate limit -> unmeasured, not absence', () => {
  assert.equal(classifyCratesStatus(403, true), 'unmeasured');
});

test('G2: absence is withheld when one surface is unmeasured', () => {
  const surfaces = [
    { kind: 'exact', status_class: 'measured', hits: [] },
    { kind: 'search', status_class: 'unmeasured', hits: [] },
  ];
  assert.equal(decideVerdict(surfaces), 'no-verdict');
});

test('G2b: absence is withheld when a positive control did not resolve', () => {
  const surfaces = [
    { kind: 'control', status_class: 'unmeasured', hits: [] },
    { kind: 'exact', status_class: 'measured', hits: [] },
    { kind: 'search', status_class: 'measured', hits: [] },
  ];
  assert.equal(decideVerdict(surfaces), 'no-verdict');
});

test('G2c: all surfaces measured + zero foreign references = registry-absence', () => {
  const surfaces = [
    { kind: 'control', status_class: 'measured', hits: [] },
    { kind: 'exact', status_class: 'measured', hits: [{ name: 'signerd', class: 'exact-name', referenceClass: 'own' }] },
    { kind: 'search', status_class: 'measured', hits: [] },
  ];
  assert.equal(decideVerdict(surfaces), 'registry-absence');
});

test('G2d: one VERIFIED foreign reference flips the verdict to registry-presence', () => {
  const surfaces = [
    { kind: 'control', status_class: 'measured', hits: [] },
    { kind: 'exact', status_class: 'measured', hits: [{ name: 'signerd', class: 'exact-name', referenceClass: 'foreign-reference' }] },
  ];
  assert.equal(decideVerdict(surfaces), 'registry-presence');
});

test('G2e: control hits NEVER count as foreign - found live when serde/express poisoned the first run', () => {
  // the exact defect the first live run had: controls resolved (as they
  // must) and their own packages were counted as foreign references
  const surfaces = [
    { kind: 'control', status_class: 'measured', hits: [{ name: 'serde', class: 'exact-name', own: false }] },
    { kind: 'exact', status_class: 'measured', hits: [] },
    { kind: 'search', status_class: 'measured', hits: [] },
  ];
  assert.equal(decideVerdict(surfaces), 'registry-absence');
});

test('G5: a name COLLISION is prior art, NOT foreign use - @zanii/signerd case', () => {
  // live hit, 2026-11-03: same name + same concept, published 7 days BEFORE
  // my first commit, referencing nothing of mine. Counting it as foreign use
  // would have been a flattering false positive.
  assert.equal(
    classifyHitReference({ name: '@zanii/signerd', class: 'name-mention', description: 'a local daemon unseals the key' }, ['auroraxo/signerd']),
    'name-collision',
  );
  const surfaces = [
    { kind: 'exact', status_class: 'measured', hits: [{ name: '@zanii/signerd', class: 'name-mention', referenceClass: 'name-collision' }] },
  ];
  assert.equal(decideVerdict(surfaces), 'registry-absence');
});

test('G5b: reference classification - own, foreign link, collision, incidental', () => {
  const markers = ['auroraxo/signerd', 'github.com/auroraxo'];
  assert.equal(classifyHitReference({ name: 'x', maintainers: [{ name: 'auroraxo' }] }, markers), 'own');
  assert.equal(classifyHitReference({ name: 'x', repository: 'github.com/auroraxo/signerd' }, markers), 'foreign-reference');
  assert.equal(classifyHitReference({ name: 'signerd', class: 'exact-name' }, markers), 'name-collision');
  assert.equal(classifyHitReference({ name: 'other', class: 'description-mention' }, markers), 'incidental-mention');
});

test('G3: npm 404 is an authoritative measured absence for the exact name', () => {
  assert.equal(classifyNpmStatus(404), 'measured');
  assert.equal(classifyNpmStatus(200), 'measured');
  assert.equal(classifyNpmStatus(403), 'unmeasured');
  assert.equal(classifyNpmStatus(500), 'unmeasured');
});

test('G3b: crates.io 404 is an authoritative measured absence too', () => {
  assert.equal(classifyCratesStatus(404, true), 'measured');
  assert.equal(classifyCratesStatus(404, false), 'measured');
});

test('G4: a package maintained by auroraxo is OWN, not foreign use', () => {
  assert.equal(isOwnPackage({ maintainers: [{ name: 'auroraxo' }] }), true);
  assert.equal(isOwnPackage({ owners: [{ login: 'auroraxo' }] }), true);
  assert.equal(isOwnPackage({ maintainers: [{ name: 'someone-else' }] }), false);
  assert.equal(isOwnPackage({}), false);
});

test('hit classifier: exact name vs name/description mention vs noise', () => {
  assert.equal(classifyRegistryHit({ name: 'signerd', description: '' }, 'signerd'), 'exact-name');
  assert.equal(
    classifyRegistryHit({ name: 'signerd-client', description: 'a local signer wrapper' }, 'signerd'),
    'name-mention',
  );
  assert.equal(
    classifyRegistryHit({ name: 'signer-helper', description: 'a client for signerd, the scoped signing daemon' }, 'signerd'),
    'description-mention',
  );
  assert.equal(classifyRegistryHit({ name: 'designer-tools', description: 'UI design helpers' }, 'signerd'), 'noise');
  // substring must not match - "signerd" as a WORD only (D1 of foreign-use)
  assert.equal(classifyRegistryHit({ name: 'xsignerdx', description: 'unrelated' }, 'signerd'), 'noise');
  assert.equal(classifyRegistryHit({ name: 't', description: 'a signerdialerendpoint' }, 'signerd'), 'noise');
});
