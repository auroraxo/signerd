// Controls for tools/measure-publish-readiness.mjs - the instrument behind
// the card's next step (3): "optional den Namen praezisieren - Bare signerd
// frei auf npm/crates.io (404), Kollision nur im Such-/Repo-Raum".
//
// The claim being falsified: that the bare name `signerd` is FREE to publish
// on every registry we claim to know about. The dangerous direction:
//   - a 200 (name taken) must never surface as 'free' (name-squat loss);
//   - a partial coverage (one registry unreachable) must never surface as
//     'free' either (the crates.io-403 lesson: client defect as absence);
//   - OUR OWN future republication must be recognized, not counted as a
//     collision, otherwise a re-run after publishing flips to taken and
//     the instrument lies about itself.
//
// THE LADDER, MEASURED:
//   - on the PRE-instrument tree (a2b0804) this file CANNOT run: the module
//     does not exist, so the import fails - the instrument itself is the fix;
//   - guards below pin the three dangerous directions (G1/G2/G3);
//   - positive control: express/serde/requests must resolve measured, else
//     the whole verdict is withheld (exit 3).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyCratesStatus,
  classifyPypiStatus,
  classifyNpmStatus,
  classifyAvailability,
  decideVerdict,
} from '../tools/measure-publish-readiness.mjs';

test('G1: npm 404 is measured, npm 200 is measured, anything else is unmeasured', () => {
  assert.equal(classifyNpmStatus(404), 'measured');
  assert.equal(classifyNpmStatus(200), 'measured');
  assert.equal(classifyNpmStatus(403), 'unmeasured');
  assert.equal(classifyNpmStatus(0), 'unmeasured');
  assert.equal(classifyNpmStatus(500), 'unmeasured');
});

test('G1b: crates.io UA-less 403 is OUR defect, never evidence about the name', () => {
  assert.equal(classifyCratesStatus(403, false), 'unmeasured-client-defect');
  assert.equal(classifyCratesStatus(403, true), 'unmeasured');
  assert.equal(classifyCratesStatus(404, true), 'measured');
});

test('G1c: PyPI follows the same status discipline', () => {
  assert.equal(classifyPypiStatus(404, true), 'measured');
  assert.equal(classifyPypiStatus(200, true), 'measured');
  assert.equal(classifyPypiStatus(403, false), 'unmeasured-client-defect');
  assert.equal(classifyPypiStatus(500, true), 'unmeasured');
});

test('G2: a 200 with FOREIGN maintainers is taken-collision, never free', () => {
  assert.equal(classifyAvailability(404), 'free');
  assert.equal(classifyAvailability(200, [{ name: 'zanii' }]), 'taken-collision');
  assert.equal(classifyAvailability(200, [{ name: 'somebody-else' }]), 'taken-collision');
});

test('G3: OUR OWN maintainer on a 200 is taken-ours, not a collision', () => {
  assert.equal(classifyAvailability(200, [{ name: 'auroraxo' }]), 'taken-ours');
  // mixed: ours + others still counts as ours (we hold the name)
  assert.equal(
    classifyAvailability(200, [{ name: 'auroraxo' }, { name: 'other' }]),
    'taken-ours',
  );
});

test('G4: non-200/non-404 availability is unmeasured, never free', () => {
  assert.equal(classifyAvailability(403), 'unmeasured');
  assert.equal(classifyAvailability(0), 'unmeasured');
  assert.equal(classifyAvailability(500), 'unmeasured');
});

test('G5: one taken-collision surface flips the whole verdict to publish-name-taken', () => {
  const surfaces = [
    { kind: 'exact', registry: 'npm', availability: 'free' },
    { kind: 'exact', registry: 'crates.io', availability: 'taken-collision' },
    { kind: 'exact', registry: 'pypi', availability: 'free' },
  ];
  const controls = [
    { status_class: 'measured' },
    { status_class: 'measured' },
    { status_class: 'measured' },
  ];
  assert.equal(decideVerdict(surfaces, controls), 'publish-name-taken');
});

test('G5b: taken-ours is NOT free - verdict names the ours-state distinctly', () => {
  const surfaces = [
    { kind: 'exact', registry: 'npm', availability: 'taken-ours' },
    { kind: 'exact', registry: 'crates.io', availability: 'free' },
    { kind: 'exact', registry: 'pypi', availability: 'free' },
  ];
  const controls = [{ status_class: 'measured' }, { status_class: 'measured' }, { status_class: 'measured' }];
  assert.equal(decideVerdict(surfaces, controls), 'publish-name-ours');
  assert.notEqual(decideVerdict(surfaces, controls), 'publish-name-free');
});

test('G6: absence (free) is withheld when any surface or control is unmeasured', () => {
  const controls = [{ status_class: 'measured' }, { status_class: 'measured' }, { status_class: 'measured' }];
  const surfaces = [
    { kind: 'exact', registry: 'npm', availability: 'free' },
    { kind: 'exact', registry: 'crates.io', availability: 'unmeasured' },
    { kind: 'exact', registry: 'pypi', availability: 'free' },
  ];
  assert.equal(decideVerdict(surfaces, controls), 'no-verdict');

  const controls2 = [{ status_class: 'unmeasured' }];
  const surfaces2 = [{ kind: 'exact', registry: 'npm', availability: 'free' }];
  assert.equal(decideVerdict(surfaces2, controls2), 'no-verdict');
});

test('G7: empty surface set never yields a verdict', () => {
  assert.equal(decideVerdict([], [{ status_class: 'measured' }]), 'no-verdict');
  assert.equal(decideVerdict([], []), 'no-verdict');
});

test('G8: an unmeasured control with taken-ours surfaces still withholds', () => {
  const surfaces = [
    { kind: 'exact', registry: 'npm', availability: 'taken-ours' },
    { kind: 'exact', registry: 'crates.io', availability: 'free' },
  ];
  const controls = [{ status_class: 'unmeasured' }];
  assert.equal(decideVerdict(surfaces, controls), 'no-verdict');
});
