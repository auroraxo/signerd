'use strict';

// The MEASUREMENT PIN for the grant cap domain (2026-11-09).
//
// The artifact research/grant-cap-domain-2026-11-09.json is what the card
// cites, so it must be a measurement and not a story:
//
//   T1 the artifact exists, names its tool and the BASELINE it measured
//      (the published v0.2.12 tag, extracted with git archive - the code a
//      stranger installs, never this working tree);
//   T2 the published tag violated the defect cases (the baseline shows the
//      defect, or the fix is unmeasurable) and this tree violates none;
//   T3 every guard case holds on BOTH trees - the fix must not over-tighten;
//   T4 the artifact carries no host path (a committed artifact that names
//      the measuring host is a snapshot, not a measurement).
//
// T2 and T4 are falsifiable on purpose: hand-edit a violation count in the
// artifact, or add a host path, and this test must go RED.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(ROOT, 'research', 'grant-cap-domain-2026-11-09.json');

function readArtifact() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('T1 the artifact exists and names the published tag it measured', () => {
  const r = readArtifact();
  assert.equal(r.tool, 'tools/measure-grant-cap-domain.js');
  assert.equal(r.baseline.tag, 'v0.2.12', 'the baseline must be the PUBLISHED tag');
  assert.match(r.baseline.source, /^git archive v0\.2\.12/,
    'the baseline must be extracted with git archive, not taken from this tree');
  assert.ok(r.baseline.commit, 'the artifact must pin the baseline commit');
  assert.equal(r.generatedAt, '2026-11-09');
});

test('T2 the published tag violated the defect cases; this tree violates none', () => {
  const r = readArtifact();
  assert.ok(r.before.contractViolations > 0,
    'a baseline that shows no defect makes the fix unmeasurable');
  assert.equal(r.after.contractViolations, 0,
    'this tree must violate the load === runtime contract nowhere');
  assert.equal(r.verdict, 'fixed');
  // The measured defect: dead caps the loader accepted anyway.
  assert.ok(r.before.violations.some((v) => v.includes('windowMaxLamports=0')));
  assert.ok(r.before.violations.some((v) => v.includes('windowMaxMessages=0')));
  // Every row keeps both trees' verdicts, so nothing is summarized away.
  assert.equal(r.rows.before.length, r.rows.after.length);
  assert.equal(r.rows.before.length, 10);
});

test('T3 every guard case holds on both trees (no over-tightening)', () => {
  const r = readArtifact();
  assert.equal(r.before.guardCasesViolated, 0, 'the baseline must accept every guard');
  assert.equal(r.after.guardCasesViolated, 0, 'this tree must accept every guard');
  // The minimal-request probe is recorded: 5000 exactly approves amount 0.
  const min = r.rows.after.find((row) => row.value === '5000');
  assert.equal(min.contractHolds, true, 'windowMaxLamports=5000 must load AND honour');
  assert.equal(min.runtimeAllowed, true, 'the minimal (amount 0) request must be approved');
  assert.equal(min.runtimeAtAmount42.allowed, false,
    'an amount-42 request over a 5000 cap must still be refused by the window');
  const below = r.rows.after.find((row) => row.value === '4999');
  assert.equal(below.loadAccepted, false, '4999 must not load');
  assert.equal(below.runtimeAllowed, false, '4999 can never be honoured');
});

test('T4 the artifact carries no host path (a snapshot is not a measurement)', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  for (const needle of ['/home/', '/Users/', '/tmp/', 'C:\\']) {
    assert.ok(!raw.includes(needle), `the artifact must not contain ${needle}`);
  }
});
