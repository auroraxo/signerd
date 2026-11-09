'use strict';

// The MEASUREMENT PIN for the socket-path domain (2026-11-09).
//
// The artifact research/socket-path-domain-2026-11-09.json is what the card
// cites, so it must be a measurement and not a story:
//
//   T1 the artifact exists, is well formed, and names the BASELINE it
//      measured (the published v0.2.11 tag, not this working tree);
//   T2 the kernel domain in the artifact agrees with the header on this
//      host (108 bytes) - 107/108 accepted, 109 EINVAL;
//   T3 the published tag violated ALL cases and this tree conforms to ALL
//      of them (the ladder, pinned as numbers);
//   T4 the artifact carries no host path (a committed artifact that names
//      the measuring host is a snapshot, not a measurement).
//
// T4 is falsifiable on purpose: change one byte in a path inside the
// artifact and this test must go RED.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(ROOT, 'research', 'socket-path-domain-2026-11-09.json');

function readArtifact() {
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}

test('T1 the artifact exists and names the published tag it measured', () => {
  const r = readArtifact();
  assert.equal(r.tool, 'tools/measure-socket-path-domain.js');
  assert.match(r.baseline, /^v0\.2\.11 \(published tag, extracted with git archive\)/,
    'the baseline must be the PUBLISHED tag, not this working tree');
  assert.ok(r.measuredAt, 'the artifact must say when it was measured');
  assert.equal(r.host.platform, process.platform);
});

test('T2 the kernel domain in the artifact is 108 bytes (this host header)', () => {
  const r = readArtifact();
  const limits = r.kernelDomain.limits;
  assert.match(limits['108 bytes'], /ok/, '108 bytes must bind and connect');
  assert.match(limits['109 bytes'], /EINVAL/, '109 bytes must be refused by the kernel');
  assert.equal(r.kernelDomain.unit, 'bytes of the string handed to bind(), not characters');
});

test('T3 the published tag violated every case; this tree conforms to every case', () => {
  const r = readArtifact();
  assert.equal(r.cases.length, 3);
  assert.equal(r.verdict.baselineViolations, r.cases.length,
    'the published tag must violate every case');
  assert.equal(r.verdict.fixedConforms, r.cases.length,
    'this tree must conform to every case');
  assert.equal(r.verdict.verdict, 'fixed');
  for (const c of r.cases) {
    assert.equal(c.baselineConforms, false, `${c.id} must be violated by the baseline`);
    assert.equal(c.fixedConforms, true, `${c.id} must be satisfied by this tree`);
  }
  // The byte-count case: the refusal names the VALUE, and the false refusal
  // case: a path the kernel accepts starts.
  const over = r.cases.find((c) => c.id === 'over-limit-121');
  assert.match(over.fixed.stderr, /is 121 bytes/);
  assert.doesNotMatch(over.fixed.stderr, /EINVAL|undefined:undefined/);
  const mb = r.cases.find((c) => c.id === 'multibyte-90chars-135bytes');
  assert.equal(mb.socketPathChars, 90, 'the case must be 90 CHARACTERS');
  assert.equal(mb.socketPathBytes, 135, '... and 135 BYTES');
  const inside = r.cases.find((c) => c.id === 'inside-domain-105');
  assert.match(inside.fixed, /started, served ok/, '105 bytes must start the daemon');
});

test('T4 the artifact carries no host path (a snapshot is not a measurement)', () => {
  const raw = fs.readFileSync(ARTIFACT, 'utf8');
  for (const needle of ['/home/', '/Users/', '/tmp/', 'C:\\']) {
    assert.ok(!raw.includes(needle), `the artifact must not contain ${needle}`);
  }
});
