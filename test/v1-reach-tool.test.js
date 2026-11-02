'use strict';

// Pin tools/v1-reach.mjs so CI re-derives the published v1 numbers.
//
// The card question was "upgrade the pinned @solana/web3.js, or document v1 as
// an upper bound?". The answer was measured, not argued: every candidate
// library reaches the SAME verdict, because the product's version rule - not
// the parser - decides reach. This test locks that answer in place:
//
//   * the pinned section is re-derivable in CI (no candidate install needed)
//     and must keep saying what the committed report says;
//   * the verdict must not depend on which library parses the wire - the
//     pinned 1.98.4 cannot even deserialize it, and 3.1.1 round-trips it
//     byte-exactly, yet the product refuses both identically;
//   * exit code 3 (NO VERDICT) must be reachable and must fire on a broken
//     instrument, so a broken measurement cannot be mistaken for a finding.
//
// A candidate probe needs a local install of the candidate package, so it is
// not re-derivable in CI; the committed report keeps those sections as
// reRunnable:false and this test asserts exactly that, rather than pretending
// they can be re-derived.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'v1-reach.mjs');
const FIXTURE = path.join(ROOT, 'test', 'fixtures', 'v1-wire-2026-11-02.json');
const REPORT = path.join(ROOT, 'research', 'v1-reach-2026-11-02.json');
const POLICY_MAX_WIRE_BYTES = 1232;

function run(args, opts = {}) {
  try {
    const stdout = execFileSync(process.execPath, [TOOL, ...args], {
      cwd: ROOT, encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'],
      ...opts,
    });
    return { code: 0, stdout };
  } catch (err) {
    return { code: err.status ?? -1, stdout: err.stdout || '', stderr: err.stderr || '' };
  }
}

test('the committed report exists and states the measured question', () => {
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.source, 'fixture', 'the report must be reproducible from a committed fixture');
  assert.match(report.question, /upgrade/i);
  assert.ok(report.totals.rows > 0, 'the report must have measured rows');
  assert.ok(report.limits.length >= 3, 'the report must state its own limits');
});

test('the pinned probe re-derives: same totals, same verdicts, zero approvals', () => {
  const committed = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const { code, stdout } = run([]);
  assert.equal(code, 0, 'the tool must exit 0 on a complete measurement');
  const fresh = JSON.parse(stdout);
  assert.equal(fresh.totals.rows, committed.totals.rows);
  assert.equal(fresh.totals.shapeEligible, committed.totals.shapeEligible);
  assert.equal(fresh.totals.underCap, committed.totals.underCap);
  assert.equal(fresh.totals.overCap, committed.totals.overCap);
  assert.equal(fresh.totals.unverified, 0, 'every row must be pairing-verified');

  const pinned = fresh.probes.find(p => p.label === 'pinned');
  assert.ok(pinned, 'the pinned probe must be present');
  assert.equal(pinned.reRunnable, true, 'the pinned section must be re-derivable in CI');
  const committedPinned = committed.probes.find(p => p.label === 'pinned');
  assert.deepEqual(pinned.productVerdicts, committedPinned.productVerdicts);
  assert.deepEqual(pinned.productVerdictsUnderCap, committedPinned.productVerdictsUnderCap);
  assert.deepEqual(pinned.productVerdictsOverCap, committedPinned.productVerdictsOverCap);
  assert.equal(pinned.productApprovals, 0,
    'the whole point of the measurement: no library widens the product\'s approval scope');
  assert.equal(committed.totals.underCap > 0, true);
});

test('the verdict is identical for every library that could parse the wire', () => {
  // The committed report holds three probes: the pinned 1.98.4 (cannot parse
  // v1 at all), the last 1.x (parses but cannot re-serialize) and 3.1.1 (parses
  // and round-trips). The parser capability differs; the PRODUCT verdict must
  // not. This is the finding, pinned.
  const committed = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const probes = committed.probes;
  assert.ok(probes.length >= 2, 'the report must compare more than one library');
  const underCapSets = probes.map(p => JSON.stringify(p.productVerdictsUnderCap));
  const overCapSets = probes.map(p => JSON.stringify(p.productVerdictsOverCap));
  assert.equal(new Set(underCapSets).size, 1,
    `under-cap verdicts must not depend on the library: ${underCapSets.join(' | ')}`);
  assert.equal(new Set(overCapSets).size, 1,
    `over-cap verdicts must not depend on the library: ${overCapSets.join(' | ')}`);
  for (const p of probes) {
    assert.equal(p.productApprovals, 0, `probe ${p.label} must not approve v1 wire`);
  }
  // The capability spread must be real, otherwise the comparison proves nothing.
  const deser = probes.map(p => p.deserializes);
  assert.ok(new Set(deser).size > 1,
    'the probes must differ in parse capability, otherwise they are not a comparison');
  // Candidate sections cannot be re-derived in CI (the packages are absent
  // there) and must say so rather than pretend.
  for (const p of probes.filter(p => p.label !== 'pinned')) {
    assert.equal(p.reRunnable, false, `candidate probe ${p.label} must be marked reRunnable:false`);
  }
});

test('every under-cap version-1 row is refused with the named version reason', () => {
  const committed = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  for (const p of committed.probes) {
    assert.deepEqual(p.productVerdictsUnderCap, { version_or_alt: committed.totals.underCap },
      `probe ${p.label} must refuse every under-cap row as version_or_alt`);
  }
});

test('the size cap still outranks the version rule', () => {
  const committed = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  for (const p of committed.probes) {
    assert.deepEqual(p.productVerdictsOverCap, { invalid_wire: committed.totals.overCap },
      `probe ${p.label} must refuse over-cap rows on size, not on version`);
  }
  assert.ok(committed.totals.overCap >= 1, 'the fixture must keep an over-cap control');
});

test('the fixture is committed live wire, not synthetic bytes', () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  assert.equal(fixture.policyMaxWireBytes, POLICY_MAX_WIRE_BYTES);
  assert.ok(Array.isArray(fixture.sourceSlots) && fixture.sourceSlots.length > 0,
    'the fixture must name the finalized slots it was fetched from');
  for (const row of fixture.rows) {
    assert.equal(String(row.version), '1');
    const wire = Buffer.from(row.wireBase64, 'base64');
    assert.equal(wire.length, row.wireLen, 'the declared length must match the bytes');
    assert.equal(wire[0], 0x81, 'version-1 wire must carry the measured prefix');
    assert.equal(row.overPolicyCap, wire.length > POLICY_MAX_WIRE_BYTES,
      'the over-cap flag must match the policy cap, not a hand-written value');
    if (row.json && Array.isArray(row.json.accountKeys)) {
      assert.ok(row.json.accountKeys.length >= 2, 'shape rows need their own accounts');
    }
  }
  // The shape-eligible rows are the ones that matter: a v1 transaction whose
  // own accounts would satisfy the envelope, so the ONLY reason it is refused
  // is the version rule. Without such a row, the measurement would be blind.
  const shapeRows = fixture.rows.filter(r => r.shape);
  assert.ok(shapeRows.length >= 3, 'the fixture must hold shape-eligible v1 rows');
});

test('exit code 3 means NO VERDICT: an empty fixture must not report a finding', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v1-reach-'));
  try {
    const empty = path.join(dir, 'empty.json');
    fs.writeFileSync(empty, JSON.stringify({ generatedAt: 'x', rows: [] }));
    const { code } = run(['--fixture', empty]);
    assert.equal(code, 3, 'an empty fixture must exit 3, never report a number');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('exit code 3 means NO VERDICT: unverified pairing must not be published', () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v1-reach-'));
  try {
    const broken = path.join(dir, 'unverified.json');
    // Break the pairing itself: the tool verifies the json signature PHYSICALLY
    // occurs in the wire bytes, so a row whose signature is absent from the
    // wire measures a different transaction than it describes.
    const rows = fixture.rows.map(r => ({ ...r, signature: '4'.repeat(64) }));
    fs.writeFileSync(broken, JSON.stringify({ ...fixture, rows }));
    const { code } = run(['--fixture', broken]);
    assert.equal(code, 3, 'rows without verified pairing must exit 3');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a candidate directory that does not resolve fails loudly, not silently', () => {
  const { code } = run(['--web3=nonexistent=/tmp/definitely-not-installed-xyz']);
  assert.equal(code, 3, 'an unusable candidate probe must exit 3, not be skipped');
});
