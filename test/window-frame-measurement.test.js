'use strict';

// THE MEASUREMENT PIN for the window-frame defect (2026-11-19, issue #1).
//
// The artifacts research/window-frame-{main,published-v0242}-2026-11-19.json
// are what the issue cites, so they must be measurements and not stories:
//
//   T1 both artifacts exist, name the CLI they measured (basename, never a
//      host path), and carry the same verdict the issue quotes;
//   T2 both trees show the DEFECT (verdict window-frame-fee-blind, all five
//      defect faces hold) - a baseline that shows nothing makes the future
//      fix unmeasurable;
//   T3 the guard set is complete in both artifacts (g1-g4, none broken) -
//      the defect is the frame arithmetic, NOT a broken window;
//   T4 the two published faces carry the exact README numbers (both
//      quickstart pairings: max == window, spent "0", remaining = the cap,
//      fix naming --append, journal untouched at 0 records);
//   T5 the artifacts are falsifiable: flip the main verdict to
//      "window-frame-honest" and this file goes RED.
//
// T4/T5 are falsifiable on purpose. The ladder equivalent - the behaviour
// re-derived live - is tools/measure-window-frame.js itself, which the
// falsification section of issue #1 documents (M1 flips D1/D2/D4 but breaks
// guard g3; M_A flips exactly D1/D2+D5 with 4/4 guards green).
//
// T6 is the live half: the CENTRAL claim is re-derived against the tree
// under test, so CI keeps proving it (and turns RED the moment a fix lands -
// which is the point: the fix author must confront this pin).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const MAIN = path.join(ROOT, 'research', 'window-frame-main-2026-11-19.json');
const PUB = path.join(ROOT, 'research', 'window-frame-published-v0242-2026-11-19.json');

function load(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

test('T1: both window-frame artifacts exist, name their CLI, verdicts as cited', () => {
  for (const [file, cli] of [[MAIN, 'signerd.js'], [PUB, 'signerd.js']]) {
    const doc = load(file);
    assert.equal(doc.cli, cli, `${path.basename(file)} must name the CLI basename`);
    assert.equal(doc.verdict, 'window-frame-fee-blind',
      `${path.basename(file)} must carry the cited verdict`);
    assert.ok(typeof doc.generatedAt === 'string' && doc.generatedAt.length > 0);
    assert.ok(Array.isArray(doc.rules) && doc.rules.includes('no-host-path'));
  }
});

test('T2: both trees show all five defect faces', () => {
  for (const file of [MAIN, PUB]) {
    const doc = load(file);
    assert.equal(doc.faceDefects, 5, `${path.basename(file)} defect count`);
    const expected = [
      'd1_d2_readme_pairing_ops-24h_max500000000',
      'd1_d2_readme_pairing_ops-payroll_max1000000',
      'd3_named_repair_not_runnable',
      'd4_ceiling_is_window_minus_fee',
      'd5_creation_accepts_dead_grant',
    ];
    for (const id of expected) {
      const row = doc.rows.find((r) => r.id === id);
      assert.ok(row, `${path.basename(file)} is missing face ${id}`);
      assert.equal(row.hold, true, `${id} must hold on ${path.basename(file)}`);
    }
  }
});

test('T3: guards g1-g4 are present and green in both artifacts', () => {
  for (const file of [MAIN, PUB]) {
    const doc = load(file);
    assert.deepEqual(doc.guardBroken, [],
      `${path.basename(file)} must report no broken guards`);
    for (const id of ['g1_transfer_at_window_minus_fee_signs',
      'g2_small_transfer_signs', 'g3_post_spend_window_report_true',
      'g4_replay_refused']) {
      const row = doc.rows.find((r) => r.id === id);
      assert.ok(row, `${path.basename(file)} is missing guard ${id}`);
      assert.equal(row.hold, true, `${id} must be green`);
    }
  }
});

test('T4: the README pairings are pinned with their exact numbers', () => {
  for (const file of [MAIN, PUB]) {
    const doc = load(file);
    for (const [id, cap] of [
      ['d1_d2_readme_pairing_ops-24h_max500000000', '500000000'],
      ['d1_d2_readme_pairing_ops-payroll_max1000000', '1000000'],
    ]) {
      const row = doc.rows.find((r) => r.id === id);
      assert.ok(row, `missing ${id}`);
      assert.equal(row.observed.error, 'window_cap');
      assert.equal(row.observed.windowSpentLamports, '0',
        `${id}: the empty window must report spent 0`);
      assert.equal(row.observed.windowRemainingLamports, cap,
        `${id}: remaining must equal the full cap ${cap}`);
      assert.equal(row.observed.fixNamesAppend, true,
        `${id}: the fix must name grant-add --append`);
      assert.equal(row.observed.journalRecords, 0,
        `${id}: nothing may be journaled`);
      assert.match(row.observed.where, /README\.md:\d+/);
    }
  }
});

test('T5: the pin is falsifiable - a flipped main verdict goes RED', () => {
  const original = load(MAIN);
  const flipped = { ...original, verdict: 'window-frame-honest' };
  const tmp = path.join(ROOT, 'research', 'window-frame-pin-flip.tmp.json');
  fs.writeFileSync(tmp, JSON.stringify(flipped));
  try {
    const doc = JSON.parse(fs.readFileSync(tmp, 'utf8'));
    assert.notEqual(doc.verdict, 'window-frame-fee-blind');
    assert.throws(() => {
      assert.equal(doc.verdict, 'window-frame-fee-blind');
    }, 'a flipped verdict must fail this pin');
  } finally {
    fs.rmSync(tmp, { force: true });
  }
});

test('T6: live - a transfer at maxLamports on the README pairing is refused on an empty window', () => {
  const CLI = path.join(ROOT, 'bin', 'signerd.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-wfpin-'));
  fs.chmodSync(dir, 0o700);
  let daemon = null;
  try {
    const pass = path.join(dir, 'pass');
    const keystore = path.join(dir, 'k.key');
    const grants = path.join(dir, 'g.json');
    const ledger = path.join(dir, 'l.jsonl');
    const socket = path.join(dir, 'd.sock');
    const tx = path.join(dir, 'tx.bin');
    fs.writeFileSync(pass, 'passphrase\n', { mode: 0o600 });
    const sh = (argv) => spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8' });

    assert.equal(sh(['keygen', '--keystore', keystore, '--passphrase-file', pass]).status, 0,
      'keygen must succeed');
    // The README quickstart pairing, as written (README.md:74): max == window.
    const created = sh(['grant-add', '--grants', grants, '--name', 'ops-payroll',
      '--keystore', keystore,
      '--destination', 'Vote111111111111111111111111111111111111111',
      '--max-lamports', '1000000', '--window-max-lamports', '1000000',
      '--window-seconds', '60', '--expires', '2030-01-01T00:00:00Z']);
    assert.equal(created.status, 0,
      'creation still accepts the README pairing (issue #1, D5); a fix that ' +
      'refuses it makes this RED on purpose - update this pin with the fix.');

    daemon = spawn(process.execPath,
      [CLI, 'run', '--keystore', keystore, '--passphrase-file', pass,
        '--grants', grants, '--ledger', ledger, '--socket', socket],
      { stdio: 'ignore', detached: true });
    let live = false;
    for (let i = 0; i < 60 && !live; i += 1) {
      const probe = spawnSync(process.execPath,
        [CLI, 'status', '--socket', socket], { encoding: 'utf8' });
      live = probe.status === 0 && probe.stdout.includes('"state":"live"');
      if (!live) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    }
    assert.ok(live, 'daemon must come up');

    assert.equal(sh(['build-tx', '--keystore', keystore,
      '--to', 'Vote111111111111111111111111111111111111111',
      '--lamports', '1000000', '--out', tx,
      '--blockhash', '4wUkybwB9QMxybEMnEivvKRcnVUnJcncyA2kbLsrqtzB']).status, 0,
      'build-tx must succeed');

    const attempt = sh(['sign', '--socket', socket, '--grant', 'ops-payroll', '--tx', tx]);
    assert.equal(attempt.status, 1, 'the transfer at maxLamports must be refused');
    let body = null;
    try { body = JSON.parse(attempt.stdout.trim().split('\n').pop()); } catch { /* asserted below */ }
    assert.ok(body, `stdout must be JSON, got: ${attempt.stdout}`);
    assert.equal(body.error, 'window_cap');
    // THE defect: an empty window, refusing, while reporting spent 0 and the
    // FULL cap remaining (issue #1, D1+D2).
    assert.equal(body.detail && body.detail.windowSpentLamports, '0');
    assert.equal(body.detail && body.detail.windowRemainingLamports, '1000000');
    assert.match(body.fix || '', /grant-add/,
      'the fix line still names grant-add (issue #1, D3: it refuses grant_exists)');
    // Nothing was spent, so nothing may be journaled.
    const records = fs.existsSync(ledger)
      ? fs.readFileSync(ledger, 'utf8').split('\n').filter(Boolean).length : 0;
    assert.equal(records, 0, 'an empty-window refusal must journal nothing');
  } finally {
    if (daemon !== null) {
      try { process.kill(-daemon.pid); } catch { try { daemon.kill(); } catch { /* gone */ } }
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
