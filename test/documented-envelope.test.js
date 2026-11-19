'use strict';

// THE DOCUMENTED ENVELOPE: the front page's sign/refuse table must describe
// the policy the shipped tree actually runs (2026-11-19).
//
// WHY (measured 2026-11-19, tree a9e2207,
// research/documented-envelope-prefix-2026-11-19.json, verdict
// documented-envelope-overclaim, 4 of 10 faces defective): the README's
// "What it will and will not sign" table promised the DESIGNED v1 envelope
// while src/policy.js signs exactly ONE legacy System transfer:
//
//   Sign cell "System transfers, Memo, ComputeBudget"
//     memo-only wire            -> refused "envelope"   (claimed: signs)
//     compute-budget-only wire  -> refused "envelope"   (claimed: signs)
//   Sign cell "SPL Token Transfer / TransferChecked ..."
//     spl token transfer wire   -> refused "envelope"   (claimed: signs)
//   `{refused: "alt", ...}` — src/ mints 158 codes; `alt` is not one of
//     them (the real code for lookup tables is `version_or_alt`).
//
// A script scoping its grant by the front page gets the OPPOSITE of what it
// read, and the same table ships in the npm tarball a stranger installs
// (measured: `npm pack signerd@0.2.40` -> package/README.md carries the
// identical lines). The existing README gates check different contracts —
// invocation runs (documented-surface), install pin (release-contract,
// pin-release-sync), command dispatch (installed-tag-journey) — none asks
// whether a documented CAPABILITY is real.
//
// THE CONTRACT (D = defect face, RED on the pre-fix tree; G = guard, green
// on BOTH trees):
//   D1 every Sign cell's shape is ADMITTED by the product's own evaluate()
//      (memo / compute-budget / SPL-token cells were refused `envelope`);
//   D2 every `{refused: "..."}` the README quotes is a code src/ actually
//      mints (`alt` is minted by nothing);
//   G1 control: the admitted shape (a plain legacy System transfer) still
//      signs — a fix that refuses everything to make the page honest must
//      not pass;
//   G2 the REFUSES column still refuses (ALT wire, CPI program, Token-2022):
//      the fix must not widen the product to make the README true;
//   G3 the cap claim holds: an over-cap transfer still refuses `amount`;
//   G4 the instrument CAN fail: a fixture README that over-claims is caught
//      (a detector that reports nothing for any input is not a detector);
//   G5 the instrument fails CLOSED: a Sign cell no probe can judge is a
//      defect, never a clean verdict.
//
// HOW: the instrument (tools/measure-documented-envelope.js) pairs each
// Sign cell with a probe that builds that shape and runs the product's own
// src/policy.js evaluate() in a child process. No network, no daemon.
// LADDER: D1/D2 RED on the pre-fix tree (the prefix artifact above, and the
// scratch-worktree run), G1-G5 GREEN on both; mutation ladder
// tools/mutation-ladder-documented-envelope.sh.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'tools', 'measure-documented-envelope.js');
const README = path.join(ROOT, 'README.md');

function runMeasure(readmePath) {
  const out = path.join(os.tmpdir(), `docenv-${process.pid}-${Date.now()}.json`);
  try {
    const r = spawnSync(process.execPath, [TOOL, '--root', ROOT, '--readme', readmePath, '--out', out],
      { encoding: 'utf8', timeout: 120000 });
    let report = null;
    if (fs.existsSync(out)) report = JSON.parse(fs.readFileSync(out, 'utf8'));
    return { report, status: r.status };
  } finally {
    try { fs.rmSync(out, { force: true }); } catch { /* gone */ }
  }
}

const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'docenv-gate-'));
test.after(() => { try { fs.rmSync(fixtureDir, { recursive: true, force: true }); } catch { /* gone */ } });

// ---------------------------------------------------------------------------
// D1/D2: MAIN's README against MAIN's policy.
// ---------------------------------------------------------------------------
test('D1 the front page only claims shapes this policy admits (RED pre-fix)', () => {
  const { report } = runMeasure(README);
  assert.ok(report, 'the instrument must produce a report');
  const overclaims = report.results.filter((r) => r.kind === 'sign-claim' && r.defect);
  assert.deepStrictEqual(overclaims.map((r) => r.id), [],
    'Sign cells promised more than the policy signs: ' +
    overclaims.map((r) => `${r.id}(${r.why})`).join('; '));
});

test('D2 every refusal code the README quotes is minted by src/ (RED pre-fix)', () => {
  const { report } = runMeasure(README);
  assert.ok(report, 'the instrument must produce a report');
  const bad = report.results.filter((r) => r.kind === 'example-code' && r.defect);
  assert.deepStrictEqual(bad.map((r) => r.measured), [],
    'the README quotes a {refused: ...} code the product cannot produce: ' +
    bad.map((r) => r.why).join('; '));
});

test('D2b the whole report is clean: no face may be defective on this tree', () => {
  const { report } = runMeasure(README);
  assert.ok(report, 'the instrument must produce a report');
  assert.strictEqual(report.verdict, 'documented-envelope-truthful',
    `verdict ${report.verdict}: ` +
    report.results.filter((r) => r.defect).map((r) => r.why).join('; '));
  assert.strictEqual(report.faceDefects, 0);
});

// ---------------------------------------------------------------------------
// G1-G3: the PRODUCT did not move — only the page did. Green on both trees.
// ---------------------------------------------------------------------------
test('G1 control: the admitted shape still signs (green on both)', () => {
  const { report } = runMeasure(README);
  const control = report.results.find((r) => r.id === 'system_transfer');
  if (control) {
    // present on any README that still claims system transfers
    assert.match(control.measured, /^allowed/, `control must stay admitted: ${control.measured}`);
    assert.strictEqual(control.defect, false);
  } else {
    // even a README that dropped the claim must not report the control as
    // refused — run the probe directly through the instrument's own shape:
    const direct = require('node:child_process').spawnSync(process.execPath, ['-e', `
      const { Keypair, SystemProgram, Transaction } = require(${JSON.stringify(path.join(ROOT, 'node_modules', '@solana', 'web3.js'))});
      const { evaluate } = require(${JSON.stringify(path.join(ROOT, 'src', 'policy.js'))});
      const s = Keypair.generate(), to = Keypair.generate().publicKey;
      const tx = new Transaction();
      tx.feePayer = s.publicKey;
      tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
      tx.add(SystemProgram.transfer({ fromPubkey: s.publicKey, toPubkey: to, lamports: 42 }));
      tx.sign(s);
      process.stdout.write(JSON.stringify(evaluate(tx.serialize(), {
        signer: s.publicKey.toBase58(), destination: to.toBase58(),
        maxLamports: '1000', expiresAt: '2027-01-01T00:00:00Z',
      }, new Date('2026-11-19T06:00:00Z'))));
    `], { encoding: 'utf8', timeout: 60000 });
    assert.strictEqual(JSON.parse(direct.stdout).allowed, true,
      'the plain legacy System transfer is the admitted shape on both trees');
  }
});

test('G2 the REFUSES column still refuses (green on both — no widening)', () => {
  const { report } = runMeasure(README);
  const guards = report.results.filter((r) => r.kind === 'refuse-guard');
  assert.ok(guards.length >= 3, `the three refusal guards must run: ${guards.length}`);
  for (const g of guards) {
    assert.strictEqual(g.defect, false, `${g.id} must still refuse: ${g.why}`);
  }
});

test('G3 the cap claim holds: an over-cap transfer refuses amount (green on both)', () => {
  const { report } = runMeasure(README);
  const cap = report.results.find((r) => r.id === 'spend_cap');
  if (cap) {
    assert.strictEqual(cap.measured, 'refused:amount', `cap claim: ${cap.why}`);
    assert.strictEqual(cap.defect, false);
  }
});

// ---------------------------------------------------------------------------
// G4/G5: the instrument itself must fail in the dangerous directions.
// ---------------------------------------------------------------------------
test('G4 an over-claiming fixture README is caught (detector can fail)', () => {
  const fixture = path.join(fixtureDir, 'overclaim.md');
  fs.writeFileSync(fixture, [
    '# x', '',
    '## What it will and will not sign', '',
    '| Signs | Refuses |', '|---|---|',
    '| System transfers, Memo | Address lookup tables |',
    '| SPL Token transfers | Token-2022 |',
    '', 'Measured on 2,835 transactions.', '',
    'a machine-readable reason (`{refused: "totally_not_a_code", ...}`).',
    '',
    '```bash', 'signerd keygen --keystore k --passphrase-file p', '```',
    '',
    'npm install github:auroraxo/signerd#v0.2.40',
    '',
    '```bash', 'umask 077', '```',
  ].join('\n'));
  const { report } = runMeasure(fixture);
  assert.ok(report, 'the instrument must produce a report');
  const ids = report.results.filter((r) => r.defect).map((r) => r.id);
  assert.ok(ids.includes('memo'), `the memo over-claim must be caught: ${JSON.stringify(ids)}`);
  assert.ok(ids.includes('spl_token_transfer'), `the SPL over-claim must be caught: ${JSON.stringify(ids)}`);
  assert.ok(ids.includes('refusal_example_minted'), `the fake refusal code must be caught: ${JSON.stringify(ids)}`);
  assert.strictEqual(report.verdict, 'documented-envelope-overclaim');
});

test('G5 an unreadable Sign cell fails CLOSED, never clean (detector not vacuous)', () => {
  const fixture = path.join(fixtureDir, 'unknown-claim.md');
  fs.writeFileSync(fixture, [
    '# x', '',
    '## What it will and will not sign', '',
    '| Signs | Refuses |', '|---|---|',
    '| Zero-Knowledge Hyperbridge streaming | Address lookup tables |',
    '', '```bash', 'umask 077', '```',
    '', 'npm install github:auroraxo/signerd#v0.2.40',
  ].join('\n'));
  const { report } = runMeasure(fixture);
  assert.ok(report, 'the instrument must produce a report');
  const coverage = report.results.find((r) => r.id === 'claims_readable');
  assert.ok(coverage, 'the coverage face must exist');
  assert.strictEqual(coverage.defect, true,
    `a Sign cell no probe judges must be a defect, not a clean pass: ${coverage.why}`);
  assert.strictEqual(report.verdict, 'documented-envelope-overclaim');
});
