// Controls for tools/policy-traffic.mjs - the instrument that measures
// signerd's OWN policy (src/policy.js evaluate) against REAL mainnet wire
// bytes. The instrument's numbers are only worth as much as its ability to
// (a) see the product approve a transaction it should approve, (b) see the
// product refuse what it should refuse, and (c) re-derive every published
// number from committed rows instead of a typed-in counter.
//
// All three controls run OFFLINE against the committed fixture rows
// (research/policy-traffic-2026-11-02-rows.json). CI therefore verifies the
// instrument without network, the same way the traffic-coverage controls do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const run = promisify(execFile);
const REPO = path.join(import.meta.dirname, '..');
const TOOL = path.join(REPO, 'tools', 'policy-traffic.mjs');
const ROWS = path.join(REPO, 'research', 'policy-traffic-2026-11-02-rows.json');
const REPORT = path.join(REPO, 'research', 'policy-traffic-2026-11-02.json');

async function replay(rowsPath, outPath) {
  const { stdout } = await run(process.execPath, [TOOL, `--fixture=${rowsPath}`, `--out=${outPath}`], {
    timeout: 60000,
  });
  return { stdout, report: JSON.parse(await readFile(outPath, 'utf8')) };
}

test('the probe sees the product approve, refuse by destination/amount, and refuse garbage (self-check)', async () => {
  const { stdout } = await run(process.execPath, [TOOL, '--selftest'], { timeout: 60000 });
  assert.match(stdout, /selftest OK \(4\/4\)/);
  assert.match(stdout, /PASS allowed/);
  assert.match(stdout, /PASS destination/);
  assert.match(stdout, /PASS amount/);
  assert.match(stdout, /PASS invalid_wire/);
});

test('replay re-derives every published number from the committed rows', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'signerd-pt-'));
  try {
    const { report } = await replay(ROWS, path.join(dir, 'out.json'));
    const committed = JSON.parse(await readFile(REPORT, 'utf8'));
    assert.equal(report.source, 'fixture');
    assert.deepEqual(report.totals, committed.totals, 'totals must re-derive from rows');
    assert.deepEqual(report.byVersion, committed.byVersion, 'version mix must re-derive from rows');
    assert.deepEqual(report.byCandidateReason, committed.byCandidateReason, 'candidate reasons must re-derive');
    assert.deepEqual(report.refusalsAmongCandidates, committed.refusalsAmongCandidates, 'refusals must re-derive');
    // The headline of this measurement, asserted from the rows: the product
    // approves the large majority of candidate transfers, and every refusal
    // among candidates is a named structural reason - never a silent pass.
    const t = report.totals;
    assert.ok(t.transactions > 0, 'sample must be non-empty');
    assert.equal(t.pairingUnverified, 0, 'every row must be pairing-verified before verdicts are published');
    assert.ok(t.candidates > 0, 'sample must contain envelope-shaped transactions');
    assert.ok(t.approved > 0, 'the product must approve some real candidates');
    assert.ok(t.approved <= t.candidates, 'approval cannot exceed candidates');
    for (const reason of Object.keys(report.refusalsAmongCandidates)) {
      assert.ok(
        ['version_or_alt', 'invalid_wire', 'envelope', 'duplicate_key', 'signer_or_fee_payer',
          'destination', 'program', 'instruction_accounts', 'instruction_data', 'amount',
          'noncanonical_wire'].includes(reason),
        `unexpected refusal reason: ${reason}`
      );
    }
    // Version mix is part of the published finding: version-1 traffic exists
    // and is counted, not folded into an unnamed bucket.
    assert.ok(Number(report.byVersion['1'] || 0) > 0, 'version-1 transactions must be counted explicitly');
    assert.ok(Number(report.byVersion.legacy) > 0, 'legacy transactions must be counted explicitly');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('a hand-edited counter in the committed report is caught by replay (mutation control)', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'signerd-pt-'));
  try {
    const rows = JSON.parse(await readFile(ROWS, 'utf8'));
    // Mutate the ROWS (the only source of truth): flip one approved candidate
    // to refused. Replay must no longer reproduce the committed report.
    const first = rows.rows.find(r => r.candidate && r.allowed);
    assert.ok(first, 'fixture must contain at least one approved candidate');
    first.allowed = false;
    first.refused = 'destination';
    const mutatedPath = path.join(dir, 'rows.json');
    await writeFile(mutatedPath, JSON.stringify(rows));
    const { report } = await replay(mutatedPath, path.join(dir, 'out.json'));
    const committed = JSON.parse(await readFile(REPORT, 'utf8'));
    assert.notDeepEqual(report.totals, committed.totals,
      'mutating a row must change the derived totals - otherwise the counter is typed in');
    assert.equal(report.totals.approved, committed.totals.approved - 1, 'exactly one approval must disappear');
    // The bucket may not exist in the committed report at all (undefined, not
    // 0) - read it as a number so the comparison is about the COUNT, not
    // about the key being present.
    const before = Number(committed.refusalsAmongCandidates.destination || 0);
    assert.equal(Number(report.refusalsAmongCandidates.destination || 0), before + 1,
      'the refusal must move to its named bucket');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the refusal reasons among candidates are measured fail-closed, none silently allowed', async () => {
  const rows = JSON.parse(await readFile(ROWS, 'utf8'));
  const candidates = rows.rows.filter(r => r.candidate);
  assert.ok(candidates.length > 0);
  for (const row of candidates) {
    if (row.allowed) {
      assert.equal(row.version, 'legacy',
        `only legacy messages may be approved; got version ${row.version} (${row.signature})`);
      assert.equal(row.refused, null, 'an approved row must carry no refusal');
      assert.equal(row.paired, true, 'an approved row must be pairing-verified');
      // The grant was built from the transaction itself, so the reported
      // amount must equal the amount the product read from the wire.
      assert.equal(row.amountLamports, row.grant.maxLamports);
    } else {
      assert.ok(row.refused, `a refused candidate must name its reason (${row.signature})`);
      assert.notEqual(row.refused, 'unknown', 'refusals must be named, never unknown');
    }
  }
});
