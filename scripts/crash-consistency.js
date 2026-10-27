'use strict';

// Falsification harness for the ledger's atomicity claim: "a returned approval
// is durable before the caller sees it". A child process approves transfers as
// fast as it can; the parent SIGKILLs it at a random moment and then checks the
// only invariant that matters: every approval the child REPORTED as allowed is
// present in the journal (journal is a superset of reported approvals), and the
// journal still loads. Journal records the caller never saw are benign.
//
// Run standalone: node scripts/crash-consistency.js [rounds]

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Ledger } = require('../src/ledger');

const ROUNDS = Number(process.argv[2]) || 25;
const CHILD = path.join(__dirname, 'crash-child.js');

function runRound(round) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-crash-'));
  const journal = path.join(dir, 'journal.jsonl');
  const report = path.join(dir, 'report.jsonl');
  const child = spawn(process.execPath, [CHILD, journal, report, '100000'], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  // Wait until the child has reported at least one approval (startup of
  // node + web3.js takes a few hundred ms), THEN kill at a pseudo-random
  // later point so rounds land mid-run, plausibly mid-append.
  const killAfterFirstApproval = () => {
    const delay = 5 + ((round * 977) % 120); // deterministic 5..125ms of racing
    setTimeout(() => child.kill('SIGKILL'), delay);
  };
  const waitForApproval = setInterval(() => {
    if (fs.existsSync(report) && fs.statSync(report).size > 0) {
      clearInterval(waitForApproval);
      killAfterFirstApproval();
    }
  }, 5);
  // Safety net: never hang forever if the child never reports.
  const safety = setTimeout(() => child.kill('SIGKILL'), 10_000);

  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', () => {
      clearInterval(waitForApproval);
      clearTimeout(safety);
      resolve({ dir, journal, report, stderr });
    });
  });
}

function readReport(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return { corrupt: line }; }
  });
}

test(`crash consistency: SIGKILL rounds preserve reported approvals (${ROUNDS} rounds)`, async () => {
  let reportedApprovals = 0;
  let journalReopens = 0;
  let bytesObserved = 0;

  for (let round = 0; round < ROUNDS; round += 1) {
    const { dir, journal, report, stderr } = await runRound(round);
    assert.equal(stderr, '', `round ${round}: child stderr not empty: ${stderr}`);

    const entries = readReport(report).filter((e) => e.verdict && e.verdict.allowed === true);
    reportedApprovals += entries.length;
    if (fs.existsSync(journal)) bytesObserved += fs.statSync(journal).size;

    // Invariant 1: the journal must load (torn tail repaired, no throw).
    let ledger;
    try {
      ledger = new Ledger({ file: journal });
    } catch (err) {
      assert.fail(`round ${round}: journal failed to load after SIGKILL: ${err.message}`);
    }
    journalReopens += 1;

    // Invariant 2: every approval the child REPORTED is durable in the journal.
    // This is the claim "fsync before the caller sees the verdict".
    const durable = new Set(ledger.records.map((r) => r.w));
    for (const entry of entries) {
      assert.ok(
        durable.has(entry.verdict.wireSha256),
        `round ${round}: reported approval ${entry.iteration} (${entry.verdict.wireSha256}) missing from journal`,
      );
    }

    // Invariant 3: sequence numbers in the journal are strictly contiguous.
    const seqs = ledger.records.map((r) => r.s);
    seqs.forEach((s, i) => assert.equal(s, i + 1, `round ${round}: seq gap at ${i}`));

    fs.rmSync(dir, { recursive: true, force: true });
  }

  // Sanity: the rounds actually exercised the path (not all instantly killed).
  assert.ok(reportedApprovals >= 10, `too few approvals observed: ${reportedApprovals}`);
  assert.ok(bytesObserved > 0, 'journal never existed: rounds did not exercise appends');
  console.log(`    crash harness: ${ROUNDS} rounds, ${reportedApprovals} reported approvals, all durable`);
});
