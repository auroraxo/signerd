#!/usr/bin/env node
'use strict';

/**
 * MEASURE THE GRANT CAP DOMAIN (2026-11-09).
 *
 * WHAT must hold: what the grant file ACCEPTS must be exactly what the
 * daemon can HONOUR. A cap that the loader accepts but the runtime can
 * never satisfy is a scope the operator believes is live and that is dead
 * on arrival - the same defect class as the 2026-11-08 grant value
 * contract (16 of 30 values written and then refused).
 *
 * WHY (measured 2026-11-09, on this tree): the CAPS are judged by their
 * FORM at the creation path and the loader, but by their MEANING at the
 * runtime:
 *   - `windowMaxLamports` is a lamport budget. The ledger charges
 *     `amount + 5000` (BASE_FEE_LAMPORTS) per approval, so a cap below
 *     the fee can never be met - every request is refused `window_cap`.
 *     A cap of 0 is the clearest case: the operator asked for "no
 *     spending in this window", got a written grant, and every request
 *     dies.
 *   - `windowMaxMessages` is a COUNT of signed receipts. A count of 0
 *     can never be reached: the ledger refuses with `window_cap` before
 *     the first signature (signed + 1 > 0), so the grant is dead on
 *     arrival - and the CLI's own repair text already says the field
 *     must be "a positive whole number of messages".
 *   - `maxLamports` is a per-transfer cap. 0 is refused at request time
 *     with `amount` (the transfer of 0 lamports... actually a 0-amount
 *     transfer IS allowed by the envelope, see README "amount 0 is
 *     allowed"), but the WINDOW cap is what kills it.
 *
 * FOR EACH CASE this records, for BOTH trees:
 *   load    does the product's own loader (src/grantfile.js) accept the
 *           grant file?
 *   create  does `signerd grant-add` (the CLI an operator walks) accept
 *           the value and write the file?
 *   runtime what does the daemon's own decision (policy + ledger) say for
 *           the MINIMAL request (amount 0 - the cheapest transfer the
 *           product's own policy admits, see README "amount 0 is
 *           allowed"); runtimeAtAmount42 keeps the 42-lamport outcome
 *           visible so the choice of probe cannot hide anything
 *   contractHolds  load === runtime
 *
 * WHY THE MINIMAL REQUEST: the contract is an EXISTENCE claim - the loader
 * may accept a grant only if the daemon CAN honour at least one real
 * request against it. The cheapest real transaction costs exactly
 * BASE_FEE_LAMPORTS (5000), so `windowMaxLamports < 5000` can never be met
 * (dead on arrival) while `>= 5000` can. A fixed amount-42 probe answers a
 * DIFFERENT question ("is this particular request inside the cap") and
 * mislabels a live grant whose cap sits between 5000 and 5042 - that
 * instrument error was made in the first run of this tool, whose guard
 * case `windowMaxLamports=5000` came back as a contract violation.
 *
 * The baseline runs against `git archive v0.2.12` - the code a stranger
 * installs - never against this working tree. The verdict comes from what
 * the loader and the daemon actually returned; this is a measurement, not
 * an assertion. Exit code 1 when the contract does NOT hold, so the tool
 * can gate a release.
 *
 * Output: research/grant-cap-domain-2026-11-09.json
 * Pinned by: test/grant-cap-domain-measurement.test.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'research', 'grant-cap-domain-2026-11-09.json');
const BASELINE_TAG = 'v0.2.12';

const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const crypto = require('node:crypto');

// The wire is built from THESE two keys, so the daemon's verdict can only
// be about the grant under test - never about a wire/grant key mismatch.
const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();

const TX_GOOD = {
  signer: PAYER.publicKey.toBase58(),
  destination: RECIPIENT.publicKey.toBase58(),
  maxLamports: '42',
  expiresAt: '2030-01-01T00:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

const MSG_GOOD = {
  kind: 'message',
  issuer: 'acme',
  type: 'receipt',
  subject: 'order/1',
  pubkey: crypto.randomBytes(32).toString('base64'),
  maxBytes: '700',
  expiresAt: '2030-01-01T00:00:00Z',
  windowMaxMessages: '5',
  windowSeconds: '3600',
};

/**
 * The cases: one substitution into an otherwise good grant, plus the
 * guards that must keep working.
 *
 * The 'defect' cases are values the loader accepts but the runtime can
 * never satisfy. The 'guard' cases are values that must keep being
 * accepted (they are the ones an operator writes on purpose).
 */
const CASES = [
  // windowMaxLamports: the lamport budget. The ledger charges amount +
  // 5000 (the fixed base fee) per approval, so a cap below the fee can
  // never be met.
  { kind: 'tx', field: 'windowMaxLamports', value: '0', label: 'zero lamport window cap', expect: 'defect' },
  { kind: 'tx', field: 'windowMaxLamports', value: '1', label: 'window cap below the base fee', expect: 'defect' },
  { kind: 'tx', field: 'windowMaxLamports', value: '4999', label: 'one lamport below the base fee', expect: 'defect' },
  { kind: 'tx', field: 'windowMaxLamports', value: '5000', label: 'exactly the base fee', expect: 'guard' },
  { kind: 'tx', field: 'windowMaxLamports', value: '5042', label: 'amount 42 plus the base fee', expect: 'guard' },
  { kind: 'tx', field: 'windowMaxLamports', value: '100000', label: 'ordinary window cap', expect: 'guard' },

  // windowMaxMessages: the receipt count. Zero can never be reached -
  // the ledger refuses before the FIRST signature.
  { kind: 'msg', field: 'windowMaxMessages', value: '0', label: 'zero message cap', expect: 'defect' },
  { kind: 'msg', field: 'windowMaxMessages', value: '1', label: 'one message cap', expect: 'guard' },
  { kind: 'msg', field: 'windowMaxMessages', value: '5', label: 'ordinary message cap', expect: 'guard' },

  // The tx side's windowMaxLamports=0 is the same defect expressed in
  // the other envelope; a message grant has no windowMaxLamports at all
  // (the fields are disjoint by design).
  { kind: 'msg', field: 'windowMaxMessages', value: '00', label: 'zero with leading zeros', expect: 'defect' },
];

/** Extract a tagged tree into a scratch dir (the published baseline). */
function extractTag(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `capdom-${tag}-`));
  const res = spawnSync('sh', ['-c', `git archive ${tag} | tar -x -C "${dir}"`],
    { cwd: ROOT, encoding: 'utf8' });
  if (res.status !== 0) throw new Error(`git archive ${tag} failed: ${res.stderr}`);
  fs.cpSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), { recursive: true });
  return dir;
}

/**
 * The loader's verdict for a grant, in a given tree.
 *
 * The loader is the PRODUCT's own reader (src/grantfile.js). We write the
 * file the way an operator's editor would and ask the loader to read it.
 */
function loadVerdict(tree, grant) {
  const grantfile = require(path.join(tree, 'src', 'grantfile.js'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdom-load-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants: { ops: grant } }, null, 2) + '\n',
    { mode: 0o600 });
  try {
    grantfile.loadGrantFile(file);
    return { accepted: true, code: null };
  } catch (err) {
    return { accepted: false, code: err && err.code ? err.code : 'unknown' };
  }
}

/**
 * The daemon's own verdict for a grant, in a given tree: the policy
 * layer first, then the ledger (the window cap lives there).
 */
function runtimeVerdict(tree, kind, grant) {
  const policy = require(path.join(tree, 'src', 'policy.js'));
  const ledgerMod = require(path.join(tree, 'src', 'ledger.js'));
  const policyMessage = require(path.join(tree, 'src', 'policy-message.js'));
  const now = new Date('2026-11-09T00:00:00.000Z');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdom-led-'));
  fs.chmodSync(dir, 0o700);
  const ledger = new ledgerMod.Ledger({ file: path.join(dir, 'journal.jsonl') });

  if (kind === 'tx') {
    const tx = new Transaction();
    tx.feePayer = PAYER.publicKey;
    tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
    tx.add(SystemProgram.transfer({
      fromPubkey: PAYER.publicKey,
      toPubkey: RECIPIENT.publicKey,
      // The MINIMAL request: 0 lamports. Its cost on chain is exactly
      // BASE_FEE_LAMPORTS (5000), so this is the cheapest real request the
      // product's own policy admits - the existence probe the contract is
      // about.
      lamports: 0,
    }));
    tx.sign(PAYER);
    const wire = tx.serialize();
    const verdict = ledgerMod.gate(wire, grant, now, ledger);
    const pol = policy.evaluate(wire, grant, now);
    return {
      allowed: verdict.allowed === true,
      refused: verdict.refused || null,
      policyRefused: pol.refused || null,
    };
  }
  const body = {
    schema: 'openreceipts/v1',
    issuer: MSG_GOOD.issuer,
    type: MSG_GOOD.type,
    subject: MSG_GOOD.subject,
    claims: { sku: 'X' },
    issued_at: '2026-11-09T00:00:00Z',
  };
  const pol = policyMessage.evaluateMessage(body, grant, now);
  if (!pol.allowed) {
    return { allowed: false, refused: pol.refused || null, policyRefused: pol.refused || null };
  }
  const led = ledger.previewMessage({ messageBytes: pol.messageBytes, grant, now });
  return {
    allowed: led.allowed === true,
    refused: led.refused || null,
    policyRefused: null,
  };
}

/** The 42-lamport twin of the runtime probe (informational, not the contract). */
function runtimeVerdictAtAmount(tree, grant, lamports) {
  const policy = require(path.join(tree, 'src', 'policy.js'));
  const ledgerMod = require(path.join(tree, 'src', 'ledger.js'));
  const now = new Date('2026-11-09T00:00:00.000Z');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'capdom-led42-'));
  fs.chmodSync(dir, 0o700);
  const ledger = new ledgerMod.Ledger({ file: path.join(dir, 'journal.jsonl') });
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports,
  }));
  tx.sign(PAYER);
  const wire = tx.serialize();
  const verdict = ledgerMod.gate(wire, grant, now, ledger);
  const pol = policy.evaluate(wire, grant, now);
  return {
    allowed: verdict.allowed === true,
    refused: verdict.refused || null,
    policyRefused: pol.refused || null,
  };
}

/** One tree, all cases. */
function measureTree(tree) {
  const rows = [];
  for (const c of CASES) {
    const good = c.kind === 'tx' ? TX_GOOD : MSG_GOOD;
    const grant = { ...good, [c.field]: c.value };
    const load = loadVerdict(tree, grant);
    const runtime = runtimeVerdict(tree, c.kind, grant);
    rows.push({
      kind: c.kind,
      field: c.field,
      value: c.value,
      label: c.label,
      expect: c.expect,
      loadAccepted: load.accepted,
      loadCode: load.code,
      runtimeAllowed: runtime.allowed,
      runtimeRefused: runtime.refused,
      policyRefused: runtime.policyRefused,
      contractHolds: load.accepted === runtime.allowed,
    });
    if (c.kind === 'tx') {
      // The 42-lamport twin, recorded but NOT part of the contract: it is
      // the request the first version of this tool probed with, so the
      // change of probe cannot be mistaken for the defect moving.
      rows[rows.length - 1].runtimeAtAmount42 = runtimeVerdictAtAmount(tree, grant, 42);
    }
  }
  return rows;
}

/** The verdicts the artifact must show, derived from the rows themselves. */
function summarize(rows) {
  const defects = rows.filter((r) => !r.contractHolds);
  const defectCases = rows.filter((r) => r.expect === 'defect');
  const guardCases = rows.filter((r) => r.expect === 'guard');
  return {
    cases: rows.length,
    contractViolations: defects.length,
    defectCases: defectCases.length,
    defectCasesViolated: defectCases.filter((r) => !r.contractHolds).length,
    guardCases: guardCases.length,
    guardCasesViolated: guardCases.filter((r) => !r.contractHolds).length,
    violations: defects.map((r) =>
      `${r.kind}.${r.field}=${r.value} (${r.label}): load=${r.loadAccepted} runtime=${r.runtimeAllowed} refused=${r.runtimeRefused}`),
  };
}

function main() {
  const baseline = extractTag(BASELINE_TAG);
  const before = measureTree(baseline);
  const after = measureTree(ROOT);

  const beforeSummary = summarize(before);
  const afterSummary = summarize(after);

  const verdict = afterSummary.contractViolations === 0 && beforeSummary.contractViolations > 0
    ? 'fixed'
    : (afterSummary.contractViolations === 0 ? 'clean' : 'open');

  const doc = {
    generatedAt: '2026-11-09',
    tool: 'tools/measure-grant-cap-domain.js',
    baseline: {
      tag: BASELINE_TAG,
      source: `git archive ${BASELINE_TAG}`,
      commit: spawnSync('git', ['rev-list', '-n', '1', BASELINE_TAG], { cwd: ROOT, encoding: 'utf8' })
        .stdout.trim(),
    },
    subject: {
      tree: 'working tree',
      commit: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim(),
    },
    verdict,
    before: beforeSummary,
    after: afterSummary,
    rows: { before, after },
  };
  fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');

  process.stdout.write(JSON.stringify({
    baseline: BASELINE_TAG,
    verdict,
    before: beforeSummary,
    after: afterSummary,
    out: path.relative(ROOT, OUT),
  }, null, 2) + '\n');
  process.exit(afterSummary.contractViolations > 0 ? 1 : 0);
}

main();
