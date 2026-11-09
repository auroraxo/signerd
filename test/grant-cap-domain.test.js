'use strict';

// THE GRANT CAP DOMAIN (2026-11-09).
//
// WHAT THE DOMAIN IS: a cap that the loader accepts must be one the
// daemon can HONOUR. Measured on the published v0.2.12 baseline with
// tools/measure-grant-cap-domain.js (research/grant-cap-domain-2026-11-09.json):
// 4 of 5 defect cases were ACCEPTED by the loader and REFUSED by the
// runtime as `window_cap` on the very first request:
//
//   - `windowMaxLamports` in [0, 4999]: every approval costs amount + 5000
//     (the base fee, fixed by the single-signature / no-ComputeBudget
//     policy envelope). The cheapest real request (transfer of 0 lamports)
//     costs exactly 5000 lamports. A cap below 5000 can NEVER be satisfied:
//     every request dies on arrival.
//   - `windowMaxMessages: 0`: the ledger checks `signed + 1 > window.max`
//     BEFORE the first signature. At 0 messages the very first approval
//     dies (0 + 1 > 0). The CLI's repair text already states the field must
//     be "a positive whole number of messages".
//
// THE RULES THIS PINS:
//   C1 grant-add REFUSES windowMaxLamports below the base fee (0, 1, 4999)
//      with grant_field_invalid, naming the repair, and writes NO file.
//   C2 grant-add REFUSES windowMaxMessages <= 0 (0, "00") and writes NO file.
//   C3 the loader (src/grantfile.js) refuses the same dead caps at load
//      time, so a hand-edited file fails at daemon startup.
//   G1 (guard, green on both trees) windowMaxLamports = 5000 (exactly the
//      base fee) is accepted and approves a 0-lamport transfer.
//   G2 (guard, green on both trees) windowMaxLamports = 5042 approves an
//      amount-42 transfer.
//   G3 (guard, green on both trees) windowMaxMessages = 1 is accepted and
//      approves a message.
//   G4 (guard, green on both trees) ordinary caps (100000 lamports, 5 msgs)
//      keep working end-to-end.
//
// The ladder: C1-C3 are RED on the pre-fix tree (v0.2.12); G1-G4 are GREEN
// on both.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { validateGrant, loadGrantFile } = require('../src/grantfile');
const { validateTxGrantArgs, validateMessageGrantArgs } = require('../src/grantadd');
const { Ledger, gate } = require('../src/ledger');
const policyMessage = require('../src/policy-message');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();
const NOW = new Date('2026-11-09T00:00:00.000Z');

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
  pubkey: Buffer.alloc(32, 1).toString('base64'),
  maxBytes: '700',
  expiresAt: '2030-01-01T00:00:00Z',
  windowMaxMessages: '5',
  windowSeconds: '3600',
};

function runCliCreate(grant) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cap-cli-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  const args = [CLI, 'grant-add', '--grants', file, '--name', 'ops',
    '--signer', grant.signer, '--destination', grant.destination,
    '--max-lamports', grant.maxLamports,
    '--window-max-lamports', grant.windowMaxLamports,
    '--window-seconds', grant.windowSeconds,
    '--expires', grant.expiresAt];
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000 });
  return {
    status: res.status,
    wrote: fs.existsSync(file),
    stderr: res.stderr || '',
  };
}

function loadThrows(grant) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cap-load-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants: { ops: grant } }, null, 2) + '\n',
    { mode: 0o600 });
  try {
    loadGrantFile(file);
    return false;
  } catch (err) {
    return err && err.code === 'grant_field_invalid';
  }
}

// ---------------------------------------------------------------------------
// C1: windowMaxLamports below the 5000-lamport base fee is refused.
// ---------------------------------------------------------------------------

test('C1 grant-add refuses windowMaxLamports below 5000 and writes nothing', () => {
  for (const value of ['0', '1', '4999']) {
    const grant = { ...TX_GOOD, windowMaxLamports: value };
    assert.throws(
      () => validateTxGrantArgs({ ...grant, name: 'ops' }),
      /grant_field_invalid/,
      `validateTxGrantArgs must refuse windowMaxLamports=${value}`
    );
    const cli = runCliCreate(grant);
    assert.notEqual(cli.status, 0, `CLI must exit non-zero for windowMaxLamports=${value}`);
    assert.equal(cli.wrote, false, `CLI must not write grants.json for windowMaxLamports=${value}`);
    assert.match(cli.stderr, /grant_field_invalid: windowMaxLamports/);
    assert.match(cli.stderr, /fix: set the field to an integer between 5000/);
  }
});

// ---------------------------------------------------------------------------
// C2: windowMaxMessages <= 0 is refused by validateMessageGrantArgs.
// ---------------------------------------------------------------------------

test('C2 buildMessageGrant / validateMessageGrantArgs refuses windowMaxMessages <= 0', () => {
  for (const value of ['0', '00']) {
    const grant = { ...MSG_GOOD, windowMaxMessages: value };
    assert.throws(
      () => validateMessageGrantArgs({ ...grant, name: 'ops' }),
      /grant_field_invalid/,
      `validateMessageGrantArgs must refuse windowMaxMessages=${value}`
    );
  }
});

// ---------------------------------------------------------------------------
// C3: the loader refuses the dead caps at startup.
// ---------------------------------------------------------------------------

test('C3 loadGrantFile refuses dead caps with grant_field_invalid', () => {
  for (const value of ['0', '1', '4999']) {
    assert.equal(
      loadThrows({ ...TX_GOOD, windowMaxLamports: value }),
      true,
      `loader must refuse windowMaxLamports=${value}`
    );
  }
  for (const value of ['0', '00']) {
    assert.equal(
      loadThrows({ ...MSG_GOOD, windowMaxMessages: value }),
      true,
      `loader must refuse windowMaxMessages=${value}`
    );
  }
});

// ---------------------------------------------------------------------------
// G1-G4 GUARDS: the working boundary and ordinary caps are accepted.
// ---------------------------------------------------------------------------

test('G1 guard: windowMaxLamports = 5000 approves a 0-lamport transfer', () => {
  const grant = { ...TX_GOOD, windowMaxLamports: '5000' };
  assert.equal(loadThrows(grant), false, '5000 must load cleanly');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cap-g1-'));
  const ledger = new Ledger({ file: path.join(dir, 'journal.jsonl') });
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports: 0,
  }));
  tx.sign(PAYER);
  const verdict = gate(tx.serialize(), grant, NOW, ledger);
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.windowSpentLamports, '5000');
  assert.equal(verdict.windowRemainingLamports, '0');
});

test('G2 guard: windowMaxLamports = 5042 approves an amount-42 transfer', () => {
  const grant = { ...TX_GOOD, windowMaxLamports: '5042' };
  assert.equal(loadThrows(grant), false, '5042 must load cleanly');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cap-g2-'));
  const ledger = new Ledger({ file: path.join(dir, 'journal.jsonl') });
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports: 42,
  }));
  tx.sign(PAYER);
  const verdict = gate(tx.serialize(), grant, NOW, ledger);
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.windowSpentLamports, '5042');
  assert.equal(verdict.windowRemainingLamports, '0');
});

test('G3 guard: windowMaxMessages = 1 approves a message', () => {
  const grant = { ...MSG_GOOD, windowMaxMessages: '1' };
  assert.equal(loadThrows(grant), false, '1 message must load cleanly');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-cap-g3-'));
  const ledger = new Ledger({ file: path.join(dir, 'journal.jsonl') });
  const body = {
    schema: 'openreceipts/v1',
    issuer: grant.issuer,
    type: grant.type,
    subject: grant.subject,
    claims: { sku: 'X' },
    issued_at: '2026-11-09T00:00:00Z',
  };
  const pol = policyMessage.evaluateMessage(body, grant, NOW);
  assert.equal(pol.allowed, true);
  const verdict = ledger.approveMessage({
    messageBytes: pol.messageBytes, grant, now: NOW,
  });
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.windowMessages, '1');
});

test('G4 guard: ordinary caps (100000 lamports, 5 messages) load and create ok', () => {
  assert.equal(loadThrows(TX_GOOD), false);
  assert.equal(loadThrows(MSG_GOOD), false);
  const c1 = runCliCreate(TX_GOOD);
  assert.equal(c1.status, 0);
  assert.equal(c1.wrote, true);
});
