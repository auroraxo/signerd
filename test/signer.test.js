'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keypair, SystemProgram, Transaction, VersionedTransaction } = require('@solana/web3.js');
const { Ledger } = require('../src/ledger');
const { signApproved, publicKeyObject, MESSAGE_OFFSET } = require('../src/signer');

const crypto = require('node:crypto');
const bs58 = require('bs58');

const signer = Keypair.generate();
const recipient = Keypair.generate().publicKey;
const blockhash = Keypair.generate().publicKey.toBase58();
const now = new Date('2026-10-27T10:00:00.000Z');
const grant = {
  signer: signer.publicKey.toBase58(),
  destination: recipient.toBase58(),
  maxLamports: '42',
  expiresAt: '2026-10-28T10:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

function wireFor(lamports = 42, keypair = signer) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}
function tmpLedger() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sign-'));
  return new Ledger({ file: path.join(dir, 'journal.jsonl') });
}

test('an approved transaction comes back signed, byte-identical outside the signature slot', () => {
  const ledger = tmpLedger();
  const input = wireFor();
  const verdict = signApproved({ wire: input, grant, ledger, keypair: signer, now });
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.signed.length, input.length);
  // Only the 64-byte signature slot may differ.
  assert.ok(verdict.signed.subarray(0, MESSAGE_OFFSET - 64).equals(input.subarray(0, MESSAGE_OFFSET - 64)));
  assert.ok(verdict.signed.subarray(MESSAGE_OFFSET).equals(input.subarray(MESSAGE_OFFSET)));
  assert.equal(verdict.signed[0], input[0]);

  // Independent verification with a third implementation path (OpenSSL via
  // Node's crypto, wrapping the raw key as SPKI DER).
  const parsed = VersionedTransaction.deserialize(verdict.signed);
  const message = Buffer.from(parsed.message.serialize());
  const signature = Buffer.from(parsed.signatures[0]);
  assert.equal(crypto.verify(null, message, publicKeyObject(grant.signer), signature), true);
  // And a tampered message must fail under the same key.
  const tampered = Buffer.from(message);
  tampered[tampered.length - 1] ^= 0x01;
  assert.equal(crypto.verify(null, tampered, publicKeyObject(grant.signer), signature), false);
  assert.equal(verdict.signature, bs58.encode(signature));
  // Budget was recorded exactly once, before signing.
  assert.deepEqual(ledger.snapshot(), { records: 1, seq: 1, fingerprints: 1 });
});

test('refusals never produce a signature and never touch the ledger', () => {
  const ledger = tmpLedger();
  const over = wireFor(43);
  const tooMuch = signApproved({ wire: over, grant, ledger, keypair: signer, now });
  assert.equal(tooMuch.allowed, false);
  assert.equal(tooMuch.refused, 'amount');
  assert.equal(tooMuch.signed, undefined);

  const wrongKey = Keypair.generate();
  const mismatch = signApproved({ wire: wireFor(42, wrongKey), grant, ledger, keypair: signer, now });
  assert.equal(mismatch.allowed, false);
  // The wire itself does not match the grant signer, so policy refuses first.
  assert.equal(mismatch.refused, 'signer_or_fee_payer');

  const expired = { ...grant, expiresAt: now.toISOString() };
  const gone = signApproved({ wire: wireFor(42), grant: expired, ledger, keypair: signer, now });
  assert.equal(gone.refused, 'expired');
  assert.equal(ledger.snapshot().records, 0);
});

test('a grant the daemon key cannot satisfy is refused BEFORE any ledger write', () => {
  const ledger = tmpLedger();
  const otherGrantee = { ...grant, signer: Keypair.generate().publicKey.toBase58() };
  const verdict = signApproved({ wire: wireFor(), grant: otherGrantee, ledger, keypair: signer, now });
  assert.deepEqual(verdict, { allowed: false, refused: 'signer_key_mismatch' });
  assert.equal(ledger.snapshot().records, 0);
  assert.equal(fs.existsSync(ledger.file), false, 'no journal file may be created');
});

test('an absent keypair is refused before the ledger too', () => {
  const ledger = tmpLedger();
  const verdict = signApproved({ wire: wireFor(), grant, ledger, keypair: null, now });
  assert.equal(verdict.refused, 'signer_unavailable');
  assert.equal(ledger.snapshot().records, 0);
});

test('replay is refused by the ledger even when the daemon key could sign it', () => {
  const ledger = tmpLedger();
  const input = wireFor();
  assert.equal(signApproved({ wire: input, grant, ledger, keypair: signer, now }).allowed, true);
  const again = signApproved({ wire: input, grant, ledger, keypair: signer, now });
  assert.equal(again.allowed, false);
  assert.equal(again.refused, 'replay');
  assert.equal(again.signed, undefined);
});

test('the window cap stops signing after the budget is gone', () => {
  const ledger = tmpLedger();
  const tight = { ...grant, windowMaxLamports: '10084' }; // two approvals of 5042 fit
  const results = [];
  for (let i = 0; i < 5; i += 1) {
    // Distinct blockhashes -> distinct wires, so only the window can stop them.
    results.push(signApproved({ wire: wireFor(42), grant: tight, ledger, keypair: signer, now }));
  }
  const allowed = results.filter((r) => r.allowed);
  assert.equal(allowed.length, 2, 'exactly two approvals fit in 10084');
  const refused = results.filter((r) => !r.allowed);
  assert.equal(refused.length, 3);
  for (const r of refused) assert.equal(r.refused, 'window_cap');
  assert.equal(refused[0].windowRemainingLamports, '0');
  assert.equal(ledger.snapshot().records, 2);
});

test('sign failures after approval consume budget instead of signing (fail closed)', () => {
  const ledger = tmpLedger();
  // A keypair object that claims the grant's public key but carries a
  // different secret: signing produces a signature that cannot verify.
  const impostorSecret = Keypair.generate();
  const impostor = { publicKey: signer.publicKey, secretKey: impostorSecret.secretKey };
  const wire = wireFor();
  const verdict = signApproved({ wire, grant, ledger, keypair: impostor, now });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.refused, 'sign_verify_failed');
  assert.equal(verdict.budget, 'consumed');
  assert.equal(verdict.signed, undefined);
  assert.deepEqual(ledger.snapshot(), { records: 1, seq: 1, fingerprints: 1 },
    'the approval is durably recorded; budget burned, nothing signed');
  // The SAME wire can never be signed later, even with the correct key: it is
  // already in the replay set.
  const retry = signApproved({ wire, grant, ledger, keypair: signer, now });
  assert.equal(retry.allowed, false);
  assert.equal(retry.refused, 'replay');
  assert.equal(retry.signed, undefined);
});

test('a non-plain-object grant is refused without a ledger write', () => {
  const ledger = tmpLedger();
  const verdict = signApproved({ wire: wireFor(), grant: null, ledger, keypair: signer, now });
  assert.equal(verdict.refused, 'invalid_grant');
  assert.equal(ledger.snapshot().records, 0);
});
