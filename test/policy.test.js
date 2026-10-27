'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  AddressLookupTableAccount, ComputeBudgetProgram, Keypair, PublicKey,
  SystemProgram, Transaction, TransactionInstruction, TransactionMessage,
  VersionedTransaction,
} = require('@solana/web3.js');
const { evaluate } = require('../src/policy');

const signer = Keypair.generate();
const otherSigner = Keypair.generate();
const recipient = Keypair.generate().publicKey;
const attacker = Keypair.generate().publicKey;
const blockhash = Keypair.generate().publicKey.toBase58();
const now = new Date('2026-10-27T10:00:00.000Z');
const grant = {
  signer: signer.publicKey.toBase58(), destination: recipient.toBase58(),
  maxLamports: '42', expiresAt: '2026-10-28T10:00:00Z',
};
function transfer(to = recipient, lamports = 42, from = signer.publicKey) {
  return SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports });
}
function legacy(...instructions) {
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = blockhash;
  for (const ix of instructions) tx.add(ix);
  // These are disposable test keys; policy does not trust or verify signatures.
  tx.sign(signer);
  return tx.serialize();
}
function verdict(raw, g = grant) { return evaluate(raw, g, now); }
function deny(raw, reason, g = grant) { assert.deepEqual(verdict(raw, g), { allowed: false, refused: reason }); }

test('the exact single legacy System transfer is allowed at the inclusive cap', () => {
  assert.deepEqual(verdict(legacy(transfer())), { allowed: true, amountLamports: '42' });
});
test('amount, recipient, fee payer and signer constraints', () => {
  deny(legacy(transfer(recipient, 43)), 'amount');
  deny(legacy(transfer(attacker)), 'destination');
  deny(legacy(transfer()), 'signer_or_fee_payer', { ...grant, signer: otherSigner.publicKey.toBase58() });
  deny(legacy(transfer()), 'destination', { ...grant, destination: attacker.toBase58() });
});
test('time and grant fail closed', () => {
  deny(legacy(transfer()), 'expired', { ...grant, expiresAt: now.toISOString() });
  deny(legacy(transfer()), 'invalid_grant', { ...grant, maxLamports: 42 });
  deny(legacy(transfer()), 'invalid_grant', { ...grant, maxLamports: '-1' });
  deny(legacy(transfer()), 'invalid_grant', { ...grant, maxLamports: '18446744073709551616' });
  deny(legacy(transfer()), 'invalid_grant', { ...grant, destination: 'not a public key' });
  deny(legacy(transfer()), 'invalid_grant', { ...grant, expiresAt: '2026-02-30T10:00:00Z' });
  assert.deepEqual(verdict(legacy(transfer()), { ...grant, expiresAt: '2026-10-28T10:00:00.000Z' }),
    { allowed: true, amountLamports: '42' });
  assert.deepEqual(evaluate(legacy(transfer()), grant, new Date(NaN)), { allowed: false, refused: 'invalid_clock' });
});
test('no second instruction, including a small transfer, price-fee drain, or Memo', () => {
  deny(legacy(transfer(), transfer(recipient, 1)), 'envelope');
  deny(legacy(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000_000 }), transfer()), 'envelope');
  deny(legacy(new TransactionInstruction({ programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'), keys: [], data: Buffer.from('hi') }), transfer()), 'envelope');
});
test('authority modification, Token-2022, arbitrary CPI-capable program are refused', () => {
  const token = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
  const token2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
  const whirlpool = new PublicKey('whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc');
  for (const programId of [token, token2022, whirlpool]) {
    const ix = new TransactionInstruction({ programId, keys: [
      { pubkey: signer.publicKey, isSigner: true, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
    ], data: Buffer.from([6, 1]) });
    deny(legacy(ix), 'program');
  }
});
test('System non-transfer instructions and tampered account order refused', () => {
  deny(legacy(SystemProgram.allocate({ accountPubkey: signer.publicKey, space: 0 })), 'envelope');
  const tx = new VersionedTransaction( new TransactionMessage({
    payerKey: signer.publicKey, recentBlockhash: blockhash,
    instructions: [transfer()],
  }).compileToLegacyMessage());
  tx.message.instructions[0].accounts.reverse();
  deny(tx.serialize(), 'instruction_accounts');
});
test('all versioned messages are refused, with or without ALT lookups', () => {
  const msg = new TransactionMessage({ payerKey: signer.publicKey, recentBlockhash: blockhash, instructions: [transfer()] });
  const noAlt = new VersionedTransaction(msg.compileToV0Message());
  deny(noAlt.serialize(), 'version_or_alt');
  const table = new AddressLookupTableAccount({
    key: Keypair.generate().publicKey,
    state: { deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, authority: signer.publicKey, addresses: [recipient] },
  });
  const withAlt = new VersionedTransaction(msg.compileToV0Message([table]));
  assert.equal(withAlt.message.addressTableLookups.length, 1);
  deny(withAlt.serialize(), 'version_or_alt');
});
test('invalid, trailing, and oversized wire formats are refused', () => {
  const raw = legacy(transfer());
  deny(Buffer.from([1, 2, 3]), 'invalid_wire');
  deny(Buffer.concat([raw, Buffer.from([0])]), 'noncanonical_wire');
  deny(Buffer.alloc(1233), 'invalid_wire');
  assert.deepEqual(verdict('not bytes'), { allowed: false, refused: 'invalid_wire' });
});
