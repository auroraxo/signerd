// Tests for tools/measure-wire-submission.mjs — the instrument that asks a
// REAL Solana runtime whether it ACCEPTS the product's signed wire (with a
// funded fee payer) and moves the lamports, instead of only simulating it.
//
// WHY this exists: the sibling instrument measure-wire-validity.mjs earns
// "wire-valid-modulo-balance" from simulateTransaction on MAINNET and names
// its own limit: the funded fee-payer case is never exercised, because the
// fixture key holds 0 lamports. Simulation is not acceptance. This instrument
// closes that limit against a LOCAL solana-test-validator (agave 4.3.2) —
// the same runtime code, a fresh local ledger, mainnet never contacted.
//
// Ladder (measured, not asserted):
//   pre-fix tree d2d2b5e: the file does not exist -> ERR_MODULE_NOT_FOUND,
//                     0/N (the instrument IS the fix)
//   this tree:           all green
//
// The directions that must not be skipped:
//   * a runtime that ACCEPTS what it had to reject must never yield a pass
//     (T7 pins that: it is the "the oracle is broken" direction)
//   * the local-only guard must refuse a mainnet endpoint (T8) — the
//     instrument has no way to submit off-machine
//   * an RPC error must be no-verdict, never "accepted" (T9)
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  isLocalEndpoint,
  classifyRefusal,
  classifyPlaceholderRejection,
  classifyCorruptedRejection,
  classifyUnfundedRejection,
  classifyFundedAcceptance,
  corruptSignatureByte,
  derive,
} from '../tools/measure-wire-submission.mjs';

// The refusal shapes are COPIED from the live local run 2026-11-05 (agave
// 4.3.2 validator) — measured, not invented:
//   blockhash  "Transaction simulation failed: Blockhash not found" / err
//              "BlockhashNotFound"
//   signature "Transaction simulation failed: Transaction did not pass
//              signature verification" / err "SignatureFailure"
//   balance   "Transaction simulation failed: Attempt to debit an account
//              but found no record of a prior credit." / err
//              "AccountNotFound"
const BLOCKHASH_REFUSED = {
  accepted: false,
  refusedMessage: 'Transaction simulation failed: Blockhash not found',
  refusedErr: 'BlockhashNotFound',
  refusedCode: -32002,
};
const SIGNATURE_REFUSED = {
  accepted: false,
  refusedMessage: 'Transaction simulation failed: Transaction did not pass signature verification',
  refusedErr: 'SignatureFailure',
  refusedCode: -32002,
};
const BALANCE_REFUSED = {
  accepted: false,
  refusedMessage: 'Transaction simulation failed: Attempt to debit an account but found no record of a prior credit.',
  refusedErr: 'AccountNotFound',
  refusedCode: -32002,
};

const FUNDED_ACCEPTED = {
  accepted: true,
  signature: 'measured-signature',
  slot: 745,
  confirmationStatus: 'confirmed',
  payerDelta: -5042,
  destDelta: 42,
};
const FUNDED_WRONG_DELTA = { ...FUNDED_ACCEPTED, payerDelta: -42, destDelta: 42 };

test('T1 C1: the placeholder wire must be rejected for its blockhash', () => {
  assert.equal(classifyPlaceholderRejection(BLOCKHASH_REFUSED).ok, true);
  assert.equal(classifyPlaceholderRejection(BLOCKHASH_REFUSED).observed, 'blockhash');
  // A runtime that ACCEPTS the placeholder wire cannot judge a wire:
  assert.equal(classifyPlaceholderRejection(FUNDED_ACCEPTED).ok, false);
  // A refusal for another reason is not the blockhash control:
  assert.equal(classifyPlaceholderRejection(BALANCE_REFUSED).ok, false);
  assert.equal(classifyPlaceholderRejection(SIGNATURE_REFUSED).ok, false);
});

test('T2 C2: a corrupted signature must be rejected AND detected as such', () => {
  assert.equal(classifyCorruptedRejection(SIGNATURE_REFUSED).ok, true);
  assert.equal(classifyCorruptedRejection(SIGNATURE_REFUSED).observed, 'signature');
  // The control that makes C4 meaningful: accepting the corrupted wire
  // means the runtime cannot discriminate.
  assert.equal(classifyCorruptedRejection(FUNDED_ACCEPTED).ok, false);
  assert.equal(classifyCorruptedRejection(BLOCKHASH_REFUSED).ok, false);
});

test('T3 C3: the unfunded fee payer must be rejected for its balance', () => {
  assert.equal(classifyUnfundedRejection(BALANCE_REFUSED).ok, true);
  assert.equal(classifyUnfundedRejection(BALANCE_REFUSED).observed, 'balance');
  assert.equal(classifyUnfundedRejection(FUNDED_ACCEPTED).ok, false);
  assert.equal(classifyUnfundedRejection(BLOCKHASH_REFUSED).ok, false);
});

test('T4 C4: the funded wire must be accepted AND move exactly the documented amounts', () => {
  const ok = classifyFundedAcceptance(FUNDED_ACCEPTED);
  assert.equal(ok.ok, true);
  // The delta is measured, not assumed: 42 lamports + the 5000 lamport fee.
  assert.equal(ok.observed, 'payerDelta=-5042,destDelta=42');
  // A wire that landed but moved the wrong amounts is NOT a pass:
  assert.equal(classifyFundedAcceptance(FUNDED_WRONG_DELTA).ok, false);
  // A refusal where acceptance was required is a defect, not a pass:
  assert.equal(classifyFundedAcceptance(BLOCKHASH_REFUSED).ok, false);
  // An unmeasured outcome is never a pass:
  assert.equal(classifyFundedAcceptance({ unmeasured: true, reason: 'rpc down' }).ok, false);
});

test('T5 the refusal classifier knows the three MEASURED classes and nothing else', () => {
  assert.equal(classifyRefusal('Blockhash not found'), 'blockhash');
  assert.equal(classifyRefusal('"BlockhashNotFound"'), 'blockhash');
  assert.equal(classifyRefusal('Transaction did not pass signature verification'), 'signature');
  assert.equal(classifyRefusal('"SignatureFailure"'), 'signature');
  assert.equal(classifyRefusal('found no record of a prior credit'), 'balance');
  assert.equal(classifyRefusal('"AccountNotFound"'), 'balance');
  // An unknown refusal is "other", never silently one of the three:
  assert.equal(classifyRefusal('something else entirely'), 'other');
  assert.equal(classifyRefusal(''), 'none');
});

test('T6 the verdict needs ALL FOUR controls', () => {
  const good = derive({
    placeholder: BLOCKHASH_REFUSED,
    corrupted: SIGNATURE_REFUSED,
    unfunded: BALANCE_REFUSED,
    funded: FUNDED_ACCEPTED,
  });
  assert.equal(good.verdict, 'wire-accepted-by-real-runtime');
  assert.deepEqual(good.defects, []);

  // One broken control => the wire is defective, and the defect is NAMED:
  const broken = derive({
    placeholder: BLOCKHASH_REFUSED,
    corrupted: SIGNATURE_REFUSED,
    unfunded: BALANCE_REFUSED,
    funded: { accepted: false, refusedMessage: 'Transaction simulation failed: Blockhash not found', refusedErr: 'BlockhashNotFound' },
  });
  assert.equal(broken.verdict, 'wire-defective');
  assert.equal(broken.defects.length, 1);
  assert.match(broken.defects[0], /funded wire was not accepted/);
});

test('T7 a runtime that accepts what it had to reject yields NO VERDICT, never a pass', () => {
  // This is the "the oracle is broken" direction: if every control accepts,
  // the runtime cannot discriminate, so it cannot judge the wire.
  const blind = derive({
    placeholder: FUNDED_ACCEPTED,
    corrupted: FUNDED_ACCEPTED,
    unfunded: FUNDED_ACCEPTED,
    funded: FUNDED_ACCEPTED,
  });
  assert.equal(blind.verdict, 'no-verdict');
  assert.match(blind.reason, /cannot discriminate/);
});

test('T8 an unmeasured step yields NO VERDICT, never a pass', () => {
  const down = derive({
    placeholder: { unmeasured: true, reason: 'rpc down' },
    corrupted: SIGNATURE_REFUSED,
    unfunded: BALANCE_REFUSED,
    funded: FUNDED_ACCEPTED,
  });
  assert.equal(down.verdict, 'no-verdict');
  assert.match(down.reason, /rpc down/);

  const missing = derive({ placeholder: null, corrupted: null, unfunded: null, funded: null });
  assert.equal(missing.verdict, 'no-verdict');
});

test('T9 the local-only guard refuses every non-loopback endpoint', () => {
  // The instrument has NO way to submit off-machine: the guard is the
  // absence of a way to.
  assert.equal(isLocalEndpoint('http://127.0.0.1:8999').local, true);
  assert.equal(isLocalEndpoint('http://localhost:8999').local, true);
  assert.equal(isLocalEndpoint('http://127.0.0.5:8999').local, true);
  // mainnet, devnet and anything public must be refused:
  assert.equal(isLocalEndpoint('https://api.mainnet-beta.solana.com').local, false);
  assert.equal(isLocalEndpoint('https://api.devnet.solana.com').local, false);
  assert.equal(isLocalEndpoint('http://example.com:8999').local, false);
  // A hostname that merely CONTAINS a loopback address is not loopback:
  assert.equal(isLocalEndpoint('http://127.0.0.1.example.com:8999').local, false);
  // And a non-HTTP scheme is refused rather than reinterpreted:
  assert.equal(isLocalEndpoint('file:///tmp/socket').local, false);
  assert.equal(isLocalEndpoint('not a url').local, false);
});

test('T10 the corruption flips a byte INSIDE the signature slot, not the message', () => {
  const wire = Buffer.alloc(215, 0);
  const bad = corruptSignatureByte(wire);
  // byte 0 is the signature count and must not change; the flipped byte
  // must be inside the 64-byte signature slot (offsets 1..64).
  assert.equal(bad[0], wire[0]);
  assert.notEqual(bad[7], wire[7]);
  assert.equal(bad[7], wire[7] ^ 0xff);
  // Everything after the signature slot (the message) stays untouched —
  // otherwise the control would test the message, not the signature.
  assert.deepEqual(bad.subarray(65), wire.subarray(65));
});
