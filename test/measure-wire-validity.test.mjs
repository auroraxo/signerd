// Tests for tools/measure-wire-validity.mjs — the instrument that asks
// Solana mainnet itself whether the signed wire is valid, WITHOUT
// submitting anything.
//
// Ladder (measured, not asserted):
//   pre-fix tree 9ac0377: the file does not exist -> ERR_MODULE_NOT_FOUND,
//                     0/N (the instrument IS the fix)
//   this tree:           all green
//
// The R4 direction is the one that cannot be skipped: an oracle that
// reports "clean" for a CORRUPTED signature must never produce a passing
// verdict — otherwise a broken oracle would pass R3 by reporting everything
// as valid. T7 pins that failure direction explicitly.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyPlaceholder,
  classifyFresh,
  classifyCorrupted,
  derive,
} from '../tools/measure-wire-validity.mjs';

// Fixture shapes copied from the LIVE run 2026-11-05 (apiVersion 4.4.0),
// research/wire-validity-2026-11-05.json — these enums are measured, not
// invented: "BlockhashNotFound", "SignatureFailure", "AccountNotFound".
const OK = { err: null, logs: [] };
const BLOCKHASH = { err: 'BlockhashNotFound', logs: [] };
const SIG_FAILURE = { err: 'SignatureFailure', logs: [] };
const ACCOUNT = { err: 'AccountNotFound', logs: [] };
const FEE_EXEC = { err: { InstructionError: [2, { Custom: 1 }] }, logs: [] };
const OTHER_INSTR = { err: { InstructionError: [0, { Custom: 42 }] }, logs: [] };
const NET_DOWN = { networkError: 'fetch failed' };
const HTTP_429 = { httpError: 429 };

test('T1 R2: the placeholder wire fails on mainnet for exactly one reason — the blockhash', () => {
  assert.equal(classifyPlaceholder(BLOCKHASH).ok, true);
  assert.equal(classifyPlaceholder(BLOCKHASH).observed, 'blockhash-not-found');
  // Anything else on the placeholder wire is a product defect, not a pass:
  assert.equal(classifyPlaceholder(SIG_FAILURE).ok, false);
  assert.equal(classifyPlaceholder(ACCOUNT).ok, false);
  assert.equal(classifyPlaceholder(OK).ok, false, 'placeholder wire cannot be clean on-chain');
});

test('T2 R3: the fresh wire may fail only on the unfunded fee payer', () => {
  assert.equal(classifyFresh(ACCOUNT).ok, true, 'AccountNotFound = unfunded fee payer, pre-execution');
  assert.equal(classifyFresh(FEE_EXEC).ok, true, 'system error 1 at execution = same case, funded-but-empty');
  assert.equal(classifyFresh(OK).ok, true, 'fully clean is also valid (fixture drift, still valid)');
  // The failure classes that MUST be defects:
  assert.equal(classifyFresh(BLOCKHASH).ok, false, 'a fresh blockhash that mainnet rejects is a wire defect');
  assert.equal(classifyFresh(SIG_FAILURE).ok, false, 'our own signature failing is a wire defect');
  assert.equal(classifyFresh(OTHER_INSTR).ok, false, 'any other instruction error is not the balance case');
});

test('T3 R4: a corrupted signature must be DETECTED, never reported clean', () => {
  assert.equal(classifyCorrupted(SIG_FAILURE).ok, true);
  // This is the control that makes R3 meaningful: an oracle that cannot
  // tell a good signature from a broken one reports clean here, and that
  // must NOT satisfy the rule.
  assert.equal(classifyCorrupted(OK).ok, false, 'clean on a corrupted wire = the oracle is broken');
  assert.equal(classifyCorrupted(BLOCKHASH).ok, false);
});

test('T4 derive: all three rules hold -> wire-valid-modulo-balance', () => {
  const d = derive({ placeholderSim: BLOCKHASH, freshSim: ACCOUNT, corruptedSim: SIG_FAILURE });
  assert.equal(d.verdict, 'wire-valid-modulo-balance');
  assert.equal(d.defects.length, 0);
  assert.equal(d.checks.length, 3);
  assert.ok(d.checks.every((c) => c.ok === true));
});

test('T5 derive: a fresh-wire failure that is not the balance case -> wire-defective', () => {
  const d = derive({ placeholderSim: BLOCKHASH, freshSim: SIG_FAILURE, corruptedSim: SIG_FAILURE });
  assert.equal(d.verdict, 'wire-defective');
  assert.ok(d.defects.some((x) => /not valid to mainnet/.test(x)), d.defects.join('; '));
});

test('T6 derive: a placeholder failure that is not the blockhash class -> wire-defective', () => {
  const d = derive({ placeholderSim: OK, freshSim: ACCOUNT, corruptedSim: SIG_FAILURE });
  assert.equal(d.verdict, 'wire-defective');
  assert.ok(d.defects.some((x) => /placeholder/.test(x)), d.defects.join('; '));
});

test('T7 derive: an oracle that reports clean on the corrupted wire -> no-verdict, never a pass', () => {
  const d = derive({ placeholderSim: BLOCKHASH, freshSim: ACCOUNT, corruptedSim: OK });
  assert.equal(d.verdict, 'no-verdict', 'a broken oracle must not yield a passing verdict');
  assert.ok(d.defects.some((x) => /oracle cannot detect/.test(x)), d.defects.join('; '));
});

test('T8 derive: any unmeasured simulation -> no-verdict with a reason, never a pass', () => {
  for (const broken of [NET_DOWN, HTTP_429, { rpcError: 'rate limited' }, { parseError: 'bad json' }, null]) {
    const d = derive({ placeholderSim: broken, freshSim: ACCOUNT, corruptedSim: SIG_FAILURE });
    assert.equal(d.verdict, 'no-verdict', JSON.stringify(broken));
    assert.ok(typeof d.reason === 'string' && d.reason.length > 0, 'no-verdict must carry a reason');
  }
  const freshDown = derive({ placeholderSim: BLOCKHASH, freshSim: NET_DOWN, corruptedSim: SIG_FAILURE });
  assert.equal(freshDown.verdict, 'no-verdict');
  const corruptDown = derive({ placeholderSim: BLOCKHASH, freshSim: ACCOUNT, corruptedSim: HTTP_429 });
  assert.equal(corruptDown.verdict, 'no-verdict');
});
