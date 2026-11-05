// Submit the SIGNED wire to a REAL Solana runtime, with a funded fee payer.
//
// WHY (measured 2026-11-05): tools/measure-wire-validity.mjs asks mainnet
// whether the signed wire is valid, via simulateTransaction, WITHOUT
// submitting. It earned the verdict "wire-valid-modulo-balance" — and it
// named its own limit: "the funded fee-payer case itself is NOT exercised —
// by construction the fixture key holds 0 lamports". A stranger who follows
// the README with a funded payer gets one surface nobody had measured: does
// the runtime actually ACCEPT the wire and MOVE the lamports? Simulation is
// not acceptance.
//
// HOW, WITHOUT TOUCHING MAINNET: a local solana-test-validator (agave
// 4.3.2, feature-set 3383571666) IS a Solana runtime — the same bankless
// runtime code that runs mainnet, on a fresh local ledger. The instrument
// funds the fee payer from the validator's own genesis faucet, signs the
// documented quickstart wire with the product's own daemon, SUBMITS it, and
// measures the ledger delta. Nothing leaves the machine; the lamports are
// local test SOL.
//
// SAFETY (non-negotiable, checked before anything else): the RPC endpoint
// MUST be a loopback address. A non-local endpoint is refused with exit 3
// and verdict "refused-not-local-runtime". There is no flag that submits to
// mainnet — the guard is the absence of a way to.
//
// CONTROLS (each one can only fail the verdict):
//   C1 placeholder wire -> the runtime must REJECT it (blockhash class).
//      If the runtime accepted it, the blockhash was never checked.
//   C2 corrupted signature byte on the same funded wire -> the runtime must
//      REJECT it (signature class). Without this control a runtime that
//      accepted everything would pass C4.
//   C3 UNFUNDED fee payer -> the runtime must REJECT it (balance class).
//      This is the case the old instrument could not reach, and it proves
//      the funded case in C4 differs because of the BALANCE, not by luck.
//   C4 FUNDED fee payer -> the runtime must ACCEPT the wire: the
//      transaction lands, err is null, and the ledger delta is EXACTLY
//      -(+lamports + 5000 fee) on the payer and +lamports on the
//      destination.
//
// FALSIFICATION RULES:
//   * Any RPC error, missing field, or unmeasurable step => NO VERDICT
//     (exit 3), never "accepted".
//   * A refusal where acceptance was required => "wire-defective" (exit 1).
//   * Acceptance where refusal was required => the control failed; the
//     verdict is "no-verdict" (exit 3), because a runtime that accepts
//     everything cannot be used to judge a wire.
//
// Usage: node tools/measure-wire-submission.mjs [--rpc http://127.0.0.1:8999] [--out file]
//   Exit 0 = measured and accepted, 1 = defective, 3 = no verdict.
'use strict';

import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

// The documented quickstart's destination. On mainnet this is the wrapped-SOL
// mint; on a fresh local ledger it does not exist until the fixture creates
// it, which is why the fixture funds it too.
const DOCUMENTED_DESTINATION = 'So11111111111111111111111111111111111111112';
const TRANSFER_LAMPORTS = 42;
const EXPECTED_FEE_LAMPORTS = 5000;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0:0:0:0:0:0:0:1']);

// ---------------------------------------------------------------- guard

// The one rule that makes this instrument safe to run unattended: the
// endpoint must be a loopback address. Anything else is refused BEFORE any
// key, wire or transaction exists.
export function isLocalEndpoint(rpcUrl) {
  let url;
  try {
    url = new URL(rpcUrl);
  } catch {
    return { local: false, reason: 'unparseable-endpoint' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { local: false, reason: 'unsupported-protocol' };
  }
  const host = url.hostname.toLowerCase();
  if (!LOOPBACK_HOSTS.has(host) && !/^127\.\d+\.\d+\.\d+$/.test(host)) {
    return { local: false, reason: `not-a-loopback-host:${host}` };
  }
  return { local: true, host };
}

// ---------------------------------------------------------------- RPC layer

let rpcSeq = 0;

export async function rawRpc(rpcUrl, method, params) {
  let res;
  try {
    res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcSeq, method, params }),
    });
  } catch (err) {
    return { networkError: String(err && err.message ? err.message : err) };
  }
  if (res.status === 429 || res.status === 503 || res.status >= 500) {
    return { httpError: res.status };
  }
  if (res.status !== 200) return { httpError: res.status };
  let json;
  try { json = await res.json(); } catch (err) {
    return { parseError: String(err && err.message ? err.message : err) };
  }
  if (json.error) return { rpcError: json.error };
  return json;
}

// The refusal text the runtime produced, from BOTH places it lives: the
// error message and the structured data.err. Measured local classes are
// named here because they were OBSERVED, not assumed.
export function refusalText(outcome) {
  if (!outcome) return '';
  // A refusal is whatever the runtime reported: either field can carry it.
  // (Guarding on a separate `refused` flag was a bug: the outcomes below
  // carry the refusal in these two fields, so the flag never existed and
  // every refusal classified as "none".)
  if (!outcome.refusedMessage && !outcome.refusedErr) return '';
  const parts = [];
  if (outcome.refusedMessage) parts.push(String(outcome.refusedMessage));
  if (outcome.refusedErr) parts.push(JSON.stringify(outcome.refusedErr));
  return parts.join(' | ');
}

// The runtime's own refusal classes, as MEASURED on a local agave 4.3.2
// validator (2026-11-05):
//   blockhash  "BlockhashNotFound" / "Blockhash not found"
//   signature "Transaction did not pass signature verification" /
//              "SignatureFailure"
//   balance   "Attempt to debit an account but found no record of a prior
//              credit" / insufficient funds
export function classifyRefusal(text) {
  const t = String(text || '');
  if (!t) return 'none';
  if (/BlockhashNotFound|blockhash not found/i.test(t)) return 'blockhash';
  if (/did not pass signature verification|SignatureFailure/i.test(t)) return 'signature';
  // "AccountNotFound" is the err the LOCAL runtime returned for the
  // unfunded fee payer (the message is the longer "Attempt to debit an
  // account..." text); both strings name the same measured class, and the
  // sibling mainnet instrument classifies AccountNotFound the same way.
  if (/no record of a prior credit|InsufficientFunds|insufficient funds|AccountNotFound/i.test(t)) return 'balance';
  return 'other';
}

// ---------------------------------------------------------------- pure rules

// C1: the placeholder wire must be REJECTED, and only for the blockhash.
export function classifyPlaceholderRejection(outcome) {
  const cls = classifyRefusal(refusalText(outcome));
  const ok = cls === 'blockhash';
  return {
    ok,
    observed: cls,
    rule: 'placeholder-wire-must-be-rejected-for-blockhash',
    note: ok
      ? 'the runtime rejected the placeholder wire for its blockhash'
      : `the runtime did not reject the placeholder wire for its blockhash (${cls})`,
  };
}

// C2: a corrupted signature must be REJECTED, and detected as such. This is
// the control that makes C4 mean anything.
export function classifyCorruptedRejection(outcome) {
  const cls = classifyRefusal(refusalText(outcome));
  const ok = cls === 'signature';
  return {
    ok,
    observed: cls,
    rule: 'corrupted-signature-must-be-rejected-and-detected',
    note: ok
      ? 'the runtime rejected the corrupted wire as a signature failure'
      : `the runtime did not detect the corrupted signature (${cls})`,
  };
}

// C3: the UNFUNDED fee payer must be REJECTED for the balance. This is the
// case the simulation-only instrument could not reach.
export function classifyUnfundedRejection(outcome) {
  const cls = classifyRefusal(refusalText(outcome));
  const ok = cls === 'balance';
  return {
    ok,
    observed: cls,
    rule: 'unfunded-fee-payer-must-be-rejected-for-balance',
    note: ok
      ? 'the runtime rejected the unfunded fee payer for its balance'
      : `the runtime did not reject the unfunded fee payer for its balance (${cls})`,
  };
}

// C4: the FUNDED wire must be ACCEPTED and the ledger delta must be exact.
export function classifyFundedAcceptance(outcome) {
  if (!outcome || outcome.unmeasured) {
    return { ok: false, observed: 'unmeasured', rule: 'funded-wire-must-be-accepted' };
  }
  if (!outcome.accepted) {
    return {
      ok: false,
      observed: outcome.accepted ? 'accepted' : `rejected:${classifyRefusal(refusalText(outcome))}`,
      rule: 'funded-wire-must-be-accepted',
      note: 'the runtime refused a funded, validly signed wire',
    };
  }
  const expectedPayer = -(TRANSFER_LAMPORTS + EXPECTED_FEE_LAMPORTS);
  const payerOk = outcome.payerDelta === expectedPayer;
  const destOk = outcome.destDelta === TRANSFER_LAMPORTS;
  const ok = payerOk && destOk;
  return {
    ok,
    observed: `payerDelta=${outcome.payerDelta},destDelta=${outcome.destDelta}`,
    rule: 'funded-wire-must-be-accepted-and-move-exactly-the-documented-amounts',
    note: ok
      ? `the runtime accepted the wire and moved exactly ${TRANSFER_LAMPORTS} lamports plus the ${EXPECTED_FEE_LAMPORTS} lamport fee`
      : `the wire landed but the ledger delta is wrong (expected payer ${expectedPayer}, dest ${TRANSFER_LAMPORTS})`,
  };
}

// The verdict. Every control must hold; a control that fails in the
// dangerous direction yields no-verdict, a product failure yields
// wire-defective.
export function derive({ placeholder, corrupted, unfunded, funded }) {
  const checks = [];
  const defects = [];

  for (const [name, outcome] of [['placeholder', placeholder], ['corrupted', corrupted], ['unfunded', unfunded], ['funded', funded]]) {
    if (!outcome || outcome.unmeasured) {
      const reason = outcome && outcome.reason ? `${name}: ${outcome.reason}` : `${name}: missing`;
      return { verdict: 'no-verdict', reason, defects, checks };
    }
  }

  const c1 = classifyPlaceholderRejection(placeholder);
  checks.push(c1);
  if (!c1.ok) defects.push(`placeholder wire was not rejected for its blockhash (${c1.observed})`);

  const c2 = classifyCorruptedRejection(corrupted);
  checks.push(c2);
  if (!c2.ok) defects.push(`corrupted signature was not detected (${c2.observed})`);

  const c3 = classifyUnfundedRejection(unfunded);
  checks.push(c3);
  if (!c3.ok) defects.push(`unfunded fee payer was not rejected for its balance (${c3.observed})`);

  const c4 = classifyFundedAcceptance(funded);
  checks.push(c4);
  if (!c4.ok) defects.push(`funded wire was not accepted with the exact ledger delta (${c4.observed})`);

  // A control that ACCEPTED what it had to reject means the runtime cannot
  // discriminate — no verdict, never a pass.
  const discriminatorFailed = (outcome, want) => {
    const cls = classifyRefusal(refusalText(outcome));
    return cls === 'none' && outcome.accepted;
  };
  if (discriminatorFailed(placeholder) || discriminatorFailed(corrupted) || discriminatorFailed(unfunded)) {
    return { verdict: 'no-verdict', reason: 'the runtime accepted a wire it had to reject — it cannot discriminate, so it cannot judge', defects, checks };
  }

  const verdict = defects.length === 0 ? 'wire-accepted-by-real-runtime' : 'wire-defective';
  return { verdict, defects, checks };
}

// ---------------------------------------------------------------- fixture

function keygenFixture(root, passphraseFile) {
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const keystore = path.join(cfg, 'ops.key');
  const keygen = spawnSync(process.execPath, [CLI, 'keygen',
    '--keystore', keystore,
    '--passphrase-file', passphraseFile], { encoding: 'utf8' });
  if (keygen.status !== 0) return { keygenError: `${keygen.stdout} ${keygen.stderr}` };
  let parsed;
  try { parsed = JSON.parse(keygen.stdout.trim().split('\n').pop()); } catch {
    return { keygenParseError: keygen.stdout };
  }
  return { keystore, fromPubkey: parsed.publicKey };
}

// One flipped byte inside the 64-byte signature slot (the slot starts at
// offset 1; byte 0 is the signature count).
export function corruptSignatureByte(wire) {
  const bad = Buffer.from(wire);
  bad[7] ^= 0xff;
  return bad;
}

async function fund(rpcUrl, pubkey, lamports) {
  const air = await rawRpc(rpcUrl, 'requestAirdrop', [pubkey, lamports]);
  if (air.rpcError) return { airdropError: JSON.stringify(air.rpcError).slice(0, 160) };
  const sig = air.result;
  for (let i = 0; i < 80; i++) {
    const st = await rawRpc(rpcUrl, 'getSignatureStatuses', [[sig]]);
    const s = st.result && st.result.value && st.result.value[0];
    if (s && s.confirmationStatus) {
      if (s.err) return { airdropError: `airdrop failed: ${JSON.stringify(s.err)}` };
      return { sig };
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return { airdropError: 'airdrop did not confirm in time' };
}

async function balanceOf(rpcUrl, pubkey) {
  const res = await rawRpc(rpcUrl, 'getBalance', [pubkey, { commitment: 'confirmed' }]);
  if (res.rpcError) return { balanceError: JSON.stringify(res.rpcError).slice(0, 160) };
  return { lamports: res.result.value };
}

async function latestBlockhash(rpcUrl) {
  const res = await rawRpc(rpcUrl, 'getLatestBlockhash', [{ commitment: 'confirmed' }]);
  if (res.rpcError) return { blockhashError: JSON.stringify(res.rpcError).slice(0, 160) };
  const value = res.result && res.result.value;
  if (!value || !value.blockhash) return { blockhashError: 'no blockhash in result' };
  return { blockhash: value.blockhash, lastValidBlockHeight: value.lastValidBlockHeight };
}

// Submit a wire and report what the runtime did with it.
export async function submitWire(rpcUrl, wire) {
  const res = await rawRpc(rpcUrl, 'sendTransaction', [
    wire.toString('base64'),
    { encoding: 'base64', skipPreflight: false, preflightCommitment: 'confirmed' },
  ]);
  if (res.rpcError) {
    const err = res.rpcError;
    const data = err.data && typeof err.data === 'object' ? err.data : null;
    return {
      accepted: false,
      refusedMessage: err.message || JSON.stringify(err),
      refusedErr: data ? data.err : null,
      refusedCode: err.code,
    };
  }
  if (res.networkError || res.httpError || res.parseError) {
    return { unmeasured: true, reason: JSON.stringify(res).slice(0, 160) };
  }
  const sig = res.result;
  // Wait for the transaction to land and report its final status.
  let final = null;
  for (let i = 0; i < 120; i++) {
    const st = await rawRpc(rpcUrl, 'getSignatureStatuses', [[sig]]);
    const s = st.result && st.result.value && st.result.value[0];
    if (s && (s.err !== null || s.confirmationStatus)) { final = s; break; }
    if (st.rpcError) return { unmeasured: true, reason: 'getSignatureStatuses failed' };
    await new Promise((r) => setTimeout(r, 250));
  }
  if (!final) return { unmeasured: true, reason: 'transaction did not land in time', signature: sig };
  if (final.err) {
    return { accepted: false, refusedMessage: `transaction failed: ${JSON.stringify(final.err)}`, refusedErr: final.err, signature: sig };
  }
  return { accepted: true, signature: sig, slot: final.slot, confirmationStatus: final.confirmationStatus, fee: final.fee };
}

// ---------------------------------------------------------------- live path

async function main() {
  const rpcIdx = process.argv.indexOf('--rpc');
  const outIdx = process.argv.indexOf('--out');
  const rpcUrl = rpcIdx !== -1 ? process.argv[rpcIdx + 1] : (process.env.SOLANA_RPC || 'http://127.0.0.1:8999');
  const outFile = outIdx !== -1 ? process.argv[outIdx + 1] : null;

  const report = {
    tool: 'measure-wire-submission',
    rpc: rpcUrl,
    at: new Date().toISOString(),
    transferLamports: TRANSFER_LAMPORTS,
    expectedFeeLamports: EXPECTED_FEE_LAMPORTS,
  };

  const finish = (code) => {
    const text = JSON.stringify(report, null, 2);
    if (outFile) fs.writeFileSync(outFile, text);
    console.log(text);
    process.exit(code);
  };

  // The guard runs FIRST: nothing else happens on a non-local endpoint.
  const local = isLocalEndpoint(rpcUrl);
  report.localGuard = local;
  if (!local.local) {
    report.verdict = 'refused-not-local-runtime';
    report.reason = `refusing to submit to a non-loopback endpoint (${local.reason})`;
    return finish(3);
  }

  const health = await rawRpc(rpcUrl, 'getHealth', []);
  if (health.rpcError || health.networkError || health.httpError) {
    report.verdict = 'no-verdict';
    report.reason = `runtime not reachable: ${JSON.stringify(health).slice(0, 160)}`;
    return finish(3);
  }
  const version = await rawRpc(rpcUrl, 'getVersion', []);
  report.runtimeVersion = version.result || { error: JSON.stringify(version).slice(0, 120) };

  // Fresh passphrase file 0600 — the fixture IS a stranger run.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-wire-submission-'));
  const passphraseFile = path.join(root, 'pass');
  fs.writeFileSync(passphraseFile, 'wire-submission fixture\n', { mode: 0o600 });

  const f = keygenFixture(root, passphraseFile);
  if (f.keygenError || f.keygenParseError) {
    report.verdict = 'no-verdict';
    report.reason = f.keygenError || f.keygenParseError;
    return finish(3);
  }
  report.fromPubkey = f.fromPubkey;

  // Fund the fee payer (the keystore's public key) and the documented
  // destination, which does not exist on a fresh local ledger.
  const payerFund = await fund(rpcUrl, f.fromPubkey, 2_000_000_000);
  if (payerFund.airdropError) {
    report.verdict = 'no-verdict';
    report.reason = `fee payer funding failed: ${payerFund.airdropError}`;
    return finish(3);
  }
  const destFund = await fund(rpcUrl, DOCUMENTED_DESTINATION, 1_000_000_000);
  if (destFund.airdropError) {
    report.verdict = 'no-verdict';
    report.reason = `destination funding failed: ${destFund.airdropError}`;
    return finish(3);
  }
  report.fundedFeePayerLamports = (await balanceOf(rpcUrl, f.fromPubkey)).lamports;

  // The documented quickstart chain, CLI alone, up to the signature.
  const grants = path.join(root, 'grants.json');
  const add = spawnSync(process.execPath, [CLI, 'grant-add',
    '--grants', grants, '--name', 'ops-24h',
    '--keystore', f.keystore,
    '--destination', DOCUMENTED_DESTINATION,
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { encoding: 'utf8' });
  if (add.status !== 0) {
    report.verdict = 'no-verdict';
    report.reason = `grant-add failed: ${add.stdout} ${add.stderr}`;
    return finish(3);
  }

  const ledger = path.join(root, 'journal.jsonl');
  const socket = path.join(root, 'signerd.sock');
  const daemon = spawn(process.execPath, [CLI, 'run',
    '--keystore', f.keystore, '--passphrase-file', passphraseFile,
    '--grants', grants, '--ledger', ledger, '--socket', socket],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let daemonOut = '';
  daemon.stdout.on('data', (c) => { daemonOut += c; });
  daemon.stderr.on('data', (c) => { daemonOut += c; });
  const up = await new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      if (daemonOut.split('\n').find((l) => l.includes('"ok":true'))) return resolve(true);
      if (daemon.exitCode !== null) return resolve(false);
      if (Date.now() - started > 20000) return resolve(false);
      setTimeout(tick, 100);
    };
    tick();
  });
  if (!up) {
    report.verdict = 'no-verdict';
    report.reason = `daemon did not start: ${daemonOut.slice(0, 300)}`;
    try { daemon.kill('SIGKILL'); } catch { /* gone */ }
    return finish(3);
  }
  const stopDaemon = () => { try { if (daemon.exitCode === null) daemon.kill('SIGKILL'); } catch { /* gone */ } };

  // Build + sign through the product's own CLI, exactly as documented.
  const signOnce = (blockhash, label) => {
    const txPath = path.join(root, `tx-${label}.bin`);
    const build = spawnSync(process.execPath, [CLI, 'build-tx',
      '--keystore', f.keystore,
      '--to', DOCUMENTED_DESTINATION,
      '--lamports', String(TRANSFER_LAMPORTS), '--out', txPath,
      ...(blockhash ? ['--blockhash', blockhash] : [])], { encoding: 'utf8' });
    if (build.status !== 0) return { buildError: `${build.stdout} ${build.stderr}`.slice(0, 200) };
    const sign = spawnSync(process.execPath, [CLI, 'sign',
      '--socket', socket, '--grant', 'ops-24h', '--tx', txPath], { encoding: 'utf8' });
    let answer;
    try { answer = JSON.parse(sign.stdout.trim().split('\n').pop()); } catch {
      return { signParseError: (sign.stdout + sign.stderr).slice(0, 200) };
    }
    if (!answer.ok) return { refused: answer };
    return { signedWire: Buffer.from(answer.signed, 'base64'), seq: answer.seq };
  };

  // --- C1: the placeholder wire (quickstart verbatim, no blockhash) ----
  const placeholderSigned = signOnce('', 'placeholder');
  if (!placeholderSigned.signedWire) {
    report.verdict = 'no-verdict';
    report.reason = 'placeholder path failed: ' + JSON.stringify(placeholderSigned).slice(0, 200);
    stopDaemon();
    return finish(3);
  }
  report.signedWireBytes = placeholderSigned.signedWire.length;

  // Independent verification under OpenSSL, same oracle as the sibling
  // instrument: the daemon's signature must verify against the keystore's
  // public key before anything is submitted.
  {
    const { VersionedTransaction, PublicKey } = require('@solana/web3.js');
    const parsed = VersionedTransaction.deserialize(placeholderSigned.signedWire);
    const message = Buffer.from(parsed.message.serialize());
    const signature = Buffer.from(parsed.signatures[0]);
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(new PublicKey(f.fromPubkey).toBytes())]);
    const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    report.openSSLVerifies = crypto.verify(null, message, keyObject, signature);
    if (!report.openSSLVerifies) {
      report.verdict = 'wire-defective';
      report.defects = ['the daemon signature does not verify under OpenSSL ed25519'];
      stopDaemon();
      return finish(1);
    }
  }

  const placeholderOutcome = await submitWire(rpcUrl, placeholderSigned.signedWire);
  report.placeholder = placeholderOutcome;

  // --- C4: the funded wire, signed with a FRESH local blockhash --------
  let fundedOutcome = null;
  let attempts = 0;
  let blockhashUsed = null;
  let signed = null;
  // A stale blockhash is a local-timing artifact, not a product defect:
  // retry with a new blockhash (and therefore a new message the daemon has
  // not approved yet) up to three times, and report the attempt count.
  while (attempts < 3) {
    attempts += 1;
    const bh = await latestBlockhash(rpcUrl);
    if (bh.blockhashError) {
      fundedOutcome = { unmeasured: true, reason: bh.blockhashError };
      break;
    }
    blockhashUsed = bh.blockhash;
    const s = signOnce(bh.blockhash, `fresh-${attempts}`);
    if (!s.signedWire) {
      fundedOutcome = { unmeasured: true, reason: 'sign failed: ' + JSON.stringify(s).slice(0, 160) };
      break;
    }
    signed = s;
    const payerBefore = await balanceOf(rpcUrl, f.fromPubkey);
    const destBefore = await balanceOf(rpcUrl, DOCUMENTED_DESTINATION);
    if (payerBefore.balanceError || destBefore.balanceError) {
      fundedOutcome = { unmeasured: true, reason: 'balance read failed' };
      break;
    }
    const outcome = await submitWire(rpcUrl, s.signedWire);
    if (outcome.unmeasured) { fundedOutcome = outcome; break; }
    if (!outcome.accepted && /blockhash/i.test(outcome.refusedMessage || '')) {
      // Stale blockhash: retry once with a fresh one.
      report.staleBlockhashRetries = (report.staleBlockhashRetries || 0) + 1;
      continue;
    }
    const payerAfter = await balanceOf(rpcUrl, f.fromPubkey);
    const destAfter = await balanceOf(rpcUrl, DOCUMENTED_DESTINATION);
    fundedOutcome = {
      ...outcome,
      payerDelta: payerAfter.lamports - payerBefore.lamports,
      destDelta: destAfter.lamports - destBefore.lamports,
      payerBefore: payerBefore.lamports,
      payerAfter: payerAfter.lamports,
      destBefore: destBefore.lamports,
      destAfter: destAfter.lamports,
    };
    break;
  }
  report.fundedAttempts = attempts;
  report.blockhashUsed = blockhashUsed;
  report.funded = fundedOutcome;

  // --- C2: corrupted signature on the same funded wire -----------------
  if (signed && signed.signedWire) {
    const corruptedOutcome = await submitWire(rpcUrl, corruptSignatureByte(signed.signedWire));
    report.corrupted = corruptedOutcome;
  } else {
    report.corrupted = { unmeasured: true, reason: 'no funded wire to corrupt' };
  }

  // --- C3: the UNFUNDED fee payer -------------------------------------
  {
    const { Keypair } = require('@solana/web3.js');
    const unfunded = Keypair.generate();
    const bh = await latestBlockhash(rpcUrl);
    if (bh.blockhashError) {
      report.unfunded = { unmeasured: true, reason: bh.blockhashError };
    } else {
      // Build the SAME wire shape with an unfunded payer, using the
      // product's own wire builder (no daemon needed: the point is that
      // the runtime rejects it before any signature is relevant).
      const { buildTransferWire } = require('../src/client.js');
      let wire;
      try {
        wire = buildTransferWire({
          fromPubkey: unfunded.publicKey.toBase58(),
          toPubkey: DOCUMENTED_DESTINATION,
          lamports: TRANSFER_LAMPORTS,
          blockhash: bh.blockhash,
        });
      } catch (err) {
        report.unfunded = { unmeasured: true, reason: 'wire build failed' };
      }
      if (wire) {
        // Sign it with the unfunded key so the rejection can ONLY be the
        // balance, never a missing signature.
        const { Transaction, SystemProgram } = require('@solana/web3.js');
        try {
          const tx = new Transaction();
          tx.feePayer = unfunded.publicKey;
          tx.recentBlockhash = bh.blockhash;
          tx.add(SystemProgram.transfer({
            fromPubkey: unfunded.publicKey,
            toPubkey: new (require('@solana/web3.js').PublicKey)(DOCUMENTED_DESTINATION),
            lamports: TRANSFER_LAMPORTS,
          }));
          tx.sign(unfunded);
          report.unfunded = await submitWire(rpcUrl, tx.serialize());
        } catch (err) {
          report.unfunded = { unmeasured: true, reason: 'unfunded wire build failed' };
        }
      }
    }
  }

  stopDaemon();

  const derived = derive({
    placeholder: report.placeholder,
    corrupted: report.corrupted,
    unfunded: report.unfunded,
    funded: report.funded,
  });
  report.verdict = derived.verdict;
  report.defects = derived.defects || [];
  report.checks = derived.checks || [];
  if (derived.reason) report.reason = derived.reason;
  report.limits = [
    'the runtime is a LOCAL solana-test-validator (agave 4.3.2, feature-set 3383571666) on a fresh local ledger — mainnet was never contacted and no real lamports moved',
    'the destination is the documented So111...1112 address, funded on the local ledger; on mainnet it is the wrapped-SOL mint',
    'a local validator is the same runtime code as mainnet, but it is not mainnet: no mainnet state, no mainnet fee market, no mainnet congestion',
    'the fee payer is funded from the validator genesis faucet, not from a real exchange account',
    'own-host measurement; no outside user, no audit; this measures the wire, not custody',
  ];
  return finish(derived.verdict === 'wire-accepted-by-real-runtime' ? 0
    : derived.verdict === 'wire-defective' ? 1 : 3);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('measure-wire-submission crashed:', err && err.stack ? err.stack : err);
    process.exit(3);
  });
}
