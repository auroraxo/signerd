// Wire-validity against Solana mainnet itself, measured WITHOUT submitting.
//
// WHY (2026-11-05): the daemon's own path already proves ed25519 validity
// twice (noble sign + OpenSSL verify) and the wire is serialized by
// @solana/web3.js 1.98.4. But that is OUR code checking OUR bytes. A
// stranger who follows the README with a REAL blockhash and a FUNDED fee
// payer gets one final surface signerd cannot test offline: whether the
// signed wire is VALID TO SOLANA ITSELF. Until today nothing measured that.
//
// HOW, WITHOUT SUBMITTING (public RPC; no key material leaves the machine;
// no lamports move): simulateTransaction(sigVerify:true,
// replaceRecentBlockhash:false) on the SIGNED wire runs signature
// verification against the message and the real account states:
//   R2 the documented quickstart wire (placeholder blockhash) must come
//      back with exactly "BlockhashNotFound" — its own defect, not a
//      signature or message defect. (Which check mainnet runs FIRST is
//      NOT measured here and is not claimed.)
//   R3 the same wire with a FRESH mainnet blockhash (getLatestBlockhash,
//      authoritative) must fail on NOTHING except the unfunded fee payer
//      (measured classes: "AccountNotFound" pre-execution, or system
//      error 1 at execution). A funded stranger's first transfer cannot
//      fail on anything else if the product's wire is right.
//   R4 the oracle must DETECT a bad signature: one flipped signature byte
//      on the R3 wire must flip the verdict to "SignatureFailure".
//      Without this control a broken oracle that reports everything
//      clean would pass R3.
//
// FALSIFICATION RULES:
//   * Any RPC error, refusal, rate limit, or missing field => NO VERDICT
//     (exit 3), never "valid".
//   * verdict "wire-valid-modulo-balance" requires R2 AND R3 AND R4 to
//     hold with the exact expected classes. Anything else is a named
//     defect or no-verdict.
//
// Usage: node tools/measure-wire-validity.mjs [--out file]
//   Exit 0 = measured, 3 = no verdict.
'use strict';

import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';

// ---------------------------------------------------------------- RPC layer

async function rpc(method, params, attempt = 0) {
  let res;
  try {
    res = await fetch(RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
  } catch (err) {
    if (attempt < 2) return rpc(method, params, attempt + 1);
    return { networkError: String(err && err.message ? err.message : err) };
  }
  if (res.status === 429 || res.status === 503 || res.status >= 500) {
    if (attempt < 2) {
      await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
      return rpc(method, params, attempt + 1);
    }
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

// ---------------------------------------------------------------- fixture

function fixture(root, passphraseFile) {
  const cfg = path.join(root, '.config', 'signerd');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  const keygen = spawnSync(process.execPath, [CLI, 'keygen',
    '--keystore', path.join(cfg, 'ops.key'),
    '--passphrase-file', passphraseFile], { encoding: 'utf8' });
  if (keygen.status !== 0) return { keygenError: keygen.stderr };
  const keyLine = keygen.stdout.trim().split('\n').pop();
  let parsedKey;
  try { parsedKey = JSON.parse(keyLine); } catch { return { keygenParseError: keyLine }; }
  return { fromPubkey: parsedKey.publicKey };
}

// Flip one byte inside the 64-byte signature slot (slot starts at offset 1).
function corruptSignatureByte(wire) {
  const bad = Buffer.from(wire);
  bad[7] ^= 0xff;
  return bad;
}

// ------------------------------------------------------- classification

function simFailureText(sim) {
  if (!sim || typeof sim !== 'object') return '';
  if (sim.transportError) return String(sim.transportError);
  if (sim.err === null || sim.err === undefined) return '';
  return JSON.stringify(sim.err);
}

function failureClassOf(sim) {
  if (!sim || typeof sim !== 'object') return 'unmeasured';
  if (sim.networkError || sim.httpError || sim.rpcError || sim.parseError) return 'unmeasured';
  if (sim.transportError) {
    return /SignatureFailure|signature verification/i.test(sim.transportError)
      ? 'signature-invalid' : 'transport-rejected';
  }
  if (sim.err === null) return 'clean';
  const errText = JSON.stringify(sim.err);
  // Measured enums (mainnet RPC apiVersion 4.4.0, live 2026-11-05):
  //   "BlockhashNotFound"            stale/unknown recent blockhash
  //   "SignatureFailure"             a signature did not verify
  //   "AccountNotFound"              a required account does not exist —
  //                                  for our fixture this is the UNFUNDED
  //                                  fee payer, caught pre-execution
  //   {InstructionError:[2,{Custom:1}]} insufficient funds during execution
  if (/BlockhashNotFound/.test(errText)) return 'blockhash-not-found';
  if (/SignatureFailure/.test(errText)) return 'signature-invalid';
  if (/AccountNotFound/.test(errText)) return 'account-not-found';
  const m = /InstructionError\]?\s*:\s*\[\s*(\d+)\s*,\s*\{\s*"Custom"\s*:\s*(\d+)/.exec(errText) ||
            /"InstructionError":\[\s*(\d+)\s*,\s*\{\s*"Custom":\s*(\d+)/.exec(errText);
  if (m) {
    const programIndex = Number(m[1]);
    const code = Number(m[2]);
    if (programIndex === 2 && code === 1) return 'insufficient-funds';
    return `instruction-error-p${programIndex}-c${code}`;
  }
  return 'other:' + errText.slice(0, 80);
}

// ---------------------------------------------------------------- pure rules

// R2: the placeholder wire's only mainnet-reported failure must be the
// blockhash. Measured enum: "BlockhashNotFound" (with a FRESH blockhash and
// a flipped signature byte, mainnet instead reports "SignatureFailure" —
// so both checks are enforced; which runs first is NOT measured here and
// is not claimed).
export function classifyPlaceholder(sim) {
  const cls = failureClassOf(sim);
  return {
    ok: cls === 'blockhash-not-found',
    observed: cls,
    rule: 'placeholder-blockhash-only-defect',
  };
}

// R3: the fresh-blockhash wire must fail on NOTHING except the unfunded
// fee payer. Measured 2026-11-05: mainnet reports that case as
// "AccountNotFound" (fee payer has never transacted, pre-execution) or —
// if it exists but is empty — {InstructionError:[2,{Custom:1}]}.
export function classifyFresh(sim) {
  const cls = failureClassOf(sim);
  const ok = cls === 'clean' || cls === 'insufficient-funds' || cls === 'account-not-found';
  const notes = {
    clean: 'simulated fully clean (fee payer had a balance — fixture drift, still valid)',
    'insufficient-funds': 'only the fee payer balance failed, at execution (system error 1 on the transfer)',
    'account-not-found': 'only the UNFUNDED fee payer failed, pre-execution (mainnet: AccountNotFound)',
  };
  return {
    ok,
    observed: cls,
    rule: 'fresh-blockhash-valid-except-unfunded-fee-payer',
    note: ok ? notes[cls] : `unexpected failure class on mainnet simulation: ${cls}`,
  };
}

// R4: the oracle must DETECT a corrupted signature: same fresh wire with
// one signature byte flipped must flip to the signature class (measured
// enum: "SignatureFailure"). Without this control, a broken oracle that
// reports everything as clean would pass R3.
export function classifyCorrupted(sim) {
  const cls = failureClassOf(sim);
  return {
    ok: cls === 'signature-invalid',
    observed: cls,
    rule: 'corrupted-signature-must-be-detected',
  };
}

export function derive({ placeholderSim, freshSim, corruptedSim }) {
  const checks = [];
  for (const [name, sim] of [['placeholder', placeholderSim], ['fresh', freshSim], ['corrupted', corruptedSim]]) {
    if (!sim || sim.networkError || sim.httpError || sim.rpcError || sim.parseError) {
      const reason = sim
        ? (sim.networkError ? `${name}: ${sim.networkError}`
          : sim.httpError ? `${name}: HTTP ${sim.httpError}`
          : sim.rpcError ? `${name}: ${JSON.stringify(sim.rpcError).slice(0, 120)}`
          : `${name}: ${sim.parseError}`)
        : `${name}: missing`;
      return { verdict: 'no-verdict', reason, checks };
    }
  }

  const defects = [];
  let verdict = 'wire-valid-modulo-balance';

  const r2 = classifyPlaceholder(placeholderSim);
  checks.push(r2);
  if (!r2.ok) {
    defects.push(`placeholder wire failed with ${r2.observed}, not the blockhash-only class`);
    verdict = 'wire-defective';
  }

  const r3 = classifyFresh(freshSim);
  checks.push(r3);
  if (!r3.ok) {
    defects.push(`fresh-blockhash wire failed with ${r3.observed} — the product's wire is not valid to mainnet`);
    verdict = 'wire-defective';
  }

  const r4 = classifyCorrupted(corruptedSim);
  checks.push(r4);
  if (!r4.ok) {
    defects.push(`corrupted-signature control reported ${r4.observed} — the oracle cannot detect bad signatures`);
    verdict = 'no-verdict';
  }

  return { verdict, defects, checks };
}

// ---------------------------------------------------------------- live path

async function main() {
  const outIdx = process.argv.indexOf('--out');
  const outFile = outIdx !== -1 ? process.argv[outIdx + 1] : null;

  const report = {
    tool: 'measure-wire-validity',
    rpc: RPC,
    at: new Date().toISOString(),
  };
  let daemon = null;
  const finish = (code) => {
    if (daemon && daemon.exitCode === null) {
      try { daemon.kill('SIGKILL'); } catch { /* already gone */ }
    }
    const text = JSON.stringify(report, null, 2);
    if (outFile) fs.writeFileSync(outFile, text);
    console.log(text);
    process.exit(code);
  };

  // Fresh passphrase file 0600 — the fixture IS a stranger run.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-wire-validity-'));
  const passphraseFile = path.join(root, 'pass');
  fs.writeFileSync(passphraseFile, 'wire-validity fixture\n', { mode: 0o600 });

  const f = fixture(root, passphraseFile);
  if (f.keygenError || f.keygenParseError) {
    report.verdict = 'no-verdict';
    report.reason = f.keygenError || f.keygenParseError;
    return finish(3);
  }
  report.fromPubkey = f.fromPubkey;

  // R1: the documented quickstart chain, CLI alone, up to the signature.
  const grants = path.join(root, 'grants.json');
  const ksPath = path.join(root, '.config', 'signerd', 'ops.key');
  const add = spawnSync(process.execPath, [CLI, 'grant-add',
    '--grants', grants, '--name', 'ops-24h',
    '--keystore', ksPath,
    '--destination', 'So11111111111111111111111111111111111111112',
    '--max-lamports', '500000000', '--window-max-lamports', '500000000',
    '--window-seconds', '3600', '--expires', '2030-01-01T00:00:00Z'], { encoding: 'utf8' });
  if (add.status !== 0) {
    report.verdict = 'no-verdict';
    report.reason = `grant-add failed: ${add.stdout} ${add.stderr}`;
    return finish(3);
  }

  const ledger = path.join(root, 'journal.jsonl');
  const socket = path.join(root, 'signerd.sock');
  // The daemon must STAY ALIVE while the measurements run: an async spawn,
  // not spawnSync (whose timeout would kill the child).
  daemon = spawn(process.execPath, [CLI, 'run',
    '--keystore', ksPath, '--passphrase-file', passphraseFile,
    '--grants', grants, '--ledger', ledger, '--socket', socket],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let daemonOut = '';
  daemon.stdout.on('data', (c) => { daemonOut += c; });
  daemon.stderr.on('data', (c) => { daemonOut += c; });
  const up = await new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      const line = daemonOut.split('\n').find((l) => l.includes('"ok":true'));
      if (line) return resolve(line);
      if (daemon.exitCode !== null) return resolve(null);
      if (Date.now() - started > 20000) return resolve(null);
      setTimeout(tick, 100);
    };
    tick();
  });
  if (!up) {
    report.verdict = 'no-verdict';
    report.reason = `daemon did not start: ${daemonOut}`;
    return finish(3);
  }

  const signOnce = (blockhash) => {
    const txPath = path.join(root, `tx-${blockhash.slice(0, 8)}.bin`);
    const build = spawnSync(process.execPath, [CLI, 'build-tx',
      '--keystore', ksPath,
      '--to', 'So11111111111111111111111111111111111111112',
      '--lamports', '42', '--out', txPath,
      ...(blockhash ? ['--blockhash', blockhash] : [])], { encoding: 'utf8' });
    if (build.status !== 0) return { buildError: `${build.stdout} ${build.stderr}` };
    const sign = spawnSync(process.execPath, [CLI, 'sign',
      '--socket', socket, '--grant', 'ops-24h', '--tx', txPath], { encoding: 'utf8' });
    let answer;
    try { answer = JSON.parse(sign.stdout.trim().split('\n').pop()); } catch {
      return { signParseError: sign.stdout + sign.stderr };
    }
    if (!answer.ok) return { refused: answer };
    return { signedWire: Buffer.from(answer.signed, 'base64'), seq: answer.seq };
  };

  // --- the placeholder wire (quickstart verbatim) --------------------
  const placeholder = signOnce('');
  if (!placeholder.signedWire) {
    report.verdict = 'no-verdict';
    report.reason = 'placeholder path failed: ' + JSON.stringify(placeholder).slice(0, 200);
    return finish(3);
  }
  report.signedWireBytes = placeholder.signedWire.length;
  report.seq = placeholder.seq;

  // Independent verification, same oracle as test/quickstart-shape-verbatim.
  const { VersionedTransaction } = require('@solana/web3.js');
  const parsed = VersionedTransaction.deserialize(placeholder.signedWire);
  const message = Buffer.from(parsed.message.serialize());
  const signature = Buffer.from(parsed.signatures[0]);
  // The keystore's cleartext public key is on the keygen line we parsed.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
    Buffer.from(new (require('@solana/web3.js').PublicKey)(f.fromPubkey).toBytes())]);
  const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const verifies = crypto.verify(null, message, keyObject, signature);
  report.openSSLVerifies = verifies;
  if (!verifies) {
    report.verdict = 'wire-defective';
    report.defects = ['the daemon signature does not verify under OpenSSL ed25519'];
    return finish(1);
  }

  const simulate = async (wire) => {
    const json = await rpc('simulateTransaction', [
      wire.toString('base64'),
      { sigVerify: true, replaceRecentBlockhash: false, encoding: 'base64' },
    ]);
    if (json.networkError || json.httpError || json.rpcError || json.parseError) return json;
    // Response shape (measured live 2026-11-05, apiVersion 4.4.0):
    // { result: { context, value: { err, logs, ... } } }
    const value = json.result && json.result.value;
    if (!value || typeof value !== 'object' || !('err' in value)) {
      return { rpcError: 'simulateTransaction returned no result.value.err' };
    }
    return value;
  };

  // R2: placeholder wire — blockhash must be the ONLY failure.
  const placeholderSim = await simulate(placeholder.signedWire);
  report.placeholderSim = placeholderSim;

  // Fresh blockhash, straight from mainnet (authoritative freshness).
  const bh = await rpc('getLatestBlockhash', [{ commitment: 'finalized' }]);
  if (bh.networkError || bh.httpError || bh.rpcError || bh.parseError ||
      !bh.result || !bh.result.value || !bh.result.value.blockhash) {
    report.verdict = 'no-verdict';
    report.reason = 'getLatestBlockhash unmeasured: ' + JSON.stringify(bh).slice(0, 200);
    return finish(3);
  }
  const freshBlockhash = bh.result.value.blockhash;
  report.freshBlockhash = freshBlockhash;

  const fresh = signOnce(freshBlockhash);
  if (!fresh.signedWire) {
    report.verdict = 'no-verdict';
    report.reason = 'fresh path failed: ' + JSON.stringify(fresh).slice(0, 200);
    return finish(3);
  }

  // R3: fresh wire — only the unfunded fee payer may fail.
  const freshSim = await simulate(fresh.signedWire);
  report.freshSim = freshSim;

  // R4: oracle sensitivity — one flipped signature byte must be detected.
  const corrupted = await simulate(corruptSignatureByte(fresh.signedWire));
  report.corruptedSim = corrupted;

  const derived = derive({ placeholderSim, freshSim, corruptedSim: corrupted });
  report.verdict = derived.verdict;
  report.defects = derived.defects || [];
  report.checks = derived.checks || [];
  report.limits = [
    'simulation, not submission: nothing was sent to the mempool/chain and no lamports moved',
    'own-host measurement, public RPC; rate limits => no-verdict, never a pass',
    'the funded fee-payer case itself is NOT exercised — by construction the fixture key holds 0 lamports',
    'no outside user, no audit; this measures the wire, not custody',
  ];
  return finish(derived.verdict === 'wire-valid-modulo-balance' ? 0
    : derived.verdict === 'wire-defective' ? 1 : 3);
}

// Imported by test/measure-wire-validity.test.mjs — only run the live path
// when executed directly (same guard as the other instruments).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('measure-wire-validity crashed:', err && err.stack ? err.stack : err);
    process.exit(3);
  });
}
