#!/usr/bin/env node
'use strict';

/**
 * MEASURE THE GRANT VALUE CONTRACT (2026-11-08).
 *
 * WHAT must hold: what `grant-add` - the creation path a stranger walks -
 * accepts must be exactly what the daemon accepts at request time. A value
 * the CLI writes into the grant file while `gate()` refuses it is a scope the
 * operator believes is live and that can never sign.
 *
 * WHY (measured 2026-11-08, on this tree): the creation path validated
 * VALUES with shapes only - a base58 regex for the two keys, a calendar-
 * SHAPE regex for the expiry, digits-only regexes for the caps - while the
 * runtime re-checks the SEMANTICS:
 *   - policy.js requires `new PublicKey(v).toBase58() === v` (a real 32-byte
 *     key in canonical form) and a canonical RFC3339 round trip;
 *   - ledger.js requires the caps in u64 range and the window a SAFE
 *     integer (`Number.isSafeInteger`), and refuses a zero window.
 * Every case where the two disagree is a written-but-dead grant.
 *
 * FOR EACH CASE this records:
 *   create  does `signerd grant-add` exit 0 and write the file?
 *   load    does the product's own loader accept that file?
 *   runtime does gate(wire, grant) - the daemon's own decision - allow it?
 *   contractHolds  create === runtime
 *
 * The verdict comes from what the CLI and gate() actually returned; this is
 * a measurement, not an assertion. Exit code 1 when the contract does NOT
 * hold, so the tool can gate a release.
 *
 * Usage: node tools/measure-grant-value-contract.mjs --slot before|after
 *        (merges into research/grant-value-contract-2026-11-08.json)
 */
import { spawnSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const OUT = path.join(ROOT, 'research', 'grant-value-contract-2026-11-08.json');

// The wire is built from THESE two keys, so the daemon's verdict can only
// be about the grant under test - never about a wire/grant key mismatch.
const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();

const GOOD = {
  signer: PAYER.publicKey.toBase58(),
  destination: RECIPIENT.publicKey.toBase58(),
  maxLamports: '42',
  expiresAt: '2030-01-01T00:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

/** One substitution into an otherwise good grant. */
const CASES = [
  // expiresAt: calendar SHAPE vs. a real canonical instant.
  { field: 'expiresAt', value: '2030-01-01T00:00:00Z', label: 'canonical instant' },
  { field: 'expiresAt', value: '2032-02-29T00:00:00Z', label: 'real leap day' },
  { field: 'expiresAt', value: '2030-01-01T00:00:00.5Z', label: 'canonical fraction' },
  { field: 'expiresAt', value: '2030-02-31T00:00:00Z', label: 'impossible day (Feb 31)' },
  { field: 'expiresAt', value: '2030-04-31T00:00:00Z', label: 'impossible day (Apr 31)' },
  { field: 'expiresAt', value: '2031-13-01T00:00:00Z', label: 'impossible month (13)' },
  { field: 'expiresAt', value: '2030-01-32T00:00:00Z', label: 'impossible day (32)' },
  { field: 'expiresAt', value: '2030-01-01T25:00:00Z', label: 'impossible hour (25)' },
  { field: 'expiresAt', value: '2030-02-29T00:00:00Z', label: 'Feb 29 in a non-leap year' },
  { field: 'expiresAt', value: '2030-01-01T00:00:60Z', label: 'leap second (60s)' },
  { field: 'expiresAt', value: '2030-01-01T00:00:00.1234Z', label: 'fraction beyond ms' },
  { field: 'expiresAt', value: '2030-01-01T00:00:00+00:00', label: 'offset instead of Z' },
  { field: 'expiresAt', value: '2030-01-01 00:00:00Z', label: 'space separator' },

  // windowSeconds: digits vs. the runtime's safe-integer bound.
  { field: 'windowSeconds', value: '3600', label: 'ordinary window' },
  { field: 'windowSeconds', value: '9007199254740991', label: 'MAX_SAFE_INTEGER' },
  { field: 'windowSeconds', value: '9007199254740993', label: 'just past MAX_SAFE_INTEGER' },
  { field: 'windowSeconds', value: '99999999999999999999', label: '20 nines' },
  { field: 'windowSeconds', value: '0', label: 'zero window' },

  // u64 caps: digits vs. the runtime's 2^64-1 bound.
  { field: 'maxLamports', value: '42', label: 'ordinary cap' },
  { field: 'maxLamports', value: '18446744073709551615', label: 'u64 max' },
  { field: 'maxLamports', value: '18446744073709551616', label: 'u64 max + 1' },
  { field: 'maxLamports', value: '99999999999999999999', label: '20 nines' },
  { field: 'windowMaxLamports', value: '100000', label: 'ordinary window cap' },
  { field: 'windowMaxLamports', value: '18446744073709551616', label: 'u64 max + 1' },
  { field: 'windowMaxLamports', value: '99999999999999999999', label: '20 nines' },

  // keys: base58 charset vs. an actual 32-byte canonical public key.
  { field: 'destination', value: null, label: 'canonical key' }, // filled below
  { field: 'destination', value: '1'.repeat(43), label: '43 ones (not 32 bytes)' },
  { field: 'destination', value: '1'.repeat(31), label: '31 ones (not 32 bytes)' },
  { field: 'destination', value: 'So1111111111111111111111111111111111111111', label: 'truncated WSOL mint' },
  { field: 'destination', value: 'not-a-pubkey', label: 'non-base58' },
];

function grantAdd(file, grant) {
  const res = spawnSync(process.execPath, [CLI, 'grant-add',
    '--grants', file, '--name', 'ops', '--signer', grant.signer,
    '--destination', grant.destination,
    '--max-lamports', grant.maxLamports,
    '--window-max-lamports', grant.windowMaxLamports,
    '--window-seconds', grant.windowSeconds,
    '--expires', grant.expiresAt], { encoding: 'utf8', timeout: 60000 });
  const stderr = (res.stderr || '').trim();
  return { status: res.status, firstLine: (stderr.split('\n')[0] || '').trim() };
}

/**
 * The daemon's own decision for this grant: gate() runs policy (real key,
 * canonical expiry, cap) and then the ledger (u64 window, safe-integer
 * seconds, rolling cap, replay). The WIRE is a well-formed legacy transfer,
 * so the only thing that can refuse is the grant under test.
 */
function runtimeVerdict(grant) {
  const { evaluate } = require(path.join(ROOT, 'src', 'policy.js'));
  const { Ledger, gate } = require(path.join(ROOT, 'src', 'ledger.js'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-measure-'));
  fs.chmodSync(dir, 0o700);
  const ledger = new Ledger({ file: path.join(dir, 'journal.jsonl') });
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey,
    toPubkey: RECIPIENT.publicKey,
    lamports: 42,
  }));
  tx.sign(PAYER);
  const wire = tx.serialize();
  const now = new Date('2026-11-08T00:00:00.000Z');
  const verdict = gate(wire, grant, now, ledger);
  const policy = evaluate(wire, grant, now);
  return {
    allowed: verdict.allowed === true,
    refused: verdict.refused || null,
    policyRefused: policy.refused || null,
  };
}

function main() {
  const slotIndex = process.argv.indexOf('--slot');
  const slot = slotIndex >= 0 ? process.argv[slotIndex + 1] : null;
  if (slot !== 'before' && slot !== 'after') {
    process.stderr.write('usage: measure-grant-value-contract.mjs --slot before|after\n');
    process.exit(2);
  }

  const signer = GOOD.signer;
  const cases = CASES.map((c) => {
    const value = c.value === null ? GOOD.destination : c.value;
    return { ...c, value, grant: { ...GOOD, signer, [c.field]: value } };
  });

  const rows = [];
  for (const c of cases) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-vc-'));
    fs.chmodSync(dir, 0o700);
    const file = path.join(dir, 'grants.json');
    const create = grantAdd(file, c.grant);

    let load = false;
    if (create.status === 0) {
      try {
        require(path.join(ROOT, 'src', 'grantfile.js')).loadGrantFile(file);
        load = true;
      } catch { load = false; }
    }

    const runtime = runtimeVerdict(c.grant);
    rows.push({
      field: c.field,
      value: c.value,
      label: c.label,
      createExit: create.status,
      createAccepted: create.status === 0,
      createFirstLine: create.firstLine,
      loadAccepted: load,
      runtimeAllowed: runtime.allowed,
      runtimeRefused: runtime.refused,
      policyRefused: runtime.policyRefused,
      contractHolds: (create.status === 0) === runtime.allowed,
    });
  }

  const violations = rows.filter((r) => !r.contractHolds);
  const doc = fs.existsSync(OUT) ? JSON.parse(fs.readFileSync(OUT, 'utf8'))
    : { generatedAt: '2026-11-08', tool: 'tools/measure-grant-value-contract.mjs', slots: {} };
  doc.tool = 'tools/measure-grant-value-contract.mjs';
  doc.slots = doc.slots || {};
  doc.slots[slot] = {
    when: new Date().toISOString(),
    commit: execSync('git rev-parse --short HEAD', { cwd: ROOT }).toString().trim(),
    cases: rows.length,
    contractViolations: violations.length,
    violations: violations.map((v) =>
      `${v.field}=${v.value} (${v.label}): create=${v.createAccepted} runtime=${v.runtimeAllowed} refused=${v.runtimeRefused}`),
    rows,
  };
  fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');

  process.stdout.write(JSON.stringify({
    slot,
    cases: rows.length,
    contractViolations: violations.length,
    violations: doc.slots[slot].violations,
    out: path.relative(ROOT, OUT),
  }, null, 2) + '\n');
  process.exit(violations.length > 0 ? 1 : 0);
}

main();
