'use strict';

// THE GRANT VALUE CONTRACT (2026-11-08).
//
// WHAT THE CONTRACT IS: a value `grant-add` writes must be a value the
// daemon can honour. Measured on the pre-fix tree with
// tools/measure-grant-value-contract.mjs (research/grant-value-contract-
// 2026-11-08.json, slot "before"): 16 of 30 cases were WRITTEN by the
// creation path and REFUSED by the runtime - `grant-add --expires
// 2030-02-31T00:00:00Z` exited 0 and wrote a file, and every later request
// against that scope came back `invalid_grant`, because Date.parse
// normalizes impossible calendar dates instead of rejecting them.
//
// WHY THE TWO SIDES DRIFTED: the creation path (src/grantadd.js) and the
// loader (src/grantfile.js) validated values with SHAPES only - a base58
// charset regex for the keys, a calendar-SHAPE regex for the expiry,
// digits-only regexes for the caps - while the runtime (src/policy.js,
// src/ledger.js) validates the MEANING: a real 32-byte canonical public
// key, a canonical RFC3339 round trip, a u64 in range, a safe-integer
// window. Four hand-kept copies of each rule is what let them drift; all
// five sites now read src/grantvalues.js.
//
// THE RULES THIS PINS:
//   V1 grant-add REFUSES a value the runtime refuses, and writes NOTHING.
//   V2 the loader refuses the same value at load time (the file a stranger
//      edits by hand must fail at startup, named, not per request).
//   V3 the runtime still refuses it (guard: green on both trees).
//   V4 grant-add and the loader still ACCEPT the canonical boundary values
//      (guard: green on both trees - the fix must not over-tighten).
//   V5 a refusal prints its code EXACTLY ONCE and names its repair (the
//      house rule from test/grant-refusal-voice.test.js).
//   V6 creation, load and runtime agree on EVERY case in the table: there
//      is no value where create says ok and gate says invalid_grant.
//
// The ladder: V1, V2, V5, V6 are RED on the pre-fix tree; V3 and V4 are
// GREEN on both.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { evaluate } = require('../src/policy');
const { Ledger, gate } = require('../src/ledger');
const { validateGrant, loadGrantFile } = require('../src/grantfile');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

// One wire, one clock, one ledger for the whole table: every case below is
// refused BEFORE the wire is compared (policy checks key/expiry/cap first,
// the ledger checks the window next), so a single well-formed legacy
// transfer isolates the GRANT as the only thing that can refuse.
const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();
const NOW = new Date('2026-11-08T00:00:00.000Z');

function wire() {
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({
    fromPubkey: PAYER.publicKey,
    toPubkey: RECIPIENT.publicKey,
    lamports: 42,
  }));
  tx.sign(PAYER);
  return tx.serialize();
}
const WIRE = wire();

function ledger() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-gvc-'));
  return new Ledger({ file: path.join(dir, 'journal.jsonl') });
}

const GOOD = {
  signer: PAYER.publicKey.toBase58(),
  destination: RECIPIENT.publicKey.toBase58(),
  maxLamports: '42',
  expiresAt: '2099-01-01T00:00:00Z',
  windowMaxLamports: '100000',
  windowSeconds: '3600',
};

/**
 * The RUNTIME verdict for a grant: policy (real key, canonical expiry, cap)
 * and then the ledger (u64 window, safe-integer seconds, rolling cap).
 * null means "the runtime would sign it".
 */
function runtimeRefusal(grant) {
  const policyVerdict = evaluate(WIRE, grant, NOW);
  if (!policyVerdict.allowed) return policyVerdict.refused;
  const verdict = gate(WIRE, grant, NOW, ledger());
  return verdict.allowed ? null : verdict.refused;
}

/** Does the product's own validator accept this grant at load time? */
function loadRefusal(grant) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-gvc-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, grants: { ops: grant } }, null, 2),
    { mode: 0o600 });
  try {
    loadGrantFile(file);
    return null;
  } catch (err) {
    return err.code || 'grant_file_invalid';
  }
}

/** The CLI's verdict: exit status plus the first stderr line. */
function create(grant) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-gvc-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'grants.json');
  const res = spawnSync(process.execPath, [CLI, 'grant-add',
    '--grants', file, '--name', 'ops',
    '--signer', grant.signer, '--destination', grant.destination,
    '--max-lamports', grant.maxLamports,
    '--window-max-lamports', grant.windowMaxLamports,
    '--window-seconds', grant.windowSeconds,
    '--expires', grant.expiresAt],
  { encoding: 'utf8', timeout: 60000 });
  const stderr = res.stderr || '';
  const lines = stderr.trim().split('\n').filter((l) => l.length > 0);
  return {
    status: res.status,
    wrote: fs.existsSync(file),
    stderr,
    firstLine: (lines[0] || '').trim(),
    hasFix: lines.some((l) => /^\s*fix:/.test(l)),
    code: ((lines[0] || '').split(':')[0] || '').trim(),
    occurrences: (stderr.match(/grant_field_invalid/g) || []).length,
  };
}

/**
 * The table: { label, field, value, runtimeRefused } - every value the
 * runtime refuses as a GRANT problem (invalid_grant / invalid_grant_window),
 * plus the canonical boundaries it must keep accepting (runtimeRefused null).
 */
const TABLE = [
  // --- impossible or non-canonical instants (V1 red) ---
  { label: 'impossible day (Feb 31)', field: 'expiresAt', value: '2030-02-31T00:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'impossible day (Apr 31)', field: 'expiresAt', value: '2030-04-31T00:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'impossible month (13)', field: 'expiresAt', value: '2031-13-01T00:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'impossible day (32)', field: 'expiresAt', value: '2030-01-32T00:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'impossible hour (25)', field: 'expiresAt', value: '2030-01-01T25:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'Feb 29 in a non-leap year', field: 'expiresAt', value: '2030-02-29T00:00:00Z', runtimeRefused: 'invalid_grant' },
  { label: 'leap second (60s)', field: 'expiresAt', value: '2030-01-01T00:00:60Z', runtimeRefused: 'invalid_grant' },
  { label: 'fraction beyond milliseconds', field: 'expiresAt', value: '2030-01-01T00:00:00.1234Z', runtimeRefused: 'invalid_grant' },
  { label: 'offset instead of Z', field: 'expiresAt', value: '2030-01-01T00:00:00+00:00', runtimeRefused: 'invalid_grant' },
  { label: 'space separator', field: 'expiresAt', value: '2030-01-01 00:00:00Z', runtimeRefused: 'invalid_grant' },

  // --- caps outside u64 range (V1 red) ---
  { label: 'maxLamports over u64', field: 'maxLamports', value: '18446744073709551616', runtimeRefused: 'invalid_grant' },
  { label: 'maxLamports 20 nines', field: 'maxLamports', value: '99999999999999999999', runtimeRefused: 'invalid_grant' },
  { label: 'windowMaxLamports over u64', field: 'windowMaxLamports', value: '18446744073709551616', runtimeRefused: 'invalid_grant_window' },
  { label: 'windowMaxLamports 20 nines', field: 'windowMaxLamports', value: '99999999999999999999', runtimeRefused: 'invalid_grant_window' },

  // --- window outside the runtime's safe-integer bound (V1 red) ---
  { label: 'windowSeconds past MAX_SAFE_INTEGER', field: 'windowSeconds', value: '9007199254740993', runtimeRefused: 'invalid_grant_window' },
  { label: 'windowSeconds 20 nines', field: 'windowSeconds', value: '99999999999999999999', runtimeRefused: 'invalid_grant_window' },

  // --- keys that are not a real 32-byte canonical public key (V1 red) ---
  { label: '43 ones', field: 'destination', value: '1'.repeat(43), runtimeRefused: 'invalid_grant' },
  { label: '31 ones', field: 'destination', value: '1'.repeat(31), runtimeRefused: 'invalid_grant' },
  { label: 'truncated WSOL mint', field: 'destination', value: 'So1111111111111111111111111111111111111111', runtimeRefused: 'invalid_grant' },
  { label: '44 x-s (bad signer)', field: 'signer', value: 'x'.repeat(44), runtimeRefused: 'invalid_grant' },

  // --- canonical boundaries the fix must NOT over-tighten (V4 guard) ---
  { label: 'canonical instant', field: 'expiresAt', value: '2030-01-01T00:00:00Z', runtimeRefused: null },
  { label: 'real leap day', field: 'expiresAt', value: '2032-02-29T00:00:00Z', runtimeRefused: null },
  { label: 'canonical fraction', field: 'expiresAt', value: '2030-01-01T00:00:00.5Z', runtimeRefused: null },
  { label: 'u64 max cap', field: 'maxLamports', value: '18446744073709551615', runtimeRefused: null },
  { label: 'u64 max window cap', field: 'windowMaxLamports', value: '18446744073709551615', runtimeRefused: null },
  { label: 'MAX_SAFE_INTEGER window', field: 'windowSeconds', value: '9007199254740991', runtimeRefused: null },
  { label: 'canonical key', field: 'destination', value: RECIPIENT.publicKey.toBase58(), runtimeRefused: null },
];

function grantFor(row) {
  return { ...GOOD, [row.field]: row.value };
}

// ---------------------------------------------------------------------------
// V3: the runtime's verdicts are the ORACLE for this test - if they were to
// change, the expectations below would be meaningless. Green on both trees.
// ---------------------------------------------------------------------------
test('V3 oracle: the runtime refuses every bad row and accepts every boundary row', () => {
  for (const row of TABLE) {
    assert.strictEqual(runtimeRefusal(grantFor(row)), row.runtimeRefused,
      `oracle drift for ${row.label}: ${row.field}=${row.value}`);
  }
});

// ---------------------------------------------------------------------------
// V1: the creation path refuses what the runtime refuses, and writes nothing.
// ---------------------------------------------------------------------------
test('V1 grant-add refuses every value the runtime refuses and writes no file', () => {
  const { validateTxGrantArgs } = require('../src/grantadd');
  for (const row of TABLE.filter((r) => r.runtimeRefused !== null)) {
    // Both surfaces must refuse: the module-level argument parser (so an
    // in-process caller cannot build a dead grant) AND the CLI.
    const rawArgs = {
      name: 'ops',
      signer: row.field === 'signer' ? row.value : GOOD.signer,
      destination: row.field === 'destination' ? row.value : GOOD.destination,
      maxLamports: row.field === 'maxLamports' ? row.value : GOOD.maxLamports,
      windowMaxLamports: row.field === 'windowMaxLamports' ? row.value : GOOD.windowMaxLamports,
      windowSeconds: row.field === 'windowSeconds' ? row.value : GOOD.windowSeconds,
      expiresAt: row.field === 'expiresAt' ? row.value : GOOD.expiresAt,
    };
    assert.throws(() => validateTxGrantArgs(rawArgs), /grant_field_invalid/,
      `validateTxGrantArgs must refuse ${row.label} (${row.field}=${row.value})`);

    const res = create(grantFor(row));
    assert.notStrictEqual(res.status, 0,
      `grant-add must refuse ${row.label} (${row.field}=${row.value}) but exited 0`);
    assert.strictEqual(res.wrote, false,
      `grant-add must not write a file for ${row.label}`);
    assert.match(res.firstLine, /^grant_field_invalid: /,
      `${row.label}: the refusal must be machine-readable, got: ${res.firstLine}`);
  }
});

// ---------------------------------------------------------------------------
// V4: the canonical boundaries still go through (guard, green on both trees).
// ---------------------------------------------------------------------------
test('V4 grant-add still accepts the canonical boundary values', () => {
  for (const row of TABLE.filter((r) => r.runtimeRefused === null)) {
    const res = create(grantFor(row));
    assert.strictEqual(res.status, 0,
      `grant-add must accept ${row.label} (${row.field}=${row.value}): ${res.stderr}`);
    assert.strictEqual(res.wrote, true, `${row.label}: the grant file must exist`);
  }
});

// ---------------------------------------------------------------------------
// V2: the loader refuses the same values, so a hand-edited file fails at
// load time instead of per request.
// ---------------------------------------------------------------------------
test('V2 the loader refuses every value the runtime refuses', () => {
  for (const row of TABLE.filter((r) => r.runtimeRefused !== null)) {
    const code = loadRefusal(grantFor(row));
    assert.match(String(code), /grant_field_invalid/,
      `the loader must refuse ${row.label} (${row.field}=${row.value}), got: ${code}`);
  }
});

test('V4 the loader still accepts the canonical boundary values', () => {
  for (const row of TABLE.filter((r) => r.runtimeRefused === null)) {
    assert.strictEqual(loadRefusal(grantFor(row)), null,
      `the loader must accept ${row.label} (${row.field}=${row.value})`);
  }
});

// ---------------------------------------------------------------------------
// V5: the house voice - the code appears EXACTLY ONCE and the refusal names
// a repair the CLI actually offers.
// ---------------------------------------------------------------------------
test('V5 a value refusal prints its code once and names a fix', () => {
  const row = TABLE.find((r) => r.field === 'expiresAt' && r.runtimeRefused !== null);
  const res = create(grantFor(row));
  assert.strictEqual(res.occurrences, 1,
    `the code must appear exactly once, got ${res.occurrences}: ${res.stderr}`);
  assert.strictEqual(res.hasFix, true,
    `the refusal must name a repair on a fix: line, got: ${res.stderr}`);
});

// ---------------------------------------------------------------------------
// V6: THE CONTRACT. For every row: what the CLI writes is what the loader
// reads is what the runtime signs. This is the falsifying assertion - one
// row where create says ok and gate says invalid_grant fails it.
// ---------------------------------------------------------------------------
test('V6 creation, load and runtime agree on every case in the table', () => {
  const rows = TABLE.map((row) => {
    const grant = grantFor(row);
    return {
      label: row.label,
      field: row.field,
      value: row.value,
      created: create(grant).status === 0,
      loaded: loadRefusal(grant) === null,
      runtimeAllowed: runtimeRefusal(grant) === null,
    };
  });

  for (const row of rows) {
    assert.strictEqual(row.created, row.runtimeAllowed,
      `contract broken for ${row.label} (${row.field}=${row.value}): ` +
      `create=${row.created} runtime=${row.runtimeAllowed}`);
    assert.strictEqual(row.created, row.loaded,
      `create/load disagree for ${row.label} (${row.field}=${row.value}): ` +
      `create=${row.created} load=${row.loaded}`);
  }

  // The measurement artifact must be reproducible from the table alone.
  assert.ok(rows.length >= 20, 'the table must stay broad enough to falsify');
});
