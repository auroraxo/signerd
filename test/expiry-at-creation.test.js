'use strict';

// AN EXPIRY ALREADY IN THE PAST MUST NOT BE WRITABLE (2026-11-11).
//
// WHAT THE CONTRACT IS: what the creation path writes must be a scope the
// daemon can honour AT LEAST ONCE. The window caps got this rule on
// 2026-11-09 (src/grantvalues.js, test/grant-cap-domain.test.js: a cap
// below the base fee is refused at creation, not saved as a dead scope).
// `expiresAt` is the same existence claim one axis over: a grant whose
// expiry is already past when it is written can NEVER sign — the runtime
// rule is `nowMs >= expiry -> refused('expired')` (src/policy.js,
// src/ledger.js), so every request against it dies, forever, and the
// scope cannot be repaired by waiting: unlike a window that refills, a
// past expiry only moves further away.
//
// WHY IT MATTERS (measured 2026-11-11 on the PUBLISHED v0.2.17 tree,
// tools/measure-expiry-at-creation.js):
//   F1 `grant-add --expires 2020-01-01T00:00:00Z` exited 0 with
//      {"ok":true,...} and wrote the file; the FIRST request came back
//      {"ok":false,"error":"expired"}. A mistyped year (2020 for 2030) or
//      a copy of an old example manufactures a scope the operator believes
//      is live; the ok:true is the lie.
//   F2 `grant-add --append` with a past expiry appended the dead scope
//      into an existing LIVE grant file with ok:true — the dead grant
//      rides next to the working ones and is invisible in `status`.
//   F3 the refusal voice: `grant_field_invalid` already names repairs per
//      field; a past expiry has its own reason now, so an operator (or a
//      script) can tell "the shape is wrong" from "the shape is fine but
//      the moment already passed" — and the fix line says which one.
//
// THE RULES THIS PINS:
//   E1 grant-add REFUSES a past expiry (clearly past) with
//      grant_expired_at_creation, writes NO file, exit 1.
//   E2 grant-add --append REFUSES the same and leaves the existing file
//      byte-identical.
//   E3 validateTxGrantArgs / validateMessageGrantArgs (the library faces
//      the bootstrap uses) throw grant_expired_at_creation; an expiry
//      equal to the present instant is refused too — the runtime rule is
//      `now >= expiry`, so "expiring now" is already dead on arrival.
//   E4 the refusal voice: the code appears exactly once, names the value,
//      and carries a `fix:` line that speaks about the future.
//   G1 (guard, green on both trees) a future expiry still writes and
//      signs end-to-end — the fix must not over-tighten.
//   G2 (guard, green on both trees) a NON-canonical expiry keeps its
//      ORIGINAL reason grant_field_invalid: the liveness check runs after
//      the shape check, it does not replace it. (An impossible date like
//      2030-02-31 is future-shaped; the first check must stay the one the
//      value-contract pinned on 2026-11-08.)
//   G3 (guard, green on both trees) an ALREADY-EXPIRED grant that is
//      already in a file still LOADS, and the runtime still refuses per
//      request with `expired`: the loader must NOT gain a past-expiry
//      refusal. Every live grant expires someday; refusing expiry at load
//      time would brick the daemon the morning after a grant's deadline —
//      for the whole file, all other scopes included. The creation path
//      is the only place where "would never sign" can be told apart from
//      "has not yet expired to sign".
//
// The ladder: E1-E4 are RED on the pre-fix tree (published v0.2.17);
// G1-G3 are GREEN on both.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { validateTxGrantArgs, validateMessageGrantArgs, writeGrantFile } = require('../src/grantadd');
const { loadGrantFile } = require('../src/grantfile');
const { Ledger, gate } = require('../src/ledger');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');

const PAYER = Keypair.generate();
const RECIPIENT = Keypair.generate();

function tmpDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function txGrant(overrides = {}) {
  return {
    name: 'ops',
    signer: PAYER.publicKey.toBase58(),
    destination: RECIPIENT.publicKey.toBase58(),
    maxLamports: '1000000',
    windowMaxLamports: '1000000',
    windowSeconds: '3600',
    expiresAt: '2099-01-01T00:00:00Z',
    ...overrides,
  };
}

function messageGrant(overrides = {}) {
  return {
    name: 'releases',
    issuer: 'acme',
    type: 'release',
    subject: 'acme/app',
    pubkey: require('node:crypto').randomBytes(32).toString('base64'),
    maxBytes: '700',
    windowMaxMessages: '5',
    windowSeconds: '3600',
    expiresAt: '2099-01-01T00:00:00Z',
    ...overrides,
  };
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
}

function grantAddArgs(file, overrides = {}) {
  const g = txGrant(overrides);
  return ['grant-add', '--grants', file, '--name', g.name,
    '--signer', g.signer, '--destination', g.destination,
    '--max-lamports', g.maxLamports, '--window-max-lamports', g.windowMaxLamports,
    '--window-seconds', g.windowSeconds, '--expires', g.expiresAt];
}

// E1: the create path refuses a clearly-past expiry and writes nothing.
test('E1 grant-add refuses a past --expires with grant_expired_at_creation and writes NO file', () => {
  const dir = tmpDir('signerd-eac-e1');
  const file = path.join(dir, 'grants.json');
  const res = runCli(grantAddArgs(file, { expiresAt: '2020-01-01T00:00:00Z' }));
  assert.notStrictEqual(res.status, 0, `grant-add accepted a dead-on-arrival expiry: ${res.stdout}`);
  assert.match(res.stderr, /grant_expired_at_creation/, 'refusal must carry its own code');
  assert.ok(!fs.existsSync(file), 'a refusal must leave no file behind');
});

// E2: --append refuses too, and the existing file stays byte-identical.
test('E2 grant-add --append refuses a past expiry and leaves the existing file untouched', () => {
  const dir = tmpDir('signerd-eac-e2');
  const file = path.join(dir, 'grants.json');
  const good = runCli(grantAddArgs(file));
  assert.strictEqual(good.status, 0, good.stderr);
  const before = fs.readFileSync(file, 'utf8');
  const res = runCli([...grantAddArgs(file, {
    name: 'dead', expiresAt: '2021-06-30T23:59:59Z',
  }), '--append']);
  assert.notStrictEqual(res.status, 0, `--append accepted a dead scope into a live file: ${res.stdout}`);
  assert.match(res.stderr, /grant_expired_at_creation/);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), before,
    'the refusal must not touch the existing bytes');

  // Direct library face: extendGrantFile({ file, name, grant }) called
  // with a pre-validated grant object must STILL assert liveness — the CLI
  // parses the grant through buildTxGrant first, but a caller using the
  // library face directly must not be able to bypass the check.
  const { extendGrantFile } = require('../src/grantadd');
  assert.throws(() => extendGrantFile({
    file, name: 'direct-dead',
    grant: {
      signer: PAYER.publicKey.toBase58(), destination: RECIPIENT.publicKey.toBase58(),
      maxLamports: '1000000', windowMaxLamports: '1000000', windowSeconds: '3600',
      expiresAt: '2020-01-01T00:00:00Z',
    },
  }), (err) => err.code === 'grant_expired_at_creation', 'extendGrantFile must refuse a dead grant directly');
});

// E3: both library faces (the ones sign-message --add-grant and scripts use)
// throw the same code; "expiring now" counts as past (runtime rule >=).
test('E3 validateTxGrantArgs/validateMessageGrantArgs refuse a past or present expiry', () => {
  const g = txGrant({ expiresAt: '2020-01-01T00:00:00Z' });
  assert.throws(() => validateTxGrantArgs(g), (err) => err.code === 'grant_expired_at_creation');
  const m = messageGrant({ expiresAt: '2020-01-01T00:00:00Z' });
  assert.throws(() => validateMessageGrantArgs(m), (err) => err.code === 'grant_expired_at_creation');

  // The boundary instant: expiry DENOTES exactly `now`. The runtime rule is
  // `nowMs >= expiry -> expired`, so an instant denoted equal to now is
  // already dead on arrival and must refuse.
  const { isFutureExpiry } = require('../src/grantvalues');
  const exactInstant = '2030-01-01T00:00:00.000Z';
  const exactNow = Date.parse(exactInstant);
  assert.strictEqual(isFutureExpiry(exactInstant, exactNow), false,
    'an instant equal to now must NOT be judged future (>= would accept it)');
  assert.strictEqual(isFutureExpiry(exactInstant, exactNow - 1), true,
    'an instant 1ms in the future is accepted');
  assert.strictEqual(isFutureExpiry(exactInstant, exactNow + 1), false,
    'an instant 1ms in the past is refused');

  // writeGrantFile is a library face too: the validator is the judge.
  const dir = tmpDir('signerd-eac-e3');
  assert.throws(() => writeGrantFile({
    file: path.join(dir, 'grants.json'), name: 'ops',
    grant: {
      signer: g.signer, destination: g.destination, maxLamports: g.maxLamports,
      windowMaxLamports: g.windowMaxLamports, windowSeconds: g.windowSeconds,
      expiresAt: '2020-01-01T00:00:00Z',
    },
  }), (err) => err.code === 'grant_expired_at_creation');

  // addGrantToFile (the sign-message --add-grant bootstrap face) too — the
  // CLI builds the grant through buildMessageGrant (which validates), but a
  // direct library caller must not bypass the liveness guard.
  const { addGrantToFile } = require('../src/grantadd');
  const dir2 = tmpDir('signerd-eac-e3b');
  const file2 = path.join(dir2, 'grants.json');
  assert.throws(() => addGrantToFile({
    file: file2, name: 'releases',
    grant: {
      kind: 'message', issuer: 'acme', type: 'release', subject: 'acme/app',
      pubkey: require('node:crypto').randomBytes(32).toString('base64'),
      maxBytes: '700', windowMaxMessages: '5', windowSeconds: '3600',
      expiresAt: '2020-01-01T00:00:00Z',
    },
  }), (err) => err.code === 'grant_expired_at_creation');
  assert.ok(!fs.existsSync(file2), 'the bootstrap refusal writes nothing');

  // E3c: addGrantToFile against an EXISTING live file — the append face of
  // the bootstrap. A mutation that drops the guard HERE (while the create
  // face keeps it) must still be caught: the dead message grant must not
  // ride into a live file, and the live bytes must not change.
  const good0 = runCli(grantAddArgs(file2));
  assert.strictEqual(good0.status, 0, good0.stderr);
  const before2 = fs.readFileSync(file2, 'utf8');
  assert.throws(() => addGrantToFile({
    file: file2, name: 'releases2',
    grant: {
      kind: 'message', issuer: 'acme', type: 'release', subject: 'acme/app',
      pubkey: require('node:crypto').randomBytes(32).toString('base64'),
      maxBytes: '700', windowMaxMessages: '5', windowSeconds: '3600',
      expiresAt: '2020-01-01T00:00:00Z',
    },
  }), (err) => err.code === 'grant_expired_at_creation',
    'addGrantToFile must refuse against an existing file too');
  assert.strictEqual(fs.readFileSync(file2, 'utf8'), before2,
    'the refusal must leave the live file byte-identical');
});

// E4: the voice — code exactly once, names the value, carries a fix.
test('E4 the refusal voice: code once, value named, a fix line about the future', () => {
  const dir = tmpDir('signerd-eac-e4');
  const file = path.join(dir, 'grants.json');
  const res = runCli(grantAddArgs(file, { expiresAt: '2020-01-01T00:00:00Z' }));
  const stderr = res.stderr;
  const occurrences = (stderr.match(/grant_expired_at_creation/g) || []).length;
  assert.strictEqual(occurrences, 1, `the code must appear exactly once, saw ${occurrences}:\n${stderr}`);
  assert.match(stderr, /2020-01-01T00:00:00Z/, 'the refusal must name the offending value');
  assert.match(stderr, /^\s*fix:.*future/im, `the refusal must name a repair about the future:\n${stderr}`);
});

// G1: a future expiry keeps working end-to-end (guard, green on both trees).
test('G1 guard: a future expiry writes, loads, and the runtime approves', () => {
  const dir = tmpDir('signerd-eac-g1');
  const file = path.join(dir, 'grants.json');
  const res = runCli(grantAddArgs(file, { expiresAt: '2099-01-01T00:00:00Z' }));
  assert.strictEqual(res.status, 0, res.stderr);
  const loaded = loadGrantFile(file);
  assert.deepEqual(loaded.names, ['ops']);
  // The runtime signs the cheapest real request: amount 0.
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports: 0 }));
  tx.sign(PAYER);
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file: ledgerFile });
  const grant = loaded.grants.ops;
  const verdict = gate(tx.serialize(), grant, new Date(), ledger);
  assert.strictEqual(verdict.allowed, true, JSON.stringify(verdict));
});

// G2: a non-canonical expiry keeps its ORIGINAL reason (order preserved).
test('G2 guard: an impossible date is still grant_field_invalid, not the new code', () => {
  const dir = tmpDir('signerd-eac-g2');
  const file = path.join(dir, 'grants.json');
  const res = runCli(grantAddArgs(file, { expiresAt: '2030-02-31T00:00:00Z' }));
  assert.notStrictEqual(res.status, 0);
  assert.match(res.stderr, /grant_field_invalid/, 'the shape rule must win first');
  assert.doesNotMatch(res.stderr, /grant_expired_at_creation/,
    'a value that is not a real instant must not be re-labelled a liveness refusal');
});

// G3: an already-expired grant in an EXISTING file still loads and still
// refuses per request with `expired` — the loader must NOT gain the rule.
test('G3 guard: a hand-edited expired grant still loads; the runtime refuses it by name', () => {
  const dir = tmpDir('signerd-eac-g3');
  const file = path.join(dir, 'grants.json');
  fs.writeFileSync(file, JSON.stringify({
    version: 1,
    grants: {
      yesterday: {
        signer: PAYER.publicKey.toBase58(), destination: RECIPIENT.publicKey.toBase58(),
        maxLamports: '1000000', windowMaxLamports: '1000000', windowSeconds: '3600',
        expiresAt: '2020-01-01T00:00:00Z',
      },
      tomorrow: {
        signer: PAYER.publicKey.toBase58(), destination: RECIPIENT.publicKey.toBase58(),
        maxLamports: '1000000', windowMaxLamports: '1000000', windowSeconds: '3600',
        expiresAt: '2099-01-01T00:00:00Z',
      },
    },
  }, null, 2) + '\n', { mode: 0o600 });
  let loaded = null;
  assert.doesNotThrow(() => { loaded = loadGrantFile(file); },
    'the loader must not refuse a whole file because one grant expired — every live grant expires someday');
  assert.deepEqual(loaded.names, ['tomorrow', 'yesterday']);
  const tx = new Transaction();
  tx.feePayer = PAYER.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT.publicKey, lamports: 0 }));
  tx.sign(PAYER);
  const ledger = new Ledger({ file: path.join(dir, 'journal.jsonl') });
  const dead = gate(tx.serialize(), loaded.grants.yesterday, new Date(), ledger);
  assert.strictEqual(dead.allowed, false);
  assert.strictEqual(dead.refused, 'expired', 'the per-request refusal by name stays the runtime contract');
  const live = gate(tx.serialize(), loaded.grants.tomorrow, new Date(), new Ledger({ file: path.join(dir, 'journal2.jsonl') }));
  assert.strictEqual(live.allowed, true, 'the live scope in the same file must be untouched by the dead one');
});
