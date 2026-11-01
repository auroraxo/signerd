'use strict';

// R4-2: the journal has the same open-write-handle hole R4-1 closed for the
// grant file.
//
// The grant file is re-read on every request, so a surviving descriptor was
// caught there (R4-1). The JOURNAL was still read with fs.readFileSync: a
// process that opened it for writing while it was writable keeps writing
// through the descriptor after chmod, and neither the mode bits nor a fresh
// stat say so. The bytes the daemon then trusts for the replay set, the spend
// budget and the hash chain are not the bytes on disk it thinks it read.
//
// Every test here FAILS against the pre-fix tree: there the journal is
// believed unconditionally, so "refused with ledger_held_writer" is the
// assertion that separates the trees.

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');

const { Ledger, gate } = require('../src/ledger');
const { migrateJournal } = require('../src/migrate');

const signer = Keypair.generate();
const recipient = Keypair.generate().publicKey;
const now = new Date('2026-10-30T10:00:00.000Z');
const grant = {
  signer: signer.publicKey.toBase58(),
  destination: recipient.toBase58(),
  maxLamports: '1000000',
  expiresAt: '2099-01-01T00:00:00Z',
  windowMaxLamports: '100000000',
  windowSeconds: '3600',
};

function transfer(to = recipient, lamports = 42) {
  return SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: to, lamports });
}
function wire() {
  const tx = new Transaction();
  tx.feePayer = signer.publicKey;
  // A fresh blockhash per call: each approval in these tests must be a
  // DISTINCT message, so the replay check never fires before the check under
  // test does.
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(transfer());
  tx.sign(signer); // disposable test key; policy does not verify signatures
  return tx.serialize();
}
function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r42-'));
}
/** A journal that exists and holds exactly one approval. */
function seededJournal() {
  const dir = tmpDir();
  const file = path.join(dir, 'journal.jsonl');
  const ledger = new Ledger({ file });
  const verdict = gate(wire(), grant, now, ledger);
  assert.equal(verdict.allowed, true, 'seed approval must succeed');
  return { dir, file };
}

/**
 * Hold `file` open with the given access mode until the returned stop() runs.
 * `mode` is 'r' (read) or 'w' (write).
 *
 * Same protocol as test/r4-1.test.js, and for the same reason: signalling
 * cannot reach a descriptor owned by another uid, so the holder releases
 * itself when a flag file appears. The holder has a hard self-timeout, so a
 * failed stop() can never keep the suite alive.
 */
function hold(file, mode, uid) {
  const access = mode === 'w' ? 'os.O_RDWR' : 'os.O_RDONLY';
  const release = `${file}.release`;
  const code = [
    'import os,time',
    `fd=os.open(${JSON.stringify(file)}, ${access})`,
    `release=${JSON.stringify(release)}`,
    "print('held',flush=True)",
    'deadline=time.time()+30',
    'while not os.path.exists(release) and time.time()<deadline:',
    '    time.sleep(0.02)',
  ].join('\n');
  const argv = uid === 'root'
    ? ['sudo', '-n', 'python3', '-c', code]
    : ['python3', '-c', code];
  const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });

  let isReady = false;
  let readyResolve = null;
  let readyReject = null;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const timer = setTimeout(() => readyReject(new Error('holder did not open the file')), 15000);
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d.toString();
    if (buf.includes('held') && !isReady) {
      isReady = true;
      clearTimeout(timer);
      readyResolve();
    }
  });
  child.on('error', (err) => {
    clearTimeout(timer);
    if (!isReady) readyReject(err);
  });
  child.on('exit', (code2) => {
    clearTimeout(timer);
    if (!isReady) readyReject(new Error(`holder exited early: ${code2}`));
  });

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    try {
      fs.writeFileSync(release, 'go');
    } catch { /* the wait below still terminates */ }
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      child.once('exit', resolve);
      setTimeout(resolve, 5000);
    });
    try {
      fs.unlinkSync(release);
    } catch { /* already gone */ }
  };
  return { ready, stop };
}

test('R4-2: a journal held open for WRITING is refused at load', async () => {
  const { file } = seededJournal();
  const holder = hold(file, 'w');
  try {
    await holder.ready;
    // The mode is 0600, the owner is ours and the chain hashes verify. Only
    // the open write handle makes these bytes untrustworthy.
    assert.throws(() => new Ledger({ file }), /ledger_held_writer/,
      'a journal with an open write handle must not be loaded');
  } finally {
    await holder.stop();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test('R4-2: a journal held open for READING is still loaded and usable', async () => {
  const { file } = seededJournal();
  const holder = hold(file, 'r');
  try {
    await holder.ready;
    // The false-positive guard: a reader cannot alter the replay set. If this
    // failed, every `signerd status` or journal inspection would brick the
    // daemon for as long as somebody looked at the file.
    const ledger = new Ledger({ file });
    assert.equal(ledger.snapshot().records, 1);
    const verdict = gate(wire(), grant, new Date('2026-10-30T10:00:01.000Z'), ledger);
    assert.equal(verdict.allowed, true, 'approvals must work while a reader holds the journal');
  } finally {
    await holder.stop();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test('R4-2: an approval is refused while a writer holds the journal', async () => {
  const { file } = seededJournal();
  const ledger = new Ledger({ file });
  const holder = hold(file, 'w');
  try {
    await holder.ready;
    // The ledger was constructed BEFORE the writer appeared - the load check
    // cannot be what catches this. The append path must re-check, because it
    // is the step that decides the file still holds the state it vouches for.
    const verdict = gate(wire(), grant, new Date('2026-10-30T10:00:02.000Z'), ledger);
    assert.equal(verdict.allowed, false,
      'the ledger must refuse to append into a file somebody else has open for writing');
    assert.equal(verdict.refused, 'ledger_held_writer',
      `expected ledger_held_writer, got ${verdict.refused}`);
    // Nothing was recorded: the in-memory state must match the file.
    assert.equal(ledger.snapshot().records, 1, 'a refused append must record nothing');
    const after = fs.readFileSync(file, 'utf8');
    assert.equal(after.trimEnd().split('\n').length, 1, 'the file must be unchanged too');
  } finally {
    await holder.stop();
  }
  // No permanent poisoning: the refusal reflects the CURRENT state.
  const verdict = gate(wire(), grant, new Date('2026-10-30T10:00:03.000Z'), ledger);
  assert.equal(verdict.allowed, true, 'the same ledger must work once the writer leaves');
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
});

test('R4-2: once the writer is gone, the same journal loads again', async () => {
  const { file } = seededJournal();
  const holder = hold(file, 'w');
  try {
    await holder.ready;
    assert.throws(() => new Ledger({ file }), /ledger_held_writer/);
  } finally {
    await holder.stop();
  }
  const ledger = new Ledger({ file });
  assert.equal(ledger.snapshot().records, 1);
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
});

test('R4-2: the load check is a point-in-time observation, not a cached verdict', async () => {
  // R4-1's /proc-scan variant cached its verdict, so a writer that appeared
  // after the first scan was invisible for the process's lifetime. The lease
  // is taken on every call, so the verdict must follow the CURRENT state.
  const { file } = seededJournal();
  assert.equal(new Ledger({ file }).snapshot().records, 1);

  const holder = hold(file, 'w');
  try {
    await holder.ready;
    assert.throws(() => new Ledger({ file }), /ledger_held_writer/,
      'a writer that appears after a successful load must be caught');
  } finally {
    await holder.stop();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test('R4-2: the write handle is detected for a FOREIGN uid too', async (t) => {
  // A /proc scan cannot see a foreign uid's fd table; the kernel decides
  // leases for every uid, which is the whole reason R4-1 shipped a lease.
  const probe = spawn('sudo', ['-n', 'true'], { stdio: 'ignore' });
  const ok = await new Promise((resolve) => {
    probe.on('error', () => resolve(false));
    probe.on('exit', (code) => resolve(code === 0));
  });
  if (!ok) {
    t.skip('sudo not available: cannot create a foreign-uid holder');
    return;
  }

  const { file } = seededJournal();
  const holder = hold(file, 'w', 'root');
  try {
    await holder.ready;
    assert.throws(() => new Ledger({ file }), /ledger_held_writer/,
      'a foreign-uid writer must be detected - a /proc scan cannot see it');
  } finally {
    await holder.stop();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test('R4-2: migration refuses to rewrite a journal somebody holds open', async (t) => {
  // The migration reads the journal and then renames a replacement over it.
  // If a writer is holding the file, that rename replaces the file the writer
  // is editing with a stale copy - spend records vanish.
  const { file } = seededJournal();
  // A format-1 fixture makes this a REAL migration: without the holder the
  // run migrates and reports migrated:true, so the assertion below cannot be
  // satisfied by an unrelated precondition failure.
  const fixture = path.join(__dirname, 'fixtures', 'format1-ledger.jsonl');
  fs.copyFileSync(fixture, file);
  fs.chmodSync(file, 0o600);

  const holder = hold(file, 'w');
  try {
    await holder.ready;
    assert.throws(() => migrateJournal({ file, discardLegacy: true }), /ledger_held_writer/,
      'migrating a journal with an open write handle must be refused');
  } finally {
    await holder.stop();
  }
  // And with the writer gone the migration still works - no permanent state.
  const result = migrateJournal({ file, discardLegacy: true });
  assert.equal(result.migrated, true, `migration must still run, got ${JSON.stringify(result)}`);
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
});
