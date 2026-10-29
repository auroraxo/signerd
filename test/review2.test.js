'use strict';

// Regression tests for the 29.10.2026 second adversarial review of the
// signing path (review #2, findings R2-1 .. R2-6). The suite was green before
// those findings existed: every test below fails against the code as reviewed
// and passes only after the corresponding fix.
//
//   R2-1  a failed start() / never-started stop() unlinks a LIVE daemon socket
//   R2-2  the replay set is keyed on the client-controlled signature slot
//   R2-3  the journal has no owner/mode/directory validation
//   R2-4  grant file edits (revocation) are never reloaded
//   R2-5  framing re-handles the first request on every later data event
//   R2-6  a JSON byte array is accepted where base64 is required

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { Keypair, SystemProgram, Transaction } = require('@solana/web3.js');
const { Daemon, request } = require('../src/daemon');
const { Ledger } = require('../src/ledger');
const { createKeystore, loadKeystore } = require('../src/keystore');
const { loadGrantFile } = require('../src/grantfile');

const PASSPHRASE = 'a passphrase for tests only';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-review2-'));
}

/** An expiry that moves with the clock, so this file never rots into a time bomb. */
function futureIso(hours = 24) {
  return new Date(Math.floor(Date.now() / 1000 + hours * 3600) * 1000).toISOString();
}

function grantFor(signer, destination, overrides = {}) {
  return {
    signer,
    destination,
    maxLamports: '42',
    expiresAt: futureIso(),
    windowMaxLamports: '100000',
    windowSeconds: '3600',
    ...overrides,
  };
}

async function fixture({ grants: names = ['ops'], start = true } = {}) {
  const dir = tmpDir();
  const recipient = Keypair.generate().publicKey;
  const keystore = path.join(dir, 'ops.key');
  const created = createKeystore({ file: keystore, passphrase: PASSPHRASE });
  const keypair = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  const grantFile = path.join(dir, 'grants.json');
  const grants = {};
  for (const name of names) grants[name] = grantFor(created.publicKey, recipient.toBase58());
  fs.writeFileSync(grantFile, JSON.stringify({ version: 1, grants }, null, 2));
  const socketPath = path.join(dir, 'signerd.sock');
  const ledgerFile = path.join(dir, 'journal.jsonl');
  const make = (overrides = {}) => new Daemon({
    socketPath,
    keystorePath: keystore,
    passphrase: PASSPHRASE,
    grantFile,
    ledgerFile,
    ...overrides,
  });
  const daemon = make();
  if (start) await daemon.start();
  return { dir, daemon, make, socketPath, keypair, recipient, grantFile, keystore, ledgerFile };
}

function wire(keypair, recipient, lamports = 42) {
  const tx = new Transaction();
  tx.feePayer = keypair.publicKey;
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.add(SystemProgram.transfer({ fromPubkey: keypair.publicKey, toPubkey: recipient, lamports }));
  tx.sign(keypair);
  return tx.serialize();
}

/** Read every newline-delimited response off a raw connection. */
function rawExchange(socketPath, payload, { afterResponse, halfOpen = false } = {}) {
  return new Promise((resolve, reject) => {
    // halfOpen keeps OUR write side open after the daemon's FIN, so a
    // follow-up frame can still be written - that is what makes the
    // "second request arrives in a LATER data event" case reachable.
    const socket = halfOpen
      ? net.connect({ path: socketPath, allowHalfOpen: true })
      : net.connect(socketPath);
    const lines = [];
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); resolve(lines); }, 4000);
    const flush = (isEnd) => {
      let nl;
      while ((nl = buf.indexOf(0x0a)) !== -1) {
        lines.push(JSON.parse(buf.subarray(0, nl).toString('utf8')));
        buf = buf.subarray(nl + 1);
      }
      if (isEnd) {
        clearTimeout(timer);
        resolve(lines);
      }
    };
    socket.on('connect', () => {
      socket.write(payload);
      if (afterResponse) {
        // Send the follow-up only once the daemon has answered the first
        // frame, so the two land in DIFFERENT 'data' events.
        const onData = () => {
          if (lines.length === 0) return;
          socket.removeListener('data', onData);
          afterResponse(socket);
        };
        socket.on('data', onData);
      }
    });
    socket.on('data', (chunk) => { buf = Buffer.concat([buf, chunk]); flush(false); });
    socket.on('close', () => { clearTimeout(timer); flush(true); });
    socket.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

// ---------------------------------------------------------------------------
// R2-1: socket path ownership
// ---------------------------------------------------------------------------

test('R2-1: a failed start() and a never-started stop() never unlink a LIVE daemon socket', async () => {
  const f = await fixture();
  try {
    assert.ok(fs.existsSync(f.socketPath));

    // (a) A second daemon with the SAME socket path but its own ledger must
    // fail to start, and must leave the running daemon's socket alone: that
    // path is how clients find the real daemon, and deleting it lets any
    // local process bind it and impersonate the signing daemon.
    const rival = f.make({ ledgerFile: path.join(f.dir, 'rival-journal.jsonl') });
    await assert.rejects(() => rival.start(), /socket_in_use/);
    assert.equal(fs.existsSync(f.socketPath), true,
      'a failed start() must not delete the live daemon socket');
    const afterFailedStart = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(afterFailedStart.ok, true, 'the original daemon must still answer');

    // (b) stop() on an instance that never started must not delete it either.
    const idle = f.make({ ledgerFile: path.join(f.dir, 'idle-journal.jsonl') });
    await idle.stop();
    assert.equal(fs.existsSync(f.socketPath), true,
      'stop() on a daemon that never started must not delete the live socket');
    const afterIdleStop = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(afterIdleStop.ok, true, 'the original daemon must still answer');
    assert.equal(idle.lockHeld, false);
    assert.equal(rival.lockHeld, false, 'a failed start() must give the lock back');
  } finally {
    await f.daemon.stop();
  }
  assert.equal(fs.existsSync(f.socketPath), false,
    'the owning daemon still removes its own socket on shutdown');
});

// ---------------------------------------------------------------------------
// R2-1b: the socket path is a capability - nobody else may rebind it
// ---------------------------------------------------------------------------

test('R2-1b: the daemon refuses a socket directory another user can write', async () => {
  const f = await fixture({ start: false });
  // Every daemon this test creates is stopped in `finally`, so a FAILING run
  // (e.g. against pre-fix code, where the refusal does not happen) must not
  // leave a listening server behind and hang the runner.
  const started = [];
  try {
    const openDir = path.join(f.dir, 'open');
    fs.mkdirSync(openDir);
    const openSock = path.join(openDir, 'signerd.sock');

    // A stranger who can write this directory can unlink the socket file and
    // bind their own server at the documented path; clients that trust the
    // path would then believe a forged approval. Refuse to serve from there.
    fs.chmodSync(openDir, 0o777);
    const refused = f.make({ socketPath: openSock });
    // Registered BEFORE start(): against pre-fix code the start SUCCEEDS
    // (there is no directory check), and an un-registered daemon would keep
    // listening and hang the runner instead of failing the test.
    started.push(refused);
    await assert.rejects(() => refused.start(), /socket_dir_mode/,
      'a world-writable socket directory must be refused');
    assert.equal(fs.existsSync(openSock), false, 'nothing may be bound there');
    assert.equal(refused.lockHeld, false, 'a refused start must give the lock back');
    assert.equal(fs.existsSync(`${f.ledgerFile}.lock`), false);

    // A sticky directory is safe: only the file's own owner may unlink it.
    fs.chmodSync(openDir, 0o1777);
    await refused.start();
    assert.ok(fs.existsSync(openSock));
    assert.equal(fs.statSync(openSock).mode & 0o777, 0o600);
    const ok = await request({ socketPath: openSock, grant: 'ops', wire: wire(f.keypair, f.recipient) });
    assert.equal(ok.ok, true);
    await refused.stop();
    started.pop();
    assert.equal(fs.existsSync(openSock), false);
    fs.chmodSync(openDir, 0o700);

    // A directory owned by somebody else is refused even when its mode looks
    // safe: its owner can rearrange it regardless of what we see.
    const foreignDir = path.join(f.dir, 'foreign');
    fs.mkdirSync(foreignDir);
    fs.chmodSync(foreignDir, 0o700); // safe mode, foreign owner
    const foreignSock = path.join(foreignDir, 'signerd.sock');
    const realStatSync = fs.statSync;
    fs.statSync = function spoofedStat(dirLike, ...rest) {
      const stat = realStatSync.call(fs, dirLike, ...rest);
      if (typeof dirLike === 'string' && path.resolve(dirLike) === path.resolve(foreignDir)) {
        return Object.assign(Object.create(stat), { uid: stat.uid + 1 });
      }
      return stat;
    };
    try {
      const foreign = f.make({ socketPath: foreignSock });
      started.push(foreign);
      await assert.rejects(() => foreign.start(), /socket_dir_owner/,
        'a foreign-owned socket directory must be refused');
      assert.equal(foreign.lockHeld, false);
    } finally {
      fs.statSync = realStatSync;
    }
    assert.equal(fs.existsSync(`${f.ledgerFile}.lock`), false);
  } finally {
    for (const daemon of started) await daemon.stop().catch(() => { /* cleanup */ });
    await f.daemon.stop().catch(() => { /* never started */ });
  }
});

// ---------------------------------------------------------------------------
// R2-2: the replay identity is the MESSAGE, not the client's signature slot
// ---------------------------------------------------------------------------

test('R2-2: the same transaction message is approved once, whatever the signature slot holds', async () => {
  const f = await fixture();
  try {
    const base = wire(f.keypair, f.recipient, 10);
    // Two wires carrying ONE message: only the 64 client-controlled signature
    // bytes differ, and those are overwritten by the daemon anyway.
    const a = Buffer.from(base);
    const b = Buffer.from(base);
    for (let i = 1; i <= 64; i += 1) {
      a[i] = (a[i] + 1) & 0xff;
      b[i] = (b[i] + 2) & 0xff;
    }
    assert.equal(a.equals(b), false, 'the two wires must differ');
    assert.equal(a.subarray(65).equals(b.subarray(65)), true, 'but carry the same message');

    const first = await request({ socketPath: f.socketPath, grant: 'ops', wire: a });
    assert.equal(first.ok, true);
    assert.ok(first.signature);

    const second = await request({ socketPath: f.socketPath, grant: 'ops', wire: b });
    assert.equal(second.ok, false, 'the same message must not be approved twice');
    assert.equal(second.error, 'replay');

    // The artifact the daemon returned carries the SAME message: handing it
    // back must not buy a second approval either.
    const signed = Buffer.from(first.signed, 'base64');
    const resubmitted = await request({ socketPath: f.socketPath, grant: 'ops', wire: signed });
    assert.equal(resubmitted.ok, false, 'the signed artifact must be replay, not a new approval');
    assert.equal(resubmitted.error, 'replay');

    // Exactly one approval was made - no budget was charged twice.
    const records = f.daemon.ledger.snapshot().records;
    assert.equal(records, 1, 'only the first approval may enter the journal');

    // The journal must carry the message identity, not only the wire bytes.
    const line = JSON.parse(fs.readFileSync(f.ledgerFile, 'utf8').trim().split('\n')[0]);
    assert.equal(line.v, 2, 'the journal must be written in format 2');
    assert.match(line.m, /^[0-9a-f]{64}$/);
    assert.equal(line.w, require('node:crypto').createHash('sha256').update(a).digest('hex'));
    assert.equal(line.m, require('node:crypto').createHash('sha256').update(a.subarray(65)).digest('hex'));

    await f.daemon.stop();

    // Message-level replay must survive a restart: the identity lives in the
    // journal, not in process memory.
    const restarted = f.make();
    await restarted.start();
    try {
      for (const candidate of [b, signed, a]) {
        const again = await request({ socketPath: f.socketPath, grant: 'ops', wire: candidate });
        assert.equal(again.ok, false, 'replay protection must survive a restart');
        assert.equal(again.error, 'replay');
      }
      // A genuinely different message still gets signed after the restart.
      const fresh = await request({
        socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient, 11),
      });
      assert.equal(fresh.ok, true);
      assert.equal(fresh.messageSha256, fresh.signed
        ? require('node:crypto').createHash('sha256')
          .update(Buffer.from(fresh.signed, 'base64').subarray(65)).digest('hex')
        : null, 'the reported message identity must describe the returned artifact');
    } finally {
      await restarted.stop();
    }
  } finally {
    if (f.daemon.started) await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// R2-3: the journal is the replay set - only trust a journal nobody else can write
// ---------------------------------------------------------------------------

test('R2-3: the journal is refused when another user could write it, and refused when it is not ours', () => {
  const dir = tmpDir();

  // (a) group/other WRITABLE file: somebody else could truncate it, emptying
  // the replay set and the window budget.
  const writable = path.join(dir, 'writable.jsonl');
  fs.writeFileSync(writable, '');
  fs.chmodSync(writable, 0o666);
  assert.throws(() => new Ledger({ file: writable }), /ledger_mode/,
    'a world-writable journal must be refused, never adopted');

  // (b) owned but group readable: only a leak, so it is repaired, not refused.
  const leaky = path.join(dir, 'leaky.jsonl');
  fs.writeFileSync(leaky, '');
  fs.chmodSync(leaky, 0o644);
  const repaired = new Ledger({ file: leaky });
  assert.equal(fs.statSync(leaky).mode & 0o777, 0o600,
    'an owned readable journal must be tightened instead of bricking the daemon');
  assert.deepEqual(repaired.snapshot(), { records: 0, seq: 0, fingerprints: 0 });

  // (c) a directory a stranger can write: the journal itself can be replaced
  // by path before it is ever read. A sticky directory is fine.
  const open = path.join(dir, 'open');
  fs.mkdirSync(open);
  const inOpen = path.join(open, 'journal.jsonl');
  fs.writeFileSync(inOpen, '');
  fs.chmodSync(inOpen, 0o600);
  fs.chmodSync(open, 0o777);
  assert.throws(() => new Ledger({ file: inOpen }), /ledger_dir_mode/,
    'a world-writable directory must be refused');
  fs.chmodSync(open, 0o1777); // sticky: only the owner may unlink
  assert.doesNotThrow(() => new Ledger({ file: inOpen }));
  fs.chmodSync(open, 0o700);

  // (d) a foreign-owned journal, even with perfect permissions: its owner can
  // rewrite it at will, and the chain hash is unkeyed sha256, so a forged
  // journal validates as its own.
  const foreign = path.join(dir, 'foreign.jsonl');
  fs.writeFileSync(foreign, '');
  fs.chmodSync(foreign, 0o600);
  const realLstatSync = fs.lstatSync;
  fs.lstatSync = function spoofedLstat(fileLike, ...rest) {
    const stat = realLstatSync.call(fs, fileLike, ...rest);
    if (typeof fileLike === 'string' && path.resolve(fileLike) === path.resolve(foreign)) {
      return Object.assign(Object.create(stat), { uid: stat.uid + 1 });
    }
    return stat;
  };
  try {
    assert.throws(() => new Ledger({ file: foreign }), /ledger_owner/,
      'a foreign-owned journal must be refused');
  } finally {
    fs.lstatSync = realLstatSync;
  }

  // (e) a symlink is not a journal: whoever controls the link controls the
  // replay set, and we would be trusting a path we do not own.
  const target = path.join(dir, 'target.jsonl');
  fs.writeFileSync(target, '');
  fs.chmodSync(target, 0o600);
  const link = path.join(dir, 'link.jsonl');
  fs.symlinkSync(target, link);
  assert.throws(() => new Ledger({ file: link }), /ledger_not_a_file/,
    'a symlinked journal must be refused');

  // And the happy path in the same directory still works.
  assert.doesNotThrow(() => new Ledger({ file: path.join(dir, 'journal.jsonl') }));
});

test('R2-3b: the grant file is refused when its path can be rewritten by a stranger', () => {
  const dir = tmpDir();
  const file = path.join(dir, 'grants.json');
  const doc = { version: 1, grants: { ops: grantFor('1'.repeat(44), 'So11111111111111111111111111111111111111112') } };
  fs.writeFileSync(file, JSON.stringify(doc));

  // The grant file decides what may be signed and is re-read on EVERY request,
  // so a directory a stranger can write is exactly as fatal as for the journal.
  fs.chmodSync(dir, 0o777);
  assert.throws(() => loadGrantFile(file), /grant_file_dir_mode/,
    'a grant file in a world-writable directory must be refused');
  fs.chmodSync(dir, 0o700);

  // A writable grant file is repaired (we own it) instead of adopted:
  // if the repair cannot happen it must fail closed.
  fs.chmodSync(file, 0o666);
  assert.doesNotThrow(() => loadGrantFile(file));
  assert.equal(fs.statSync(file).mode & 0o022, 0, 'a writable grant file must be tightened');

  // A symlink at that path can be redirected between two requests.
  const link = path.join(dir, 'grants-link.json');
  fs.symlinkSync(file, link);
  assert.throws(() => loadGrantFile(link), /grant_file_invalid/);
});

// ---------------------------------------------------------------------------
// R2-4: revocation takes effect immediately
// ---------------------------------------------------------------------------

test('R2-4: a grant file edit is honoured on the very next request, without a restart', async () => {
  const f = await fixture();
  try {
    const before = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(before.ok, true);

    // Operator revokes 'ops' and adds 'ops2' in one edit.
    const doc = {
      version: 1,
      grants: { ops2: grantFor(f.keypair.publicKey.toBase58(), f.recipient.toBase58()) },
    };
    fs.writeFileSync(f.grantFile, JSON.stringify(doc, null, 2));

    const revoked = await request({
      socketPath: f.socketPath, grant: 'ops', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(revoked.ok, false, 'a revoked grant must stop working immediately');
    assert.equal(revoked.error, 'grant_not_found');

    const added = await request({
      socketPath: f.socketPath, grant: 'ops2', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(added.ok, true, 'a newly written grant must work without a restart');
    assert.equal(f.daemon.grantNames.includes('ops'), false);

    // A broken grant file fails CLOSED: every request is refused until the
    // operator fixes it, instead of falling back to the grants cached at
    // startup (which would make revocation unrevokable).
    fs.writeFileSync(f.grantFile, '{ not json');
    const broken = await request({
      socketPath: f.socketPath, grant: 'ops2', wire: wire(f.keypair, f.recipient),
    });
    assert.equal(broken.ok, false, 'an invalid grant file must refuse every request');
    assert.match(String(broken.error), /grant_file/);
    assert.equal(f.daemon.ledger.snapshot().records, 2,
      'no budget may be consumed while the grant file is invalid');
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// R2-5: one request per connection, framed once, never re-handled
// ---------------------------------------------------------------------------

test('R2-5: a second request on one connection is refused before it can spend budget', async () => {
  const f = await fixture();
  try {
    const wireA = wire(f.keypair, f.recipient, 10);
    const wireB = wire(f.keypair, f.recipient, 20);
    const payload =
      JSON.stringify({ grant: 'ops', wire: wireA.toString('base64') }) + '\n' +
      JSON.stringify({ grant: 'ops', wire: wireB.toString('base64') }) + '\n';

    const responses = await rawExchange(f.socketPath, payload);
    assert.equal(responses.length, 2, 'the client must get an answer for each frame');
    assert.equal(responses[0].ok, true, 'the first request is served');
    assert.equal(responses[1].ok, false, 'the second is refused');
    assert.equal(responses[1].error, 'one_request_per_connection');
    assert.equal(f.daemon.ledger.snapshot().records, 1,
      'only the first request may consume budget');

    // Now the other framing: the second request arrives in a LATER data event
    // (after the daemon answered). It must be dropped, not handled - and the
    // first request must not be handled a second time either.
    const before = f.daemon.ledger.snapshot().records;
    const wireC = wire(f.keypair, f.recipient, 30);
    const late = await rawExchange(
      f.socketPath,
      JSON.stringify({ grant: 'ops', wire: wireC.toString('base64') }) + '\n',
      { halfOpen: true, afterResponse: (socket) => {
        setTimeout(() => socket.write(
          JSON.stringify({ grant: 'ops', wire: wireA.toString('base64') }) + '\n'), 30);
      } },
    );
    const ok = late.filter((r) => r.ok === true);
    assert.equal(ok.length, 1, 'exactly one approval per connection');
    // Give the daemon time to have handled (or dropped) the late frame.
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal(f.daemon.ledger.snapshot().records, before + 1,
      'a late second frame must not be journaled, and the first must not be re-handled');

    // wireA was consumed by the LATE exchange above and wireC by the same one;
    // the wire that was dropped must still be spendable on its own connection.
    const fresh = await request({ socketPath: f.socketPath, grant: 'ops', wire: wireB });
    assert.equal(fresh.ok, true);
  } finally {
    await f.daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// R2-6: the wire is a canonical base64 STRING
// ---------------------------------------------------------------------------

test('R2-6: a JSON byte array is not a wire: only a canonical base64 string is accepted', async () => {
  const f = await fixture();
  try {
    const w = wire(f.keypair, f.recipient, 15);

    const asArray = await rawExchange(f.socketPath,
      JSON.stringify({ grant: 'ops', wire: [...w] }) + '\n');
    assert.equal(asArray.length, 1);
    assert.equal(asArray[0].ok, false,
      'Buffer.from(array, "base64") ignores the encoding - it must not be treated as a wire');
    assert.equal(asArray[0].error, 'request_invalid');

    const asNumber = await rawExchange(f.socketPath,
      JSON.stringify({ grant: 'ops', wire: 7 }) + '\n');
    assert.equal(asNumber[0].error, 'request_invalid');

    // Lenient decoding must not smuggle non-base64 bytes past the format.
    const nonCanonical = await rawExchange(f.socketPath,
      JSON.stringify({ grant: 'ops', wire: `${w.toString('base64')}!!` }) + '\n');
    assert.equal(nonCanonical[0].error, 'request_invalid');

    const whitespace = await rawExchange(f.socketPath,
      JSON.stringify({ grant: 'ops', wire: `  ${w.toString('base64')}` }) + '\n');
    assert.equal(whitespace[0].error, 'request_invalid');

    assert.equal(f.daemon.ledger.snapshot().records, 0,
      'a refused wire must never consume budget');

    // The documented format still works.
    const ok = await request({ socketPath: f.socketPath, grant: 'ops', wire: w });
    assert.equal(ok.ok, true);
    assert.equal(f.daemon.ledger.snapshot().records, 1);
  } finally {
    await f.daemon.stop();
  }
});
