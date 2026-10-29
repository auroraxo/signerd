'use strict';

// Grant files and journals must not be group/other writable (R3-1); make the
// test writers owner-only instead of relying on the host umask.
process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { Keypair } = require('@solana/web3.js');
const { importKeystore, loadKeystore } = require('../src/keystore');
const { scanForPattern, scanIsComplete } = require('../scripts/memscan');

const PASSPHRASE = 'a passphrase for the user-zero test only';
const BIN = path.join(__dirname, '..', 'bin', 'signerd.js');
const CLIENT = path.join(__dirname, '..', 'examples', 'user-zero-client.js');

function tmpDir() {
  // mkdtempSync makes a 0700 directory, which the keystore loader accepts.
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-userzero-'));
}

/** Read a process's stdout until `predicate` matches one line. */
function waitForLine(child, predicate, timeoutMs = 15_000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => {
      child.stdout.removeListener('data', onData);
      reject(new Error(`timeout waiting for line; saw: ${buffer.slice(0, 400)}`));
    }, timeoutMs);
    function onData(chunk) {
      buffer += chunk;
      for (const line of buffer.split('\n')) {
        if (line && predicate(line)) {
          clearTimeout(timer);
          child.stdout.removeListener('data', onData);
          resolve(line);
          return;
        }
      }
    }
    child.stdout.on('data', onData);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`child exited early (${code}); saw: ${buffer.slice(0, 400)}`));
    });
  });
}

/**
 * Read a live child's stdout into a buffer and resolve the FIRST line.
 * The child is kept alive afterwards (used with --hold) so it can be scanned.
 */
function readFirstLine(child, timeoutMs = 15_000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`timeout; saw: ${buffer.slice(0, 400)}`)), timeoutMs);
    function onData(chunk) {
      buffer += chunk;
      const nl = buffer.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        child.stdout.removeListener('data', onData);
        // keep consuming so the child never blocks on a full pipe
        child.stdout.on('data', () => {});
        resolve(buffer.slice(0, nl));
      }
    }
    child.stdout.on('data', onData);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`child exited early (${code}); saw: ${buffer.slice(0, 400)}`));
    });
  });
}

function terminate(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGKILL');
}

/**
 * Environment for the measurement: an EXISTING plaintext key (the file a real
 * key-load site reads today), migrated into an encrypted keystore, plus a
 * running daemon and a grant covering one destination.
 */
function fixture() {
  const dir = tmpDir();
  const keypair = Keypair.generate();

  // The plaintext key file, exactly as solana-keygen writes it and exactly as
  // the 21 key-load sites read it: a JSON byte array.
  const source = path.join(dir, 'id.json');
  fs.writeFileSync(source, JSON.stringify(Array.from(keypair.secretKey)) + '\n', { mode: 0o600 });
  fs.chmodSync(source, 0o600);

  // Migrate it: this is the step that did not exist before.
  const keystore = path.join(dir, 'ops.key');
  const imported = importKeystore({ file: keystore, passphrase: PASSPHRASE, from: source });
  assert.equal(imported.publicKey, keypair.publicKey.toBase58(), 'import must preserve the public key');

  // The daemon's key must be the SAME key the plaintext file held, decrypted
  // back out of the keystore — otherwise migration silently swapped the key.
  const loaded = loadKeystore({ file: keystore, passphrase: PASSPHRASE });
  assert.equal(Buffer.from(loaded.secretKey).equals(Buffer.from(keypair.secretKey)), true);

  const destination = Keypair.generate().publicKey.toBase58();
  const grantFile = path.join(dir, 'grants.json');
  const expiresAt = new Date(Math.floor(Date.now() / 1000 + 3600) * 1000).toISOString();
  fs.writeFileSync(grantFile, JSON.stringify({
    version: 1,
    grants: {
      ops: {
        signer: keypair.publicKey.toBase58(),
        destination,
        maxLamports: '1000',
        expiresAt,
        windowMaxLamports: '1000000',
        windowSeconds: '3600',
      },
    },
  }, null, 2));

  const passphraseFile = path.join(dir, 'pass');
  fs.writeFileSync(passphraseFile, PASSPHRASE + '\n', { mode: 0o600 });
  fs.chmodSync(passphraseFile, 0o600);

  return {
    dir, keypair, source, keystore, grantFile, passphraseFile,
    destination,
    socketPath: path.join(dir, 'signerd.sock'),
    ledgerFile: path.join(dir, 'journal.jsonl'),
  };
}

async function startDaemon(f) {
  const child = spawn(process.execPath, [
    BIN, 'run',
    '--keystore', f.keystore,
    '--passphrase-file', f.passphraseFile,
    '--grants', f.grantFile,
    '--ledger', f.ledgerFile,
    '--socket', f.socketPath,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', () => {});
  await waitForLine(child, (line) => line.includes('"ok":true'));
  return child;
}

test('user zero: a client signs without ever holding the key, measured in live memory', async (t) => {
  const f = fixture();
  let daemon;
  let client;
  let legacy;
  try {
    daemon = await startDaemon(f);

    const blockhash = Keypair.generate().publicKey.toBase58();

    // ---- the measurement subject -------------------------------------
    client = spawn(process.execPath, [
      CLIENT,
      '--socket', f.socketPath,
      '--grant', 'ops',
      '--from', f.keypair.publicKey.toBase58(),
      '--to', f.destination,
      '--lamports', '42',
      '--blockhash', blockhash,
      '--out', path.join(f.dir, 'signed.bin'),
      '--hold',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let clientStderr = '';
    client.stderr.on('data', (c) => { clientStderr += c; });
    const clientLine = await readFirstLine(client);
    const result = JSON.parse(clientLine);
    assert.equal(result.ok, true, `client was refused: ${clientLine} ${clientStderr}`);
    assert.equal(result.amountLamports, '42');
    assert.equal(result.feeLamports, '5000');

    // The client must be waiting for a scan now; if it is gone, there is
    // nothing to measure and the absence claim would be vacuous.
    assert.equal(client.exitCode, null, 'client must still be alive to be scanned');

    // Independent verification of the signature the client received: the
    // signed bytes must verify under the fee payer's PUBLIC key, using Node's
    // OpenSSL ed25519 rather than the daemon's own code path.
    const signedWire = fs.readFileSync(result.out);
    assert.ok(signedWire.length > 0, 'client must have written the signed wire');
    const { VersionedTransaction } = require('@solana/web3.js');
    const parsed = VersionedTransaction.deserialize(signedWire);
    const message = Buffer.from(parsed.message.serialize());
    const signature = Buffer.from(parsed.signatures[0]);
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(f.keypair.publicKey.toBytes())]);
    const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    assert.equal(crypto.verify(null, message, keyObject, signature), true,
      'the signature the client got must verify under the public key');

    const secret = Buffer.from(f.keypair.secretKey);

    // ---- scan the subject --------------------------------------------
    const clientScan = scanForPattern(client.pid, secret);

    // ---- positive control: a process that DOES hold the key ------------
    // If the scanner cannot find a key that is demonstrably present, the
    // scanner is broken and the subject's "0 hits" means nothing. This control
    // is what makes an absence claim evidence rather than a hope.
    legacy = spawn(process.execPath, ['-e', `
      const fs = require('node:fs');
      const { Keypair } = require(${JSON.stringify(require.resolve('@solana/web3.js'))});
      const bytes = new Uint8Array(JSON.parse(fs.readFileSync(${JSON.stringify(f.source)}, 'utf8')));
      const kp = Keypair.fromSecretKey(bytes);
      globalThis.HELD = kp;
      console.log('READY');
      setTimeout(() => {}, 60000);
    `], { cwd: path.join(__dirname, '..'), stdio: ['ignore', 'pipe', 'pipe'] });
    legacy.stderr.on('data', () => {});
    await waitForLine(legacy, (line) => line.includes('READY'));
    const legacyScan = scanForPattern(legacy.pid, secret);

    // ---- the key's real home: the daemon ------------------------------
    const daemonScan = scanForPattern(daemon.pid, secret);

    // An instrument that cannot read any mapping at all is an environment
    // that forbids the measurement, not a client free of keys.
    const canReadAnything = clientScan.regionsRead > 0 && legacyScan.regionsRead > 0;
    if (!canReadAnything || legacyScan.hits.length === 0) {
      t.diagnostic(`scan unavailable or instrument unproven: client read ${clientScan.regionsRead} regions, ` +
        `legacy read ${legacyScan.regionsRead} regions with ${legacyScan.hits.length} hits. ` +
        `Skipping the absence claim rather than reporting it as verified.`);
      if (legacyScan.regionsRead > 0 && legacyScan.hits.length === 0) {
        // Readable but the known-present key was not found: the instrument is
        // broken. That is a measurement failure, not a pass.
        assert.fail('positive control failed: the scanner read the control process but did not find the key in it');
      }
      t.skip('memory scanning not permitted in this environment');
      return;
    }

    // The instrument is proven: it found the key in a process that has it.
    assert.ok(legacyScan.hits.length > 0, 'positive control must find the key');
    assert.ok(daemonScan.hits.length > 0, 'the daemon is where the key lives; it must be found there');
    assert.ok(scanIsComplete(daemonScan), 'daemon scan must cover all writable mappings');

    // The claim itself: the client, which just produced that signature,
    // contains no copy of the secret key anywhere in its address space.
    assert.equal(clientScan.hits.length, 0,
      `client process must hold no copy of the secret key (found ${clientScan.hits.length} copies)`);
    assert.ok(scanIsComplete(clientScan),
      'client scan must cover every writable mapping before absence may be claimed');

    t.diagnostic(
      `secret-key copies -> legacy client (control): ${legacyScan.hits.length}, ` +
      `daemon: ${daemonScan.hits.length}, signerd user-zero client: ${clientScan.hits.length} ` +
      `(${clientScan.bytesScanned} bytes scanned across ${clientScan.regionsRead} mappings; ` +
      `${legacyScan.bytesScanned} bytes in the control)`
    );
  } finally {
    terminate(legacy);
    terminate(client);
    terminate(daemon);
    await new Promise((r) => setTimeout(r, 150));
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('user zero: an out-of-scope request is refused and leaves no signature', async (t) => {
  const f = fixture();
  let daemon;
  let client;
  try {
    daemon = await startDaemon(f);
    // Same grant, but a destination the grant does not allow: the daemon must
    // refuse, and the client must not quietly produce anything.
    const wrongDestination = Keypair.generate().publicKey.toBase58();
    client = spawn(process.execPath, [
      CLIENT,
      '--socket', f.socketPath,
      '--grant', 'ops',
      '--from', f.keypair.publicKey.toBase58(),
      '--to', wrongDestination,
      '--lamports', '42',
      '--blockhash', Keypair.generate().publicKey.toBase58(),
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    const line = await readFirstLine(client);
    const exitCode = await new Promise((resolve) => client.on('exit', resolve));
    const result = JSON.parse(line);
    assert.equal(result.ok, false, 'an out-of-scope destination must be refused');
    assert.equal(result.error, 'destination');
    assert.equal(exitCode, 1, 'the client must exit non-zero on refusal');
    assert.equal(fs.existsSync(path.join(f.dir, 'signed.bin')), false);
  } finally {
    terminate(client);
    terminate(daemon);
    await new Promise((r) => setTimeout(r, 150));
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});
