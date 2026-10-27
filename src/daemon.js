'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { Ledger } = require('./ledger');
const { loadGrantFile } = require('./grantfile');
const { signApproved } = require('./signer');

const MAX_REQUEST_BYTES = 4096;
const REQUEST_TIMEOUT_MS = 10_000;
// Grant names are request data: never resolve them through Object.prototype.
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// A stale lock is taken over at most this many times per start() before the
// daemon gives up and refuses: contention is a refusal, never a guess.
const LOCK_TAKEOVER_ATTEMPTS = 6;

function fail(reason, detail) {
  const err = new Error(detail === undefined ? reason : `${reason}: ${detail}`);
  err.code = reason;
  return err;
}

function decodeRequest(raw) {
  let doc;
  try {
    doc = JSON.parse(raw.toString('utf8'));
  } catch {
    throw fail('request_invalid');
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) throw fail('request_invalid');
  const grantName = Object.getOwnPropertyDescriptor(doc, 'grant');
  const wireField = Object.getOwnPropertyDescriptor(doc, 'wire');
  if (!grantName || !('value' in grantName) || typeof grantName.value !== 'string') {
    throw fail('request_invalid');
  }
  if (!wireField || !('value' in wireField)) throw fail('request_invalid');
  const wire = Buffer.from(wireField.value, 'base64');
  if (!wire.length) throw fail('request_invalid');
  return { grantName: grantName.value, wire };
}

/** True when `pid` refers to a live process (EPERM = alive, owned by someone else). */
function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

/**
 * A local signing daemon.
 *
 * The key lives in this process only. Clients hold a grant NAME and a
 * transaction; they never hold key material. Every request is answered by the
 * policy -> ledger -> sign -> verify chain, and a refusal is returned as
 * structured data so a caller can learn why instead of working around it.
 *
 * This is an early prototype, NOT a reviewed wallet or a production daemon.
 */
class Daemon {
  constructor({ socketPath, keystorePath, grantFile, passphrase, ledgerFile, keypair }) {
    if (typeof socketPath !== 'string' || socketPath.length === 0) throw fail('socket_path_required');
    if (path.resolve(socketPath).length > 100) throw fail('socket_path_too_long');
    this.socketPath = socketPath;
    this.ledgerFile = ledgerFile;
    this.lockFile = `${ledgerFile}.lock`;
    this.lockHeld = false;
    // A random per-instance token is written into the lock file. Release and
    // per-request checks compare it, so this daemon can neither drop nor obey
    // a lock that belongs to somebody else (a pid alone is reused by the OS).
    this.lockToken = crypto.randomBytes(16).toString('hex');
    this.lockStartedAt = Date.now();
    this.keypair = keypair || null;
    this.grants = Object.create(null);
    this.grantNames = [];
    this.ledger = null;
    this.server = null;
    this.started = false;
    this.stopPromise = null;
    // Every accepted connection is tracked so stop() can drain them: a held
    // open connection must never outlive the journal lock.
    this.connections = new Set();

    if (ledgerFile) {
      // A journal written before this hardening may still be group readable.
      // Creating it is done with an explicit 0600 mode, never by a process
      // umask: a library must not mutate global state for its host process.
      try { fs.chmodSync(ledgerFile, 0o600); } catch { /* created on first approval */ }
    }

    const loaded = loadGrantFile(grantFile);
    this.grants = loaded.grants;
    this.grantNames = loaded.names;
    this.ledger = new Ledger({ file: ledgerFile });
    if (this.keypair === null) {
      if (!keystorePath) throw fail('keystore_required');
      if (!passphrase) throw fail('passphrase_required');
      // Decryption happens here and only here; the key stays in this process.
      const { loadKeystore } = require('./keystore');
      this.keypair = loadKeystore({ file: keystorePath, passphrase });
    }
    // A grant that this daemon's key cannot satisfy would be refused on every
    // request; fail at startup instead.
    for (const name of this.grantNames) {
      const grant = this.grants[name];
      if (grant.signer !== this.keypair.publicKey.toBase58()) {
        throw fail('grant_signer_mismatch', name);
      }
    }
  }

  /** Handle one request. Returns a plain object; never throws to the socket. */
  handle(request) {
    if (!this.started) return { ok: false, error: 'daemon_not_running' };
    // The journal lock is checked on EVERY request, not only at startup: if
    // another daemon has since taken the lock over, this process must stop
    // answering rather than append to a journal it no longer owns.
    if (!this.#ownsJournalLock()) return { ok: false, error: 'ledger_lock_lost' };
    let parsed;
    try {
      parsed = decodeRequest(request);
    } catch (err) {
      return { ok: false, error: err.code || 'request_invalid' };
    }
    const { grantName, wire } = parsed;
    if (!NAME.test(grantName)) return { ok: false, error: 'grant_not_found' };
    if (!Object.prototype.hasOwnProperty.call(this.grants, grantName)) {
      return { ok: false, error: 'grant_not_found' };
    }
    const grant = this.grants[grantName];
    const verdict = signApproved({
      wire, grant, ledger: this.ledger, keypair: this.keypair, now: new Date(),
    });
    if (!verdict.allowed) return { ok: false, error: verdict.refused, detail: verdict };
    return {
      ok: true,
      signature: verdict.signature,
      signed: verdict.signed.toString('base64'),
      amountLamports: verdict.amountLamports,
      feeLamports: verdict.feeLamports,
      totalLamports: verdict.totalLamports,
      wireSha256: verdict.wireSha256,
      seq: verdict.seq,
      windowSpentLamports: verdict.windowSpentLamports,
      windowRemainingLamports: verdict.windowRemainingLamports,
    };
  }

  #lockBody() {
    return JSON.stringify({ pid: process.pid, token: this.lockToken, startedAt: this.lockStartedAt });
  }

  /**
   * Enforce the ledger's single-writer precondition with a pid+token lock file.
   * A second daemon on the same journal would share neither the replay set nor
   * the window (the same wire could then be signed twice), so it must refuse.
   *
   * The claim itself is made with link(2), which is atomic and NEVER
   * overwrites: exactly one process can place its file at the lock path. The
   * takeover of a provably dead owner is the only removal step, and it is
   * guarded: the stale lock is renamed aside with a rename(2) and the moved
   * bytes are then compared with the bytes we inspected. If they differ, a
   * concurrent process replaced the lock between our read and our rename, so
   * we have just moved a LIVE lock — it is put back (link again, which cannot
   * clobber) and this process backs off instead of stealing it.
   */
  #acquireJournalLock() {
    for (let attempt = 0; attempt < LOCK_TAKEOVER_ATTEMPTS; attempt += 1) {
      // (1) Our claim file: uniquely ours, 0600, content durable before it
      //     is ever visible at the lock path.
      const claim = `${this.lockFile}.${this.lockToken}`;
      let fd;
      try {
        fd = fs.openSync(claim, 'wx', 0o600);
        try {
          fs.writeSync(fd, this.#lockBody());
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      } catch (err) {
        if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already closed */ } }
        throw fail('ledger_lock_failed', err.code);
      }

      // (2) Atomic, non-overwriting placement at the canonical lock path.
      let linked = false;
      try {
        fs.linkSync(claim, this.lockFile);
        linked = true;
      } catch (err) {
        if (err.code !== 'EEXIST') {
          try { fs.unlinkSync(claim); } catch { /* best effort */ }
          throw fail('ledger_lock_failed', err.code);
        }
      }
      // The inode survives at lockFile when linked; the claim name is a
      // scratch link in both cases.
      try { fs.unlinkSync(claim); } catch { /* best effort */ }
      if (linked) {
        this.lockHeld = true;
        return;
      }

      // (3) Somebody holds the lock. Read and judge it.
      let raw;
      try {
        raw = fs.readFileSync(this.lockFile);
      } catch (err) {
        if (err.code === 'ENOENT') continue; // released while we looked
        throw fail('ledger_locked', err.code);
      }
      let owner = null;
      try { owner = JSON.parse(raw.toString('utf8')); } catch { owner = null; }
      if (owner === null || typeof owner !== 'object' ||
          !Number.isInteger(owner.pid) || owner.pid <= 0 ||
          typeof owner.token !== 'string' || owner.token.length === 0) {
        // Empty or malformed: refuse rather than guess. A crash between create
        // and write leaves an empty file; reclaiming it blind could let two
        // daemons pass the lock at once.
        throw fail('ledger_locked', 'unreadable lock file');
      }
      if (pidAlive(owner.pid)) throw fail('ledger_locked', `pid ${owner.pid}`);

      // (4) Provably dead owner: move the stale lock aside atomically, then
      //     prove we moved the same bytes we judged dead.
      const quarantine = `${this.lockFile}.stale.${this.lockToken}`;
      try {
        fs.renameSync(this.lockFile, quarantine);
      } catch (err) {
        if (err.code === 'ENOENT') continue; // already taken; re-claim
        throw fail('ledger_locked', err.code);
      }
      let moved = null;
      try { moved = fs.readFileSync(quarantine); } catch { moved = null; }
      if (moved === null || !moved.equals(raw)) {
        // A different file than we inspected: a concurrent process replaced
        // the lock in our read->rename window. Restore it without clobbering
        // anything and back off; the other process owns this journal now.
        try { fs.linkSync(quarantine, this.lockFile); } catch { /* someone re-claimed */ }
        try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
        continue;
      }
      try { fs.unlinkSync(quarantine); } catch { /* best effort */ }
      // The stale lock is gone: loop and try to claim it.
    }
    throw fail('ledger_locked', 'lock contention');
  }

  /** True only while THIS instance's token still occupies the lock path. */
  #ownsJournalLock() {
    if (!this.lockHeld) return false;
    let owner = null;
    try { owner = JSON.parse(fs.readFileSync(this.lockFile, 'utf8')); } catch { return false; }
    return owner !== null && typeof owner === 'object' && owner.token === this.lockToken;
  }

  #releaseJournalLock() {
    if (!this.lockHeld) return;
    this.lockHeld = false;
    // Never unlink by pid: only our own token may remove the lock, otherwise a
    // daemon that lost the takeover could delete its successor's lock.
    try {
      const owner = JSON.parse(fs.readFileSync(this.lockFile, 'utf8'));
      if (owner && owner.token === this.lockToken) fs.unlinkSync(this.lockFile);
    } catch { /* already gone or unreadable: leave it to the next owner */ }
  }

  async start() {
    if (this.started) throw fail('daemon_started');
    this.stopPromise = null;
    // Hold the journal before anything else can talk to us: two daemons on
    // one journal would bypass the replay set and double the window budget.
    this.#acquireJournalLock();
    try {
      // A stale socket file from a crashed run must not block startup, but it
      // must also not be a live daemon's socket.
      if (fs.existsSync(this.socketPath)) {
        const probe = net.connect(this.socketPath);
        const alive = await new Promise((resolve) => {
          probe.once('connect', () => resolve(true));
          probe.once('error', () => resolve(false));
          probe.setTimeout(500, () => { probe.destroy(); resolve(false); });
        });
        if (alive) throw fail('socket_in_use');
        fs.unlinkSync(this.socketPath);
      }
      fs.mkdirSync(path.dirname(path.resolve(this.socketPath)), { recursive: true });
      this.server = net.createServer((socket) => this.#onConnection(socket));
      await new Promise((resolve, reject) => {
        const onListenError = (err) => reject(err);
        this.server.once('error', onListenError);
        this.server.listen(this.socketPath, () => {
          // removeListener must name the function that was ADDED; removing
          // `reject` would leave the handler attached for the process
          // lifetime, where a later server error released the journal lock
          // while this daemon kept serving.
          this.server.removeListener('error', onListenError);
          // Belt and braces: the journal/socket modes are set explicitly, never
          // left to a default umask, because the socket is a capability.
          try {
            fs.chmodSync(this.socketPath, 0o600);
          } catch (err) {
            // A chmod failure after listen() must reject (not hang and not
            // leave an orphan listener): the outer catch closes the server,
            // unlinks the socket and gives the journal lock back.
            reject(err);
            return;
          }
          // A post-listen server error must not leave an unguarded lock: the
          // daemon stops serving FIRST and only then releases the journal.
          this.server.on('error', () => { this.stop().catch(() => { /* closing */ }); });
          resolve();
        });
      });
      this.started = true;
      return this;
    } catch (err) {
      // Any failure between listen() and started=true must leave nothing
      // running: an orphan listener would keep accepting (and signing) while
      // the journal lock has already been given back.
      const server = this.server;
      this.server = null;
      if (server) {
        try { server.close(); } catch { /* never listened */ }
        for (const socket of this.connections) { try { socket.destroy(); } catch { /* closed */ } }
      }
      this.connections.clear();
      try { fs.unlinkSync(this.socketPath); } catch { /* not created */ }
      this.#releaseJournalLock();
      throw err;
    }
  }

  #onConnection(socket) {
    this.connections.add(socket);
    socket.on('close', () => { this.connections.delete(socket); });
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => socket.destroy(), REQUEST_TIMEOUT_MS);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_REQUEST_BYTES) {
        clearTimeout(timer);
        socket.destroy();
        return;
      }
      // One JSON document per connection, newline framed.
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;
      const raw = buffer.subarray(0, newline);
      clearTimeout(timer);
      let response;
      try {
        response = this.handle(raw);
      } catch {
        response = { ok: false, error: 'internal_error' };
      }
      socket.end(JSON.stringify(response) + '\n');
    });
    socket.on('error', () => { clearTimeout(timer); socket.destroy(); });
  }

  async stop() {
    // Idempotent: a SIGTERM handler and a post-listen server error may both
    // ask for shutdown, and the journal lock must be released exactly once.
    if (this.stopPromise) return this.stopPromise;
    this.stopPromise = this.#stop();
    return this.stopPromise;
  }

  async #stop() {
    const server = this.server;
    this.server = null;
    if (server) {
      await new Promise((resolve) => {
        // close() stops accepting new connections but waits for in-flight
        // ones, so the held-open connection a client can keep alive would
        // otherwise delay the lock release indefinitely.
        try { server.close(() => resolve()); } catch { resolve(); }
        for (const socket of this.connections) { try { socket.destroy(); } catch { /* closed */ } }
      });
    }
    this.connections.clear();
    try { fs.unlinkSync(this.socketPath); } catch { /* already gone */ }
    this.started = false;
    // LAST: the journal lock is released only once no request can be served,
    // so a second daemon can never start while this one could still answer.
    this.#releaseJournalLock();
  }

  status() {
    return {
      socketPath: this.socketPath,
      grants: this.grantNames,
      ledger: this.ledger.snapshot(),
      signer: this.keypair ? this.keypair.publicKey.toBase58() : null,
    };
  }
}

/** Client: connect, send one request, read one response. */
function request({ socketPath, grant, wire, timeoutMs = REQUEST_TIMEOUT_MS }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socketPath);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('request_timeout')); }, timeoutMs);
    socket.on('connect', () => {
      socket.write(JSON.stringify({ grant, wire: Buffer.from(wire).toString('base64') }) + '\n');
    });
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;
      clearTimeout(timer);
      let response;
      try {
        response = JSON.parse(buffer.subarray(0, newline).toString('utf8'));
      } catch {
        socket.destroy();
        reject(new Error('response_invalid'));
        return;
      }
      socket.end();
      resolve(response);
    });
    socket.on('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

module.exports = { Daemon, request };
