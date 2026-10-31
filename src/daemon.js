'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { Ledger } = require('./ledger');
const { loadGrantFile } = require('./grantfile');
const { signApproved } = require('./signer');
const { classifySocketPath } = require('./socketprobe');

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
  // The wire is a BASE64 STRING. Buffer.from(array, 'base64') silently
  // ignores the encoding argument and converts the array, so a JSON byte
  // array used to be accepted as if it were the documented wire format.
  if (typeof wireField.value !== 'string' || wireField.value.length === 0) {
    throw fail('request_invalid');
  }
  const wire = Buffer.from(wireField.value, 'base64');
  // Canonical base64 only: Node's decoder also skips characters that are not
  // in the alphabet and accepts base64url, so the round trip is the check.
  if (!wire.length || wire.toString('base64') !== wireField.value) throw fail('request_invalid');
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
 * `grantSealPassphrase` (optional) turns ON sealed-grant mode: every load and
 * reload of the grant file must verify the document's HMAC seal against a key
 * derived from that passphrase (R5-2). Without it the daemon accepts unsealed
 * grant files exactly as before.
 *
 * `journalSealPassphrase` (optional) turns ON sealed-journal mode: every
 * journal record carries a keyed chain MAC and a seal floor next to the
 * journal says how much history this daemon approved (R5-2 journal half).
 * Without it the daemon accepts unsealed journals exactly as before - but a
 * journal that HAS a seal floor is then refused, not degraded.
 *
 * This is an early prototype, NOT a reviewed wallet or a production daemon.
 */
class Daemon {
  constructor({ socketPath, keystorePath, grantFile, passphrase, ledgerFile, keypair,
    grantSealPassphrase, journalSealPassphrase }) {
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
    this.grantFile = grantFile;
    // Sealed-grant mode: key derivation from the seal passphrase, cached per
    // salt (grantfile re-reads the document on every request).
    this.sealKeyFor = typeof grantSealPassphrase === 'string' && grantSealPassphrase.length > 0
      ? require('./grantseal').makeSealKeyProvider(grantSealPassphrase)
      : null;
    this.ledger = null;
    this.server = null;
    this.started = false;
    this.stopPromise = null;
    // True only while THIS instance created the socket file. A failed start()
    // or a never-started stop() must never unlink a LIVE daemon's socket: the
    // path is how clients find the real daemon, and deleting it lets any local
    // process bind the path and impersonate it.
    this.socketOwned = false;
    // Every accepted connection is tracked so stop() can drain them: a held
    // open connection must never outlive the journal lock.
    this.connections = new Set();

    if (this.keypair === null) {
      if (!keystorePath) throw fail('keystore_required');
      if (!passphrase) throw fail('passphrase_required');
      // Decryption happens here and only here; the key stays in this process.
      const { loadKeystore } = require('./keystore');
      this.keypair = loadKeystore({ file: keystorePath, passphrase });
    }
    this.#reloadGrants();
    // The journal's owner/mode/directory policy is Ledger's alone: it refuses
    // a journal another user could write and repairs one that is merely
    // readable. A blanket chmod before this check would silently adopt a
    // world-writable journal. Creation with an explicit 0600 - never by
    // process umask - happens on the first append.
    this.ledger = new Ledger({
      file: ledgerFile,
      sealPassphrase: typeof journalSealPassphrase === 'string' && journalSealPassphrase.length > 0
        ? journalSealPassphrase
        : undefined,
    });
  }

  /**
   * Load (or RELOAD) the grant file and enforce that every grant speaks for
   * this daemon's key.
   *
   * Reload happens on every request, not once at startup: revocation is the
   * operator's main control and an edit that only takes effect after a restart
   * is fail-open. If the file is unreadable or invalid at request time the
   * daemon refuses every request until it is valid again - never the reverse.
   */
  #reloadGrants() {
    const loaded = loadGrantFile(this.grantFile,
      this.sealKeyFor === null ? {} : { sealKeyFor: this.sealKeyFor });
    for (const name of loaded.names) {
      // A grant that this daemon's key cannot satisfy would be refused on every
      // request anyway; make it an explicit refusal at load/reload time too.
      if (loaded.grants[name].signer !== this.keypair.publicKey.toBase58()) {
        throw fail('grant_signer_mismatch', name);
      }
    }
    this.grants = loaded.grants;
    this.grantNames = loaded.names;
  }

  /** Handle one request. Returns a plain object; never throws to the socket. */
  handle(request) {
    if (!this.started) return { ok: false, error: 'daemon_not_running' };
    // The journal lock is checked on EVERY request, not only at startup: if
    // another daemon has since taken the lock over, this process must stop
    // answering rather than append to a journal it no longer owns.
    if (!this.#ownsJournalLock()) return { ok: false, error: 'ledger_lock_lost' };
    // Revocation takes effect immediately: the grant file is re-read before
    // every request instead of once at startup.
    try {
      this.#reloadGrants();
    } catch (err) {
      return { ok: false, error: err.code || 'grant_file_invalid' };
    }
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
      messageSha256: verdict.messageSha256,
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
      // The socket path is a CAPABILITY: whoever can bind it can impersonate
      // the signing daemon. Its directory must therefore not be writable by
      // anybody else - otherwise a stranger can unlink the socket file and
      // bind their own server at the documented path, and every client that
      // trusts the path will believe a forged approval. A sticky directory is
      // safe (only the file's own owner may remove it).
      const socketDir = path.dirname(path.resolve(this.socketPath));
      let dirStat;
      try {
        dirStat = fs.statSync(socketDir);
      } catch (err) {
        if (err.code !== 'ENOENT') throw fail('socket_dir_unreadable', err.code);
        // Create it ourselves with an owner-only mode; never inherit the
        // process umask here, because this directory is what protects the
        // capability the socket represents.
        fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(socketDir, 0o700); } catch { /* verified below */ }
        dirStat = fs.statSync(socketDir);
      }
      if (!dirStat.isDirectory()) throw fail('socket_dir_invalid');
      const dirMode = dirStat.mode & 0o7777;
      if ((dirMode & 0o022) !== 0 && (dirMode & 0o1000) === 0) {
        throw fail('socket_dir_mode', dirMode.toString(8));
      }
      if (typeof process.getuid === 'function' &&
          dirStat.uid !== process.getuid() && dirStat.uid !== 0) {
        throw fail('socket_dir_owner', String(dirStat.uid));
      }
      // A stale socket file from a crashed run must not block startup, but it
      // must also not be a live daemon's socket. The probe has THREE verdicts
      // on purpose: 'live' -> refuse, 'stale' (only ECONNREFUSED proves nobody
      // listens) -> replace, 'unknown' (EAGAIN on a saturated accept queue,
      // timeout, ...) -> refuse. Collapsing 'unknown' into 'stale' let a
      // second start unlink a LIVE daemon's socket and bind the documented
      // client path instead (research/review5 p4).
      const socketState = await classifySocketPath(this.socketPath);
      if (socketState === 'live' || socketState === 'unknown') {
        throw fail('socket_in_use', socketState === 'unknown'
          ? 'the existing socket could not be proven dead - refusing to replace it'
          : undefined);
      }
      if (socketState === 'stale') fs.unlinkSync(this.socketPath);
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
          // The socket file exists BECAUSE we bound it, so from this point on
          // only this instance may remove it. Ownership is claimed BEFORE the
          // chmod below: a chmod failure is a failure after listen(), and the
          // catch block must still clean up the socket we just created.
          this.socketOwned = true;
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
      // Only a socket THIS instance created may be removed. A failed start
      // must never delete a live daemon's socket path: that path is how
      // clients find the real daemon, and deleting it lets any local process
      // bind it and impersonate the daemon.
      if (this.socketOwned) {
        try { fs.unlinkSync(this.socketPath); } catch { /* not created */ }
        this.socketOwned = false;
      }
      this.#releaseJournalLock();
      throw err;
    }
  }

  #onConnection(socket) {
    this.connections.add(socket);
    socket.on('close', () => { this.connections.delete(socket); });
    let buffer = Buffer.alloc(0);
    // Exactly ONE request is served per connection. `handled` is checked
    // BEFORE handle() is called, never after: an extra frame must be refused
    // before it can be parsed, charged against the window budget, journaled or
    // signed. The timer both bounds a silent client and reaps the half-open
    // connection that remains after we have answered.
    let handled = false;
    const timer = setTimeout(() => socket.destroy(), REQUEST_TIMEOUT_MS);
    const reapAfter = (ms) => setTimeout(() => socket.destroy(), ms).unref();
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_REQUEST_BYTES) {
        clearTimeout(timer);
        socket.destroy();
        return;
      }
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;
      const raw = buffer.subarray(0, newline);
      const rest = buffer.subarray(newline + 1);
      if (handled) {
        // A second frame on this connection is dropped without ever reaching
        // handle(): it must not consume budget or produce a signature. The
        // response side is already ended, so writing is no longer safe - the
        // client is told by the connection closing (and by never receiving a
        // second response). The reap timer reaps this socket.
        return;
      }
      handled = true;
      buffer = rest;
      let response;
      try {
        response = this.handle(raw);
      } catch {
        response = { ok: false, error: 'internal_error' };
      }
      clearTimeout(timer);
      const extra = rest.length > 0
        // A pipelined second request arrived behind the first line. It is
        // refused IN THE SAME WRITE, so the client is told and the first
        // request is answered exactly once (it used to be re-handled, running
        // the whole policy -> ledger -> sign chain again, on every later data
        // event, because the buffer was never consumed).
        ? JSON.stringify(response) + '\n' +
          JSON.stringify({ ok: false, error: 'one_request_per_connection' }) + '\n'
        : JSON.stringify(response) + '\n';
      socket.end(extra);
      reapAfter(1000);
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
    // Only a socket THIS instance created may be removed. stop() on a daemon
    // that never started must not delete a live daemon's socket path.
    if (this.socketOwned) {
      try { fs.unlinkSync(this.socketPath); } catch { /* already gone */ }
      this.socketOwned = false;
    }
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
