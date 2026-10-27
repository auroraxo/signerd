'use strict';

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
    this.keypair = keypair || null;
    this.grants = Object.create(null);
    this.grantNames = [];
    this.ledger = null;
    this.server = null;
    this.started = false;

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

  async start() {
    if (this.started) throw fail('daemon_started');
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
      this.server.once('error', reject);
      this.server.listen(this.socketPath, () => {
        this.server.removeListener('error', reject);
        resolve();
      });
    });
    // The socket is a capability: only the owner may talk to the daemon.
    fs.chmodSync(this.socketPath, 0o600);
    this.started = true;
    return this;
  }

  #onConnection(socket) {
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
    if (!this.started) return;
    await new Promise((resolve) => this.server.close(resolve));
    try { fs.unlinkSync(this.socketPath); } catch { /* already gone */ }
    this.started = false;
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
