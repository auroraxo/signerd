'use strict';

// The socket path is a capability: whoever can bind it can impersonate the
// signing daemon. So a start() may only REPLACE the path when it can PROVE
// that nobody is listening on it.
//
// These tests pin the three-way verdict. The old two-way probe ("connected"
// vs. "anything else") read a saturated accept queue (EAGAIN) as "dead" and
// unlinked a LIVE daemon's socket.

process.umask(0o077);

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { classifySocketPath } = require('../src/socketprobe');

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A listening socket that never accepts: the accept queue fills up. */
function saturatedServer(socketPath) {
  const child = spawn(process.execPath, ['-e', `
    const net = require('node:net');
    const server = net.createServer(() => {});
    server.listen(${JSON.stringify(socketPath)}, () => process.stdout.write('up\\n'));
    setInterval(() => {}, 1000);
  `], { stdio: ['ignore', 'pipe', 'inherit'] });
  const ready = new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('server never came up')), 10000);
    child.stdout.on('data', (d) => {
      buf += String(d);
      if (buf.includes('up')) { clearTimeout(timer); resolve(); }
    });
    child.on('exit', (c) => { clearTimeout(timer); reject(new Error(`server exited ${c}`)); });
  });
  return { child, ready };
}

test('an absent path is absent, not stale', async () => {
  const dir = tmpdir('signerd-sockprobe-');
  assert.equal(await classifySocketPath(path.join(dir, 'nothing.sock')), 'absent');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a plain file at the path is stale and may be replaced', async () => {
  const dir = tmpdir('signerd-sockprobe-');
  const p = path.join(dir, 'plain.sock');
  fs.writeFileSync(p, '');
  assert.equal(await classifySocketPath(p), 'stale');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a socket nobody listens on is stale', async () => {
  const dir = tmpdir('signerd-sockprobe-');
  const p = path.join(dir, 'dead.sock');
  // A child that listens and is then SIGKILLed leaves the socket FILE behind
  // with nobody listening - exactly what a crashed daemon leaves on disk.
  // (Node unlinks the path itself on a clean close, and a unix socket file
  // cannot be opened with open() to fake it.)
  const child = spawn(process.execPath, ['-e', `
    const net = require('node:net');
    net.createServer(() => {}).listen(${JSON.stringify(p)}, () => process.stdout.write('up\\n'));
    setInterval(() => {}, 1000);
  `], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error('server never came up')), 10000);
    child.stdout.on('data', (d) => {
      buf += String(d);
      if (buf.includes('up')) { clearTimeout(timer); resolve(); }
    });
  });
  process.kill(child.pid, 'SIGKILL');
  await new Promise((resolve) => child.once('exit', resolve));
  assert.equal(fs.existsSync(p), true, 'the crashed run must leave the socket file behind');
  assert.equal(await classifySocketPath(p), 'stale');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a live daemon is live', async () => {
  const dir = tmpdir('signerd-sockprobe-');
  const p = path.join(dir, 'live.sock');
  const server = net.createServer((s) => s.destroy());
  await new Promise((resolve) => server.listen(p, resolve));
  assert.equal(await classifySocketPath(p), 'live');
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a saturated accept queue is UNKNOWN, never stale', async () => {
  const dir = tmpdir('signerd-sockprobe-');
  const p = path.join(dir, 'busy.sock');
  const { child, ready } = saturatedServer(p);
  await ready;
  // Stop the server so it can never drain the queue: a paused or wedged
  // daemon is exactly the state where new connects stop being accepted.
  process.kill(child.pid, 'SIGSTOP');
  await sleep(100);

  // Fill the accept queue. New connects then fail with EAGAIN instead of
  // ECONNREFUSED - the daemon is alive, but the kernel refuses new clients.
  const held = [];
  let saturated = false;
  for (let i = 0; i < 1200 && !saturated; i += 1) {
    const s = net.connect(p);
    held.push(s);
    const code = await new Promise((resolve) => {
      s.once('connect', () => resolve('ok'));
      s.once('error', (e) => resolve(e.code));
      s.setTimeout(3000, () => { s.destroy(); resolve('timeout'); });
    });
    if (code === 'EAGAIN') saturated = true;
  }
  assert.ok(saturated, 'the accept queue could not be saturated on this host');

  // The verdict must be 'unknown': the daemon is alive and the path must not
  // be replaced. Reading EAGAIN as "dead" is exactly the bug.
  const verdict = await classifySocketPath(p);
  assert.equal(verdict, 'unknown');

  for (const s of held) { try { s.destroy(); } catch { /* closed */ } }
  try { process.kill(child.pid, 'SIGCONT'); } catch { /* gone */ }
  try { process.kill(child.pid, 'SIGKILL'); } catch { /* gone */ }
  fs.rmSync(dir, { recursive: true, force: true });
});
