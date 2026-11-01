'use strict';

// Review #8 — probe file 2: the LIVE path for the Review-#7 fix diff
// (84888d4). A real daemon signs through a real Unix socket; interop is
// measured with the REAL openreceipts verifiers (python3 receipt.py verify
// and node verify.mjs), pinned to the fixture public key.
//
// Probes L1-L3 are the fix itself (they must FAIL on the pre-fix tree).
// Probes L4-L8 are the false-positive guards (they must pass on BOTH trees).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { fixture, body, verdict } = require('./helper');

const OPENRECEIPTS = process.env.OPENRECEIPTS_DIR ||
  path.resolve(__dirname, '..', '..', '..', 'openreceipts');

function consumerVerifiers(doc, fixturePubFile) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-r8-doc-'));
  const file = path.join(dir, 'receipt.json');
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + '\n');
  const out = {};
  try {
    const py = spawnSync('python3', [path.join(OPENRECEIPTS, 'receipt.py'),
      'verify', file, '--key', fixturePubFile], { encoding: 'utf8' });
    out.python = py.status;
    if (py.status !== 0) out.pythonOut = (py.stderr || py.stdout || '').trim().split('\n').slice(-2).join(' | ');
    const js = spawnSync('node', [path.join(OPENRECEIPTS, 'verify.mjs'),
      file, '--key', fixturePubFile], { encoding: 'utf8' });
    out.node = js.status;
    if (js.status !== 0) out.nodeOut = (js.stderr || js.stdout || '').trim().split('\n').slice(-2).join(' | ');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return out;
}

function isoPlus(ms) {
  return new Date(Date.now() + ms).toISOString().replace(/\.\d+Z$/, '+00:00');
}

async function main() {
  const f = await fixture();
  // Each probe area owns its window budget: the window probe drives to the
  // cap, and the restart-replay probe runs in its OWN scope (subject
  // signerd-r8) so it can be starved by neither — replay identity is the
  // body bytes, independent of the scope. Grants reload on every request,
  // so extending the file here takes effect without a restart, and both
  // grants pin THIS fixture's key (f.messageGrant builds from f.pubB64).
  fs.writeFileSync(f.grantFile, JSON.stringify({ version: 1, grants: {
    releases: f.messageGrant({ windowMaxMessages: '12' }),
    replays: f.messageGrant({ subject: 'auroraxo/signerd-r8', windowMaxMessages: '12' }),
  } }, null, 2), { mode: 0o600 });
  const pubFile = path.join(f.dir, 'fixture.pub');
  fs.writeFileSync(pubFile, f.pubB64 + '\n');
  let failures = 0;
  const v = (label, ok, detail) => { if (!verdict(label, ok, detail)) failures += 1; };

  try {
    // ---- the fix, live (red on the pre-fix tree) ----
    const noIssued = body(); delete noIssued.issued_at;
    const l1 = await f.sign('releases', noIssued);
    v('R8-L1 live: missing issued_at refused over the socket',
      l1.ok === false && l1.error === 'envelope', `error=${l1.error}`);

    const l2 = await f.sign('releases', body({ issued_at: '2026-02-30T00:00:00+00:00' }));
    v('R8-L2 live: Feb 30 refused over the socket',
      l2.ok === false && l2.error === 'envelope', `error=${l2.error}`);

    const l3 = await f.sign('releases', body({ issued_at: isoPlus(24 * 3600e3 + 120e3) }));
    v('R8-L3 live: issued_at beyond the 24h future bound refused',
      l3.ok === false && l3.error === 'issued_at_in_future', `error=${l3.error}`);

    // ---- false-positive guards (green on both trees) ----
    const inside = body({ issued_at: isoPlus(23 * 3600e3 + 58 * 60e3), claims: { probe: 'boundary-inside' } });
    const l4 = await f.sign('releases', inside);
    const l4ok = l4.ok === true;
    const l4ver = l4ok
      ? consumerVerifiers({ receipt: inside, pubkey: l4.pubkey, sig: l4.signature }, pubFile)
      : { python: -1, node: -1 };
    v('R8-L4 guard live: +23:58 signs and BOTH openreceipts verifiers accept (pinned)',
      l4ok && l4ver.python === 0 && l4ver.node === 0,
      l4ok ? `py=${JSON.stringify(l4ver.pythonOut || '')} node=${JSON.stringify(l4ver.nodeOut || '')}`
           : `error=${l4.error}`);

    const negOffset = body({
      issued_at: '2020-05-05T12:00:00-03:30',
      claims: { probe: 'negative-offset' },
    });
    const l5 = await f.sign('releases', negOffset);
    const l5ver = l5.ok === true
      ? consumerVerifiers({ receipt: negOffset, pubkey: l5.pubkey, sig: l5.signature }, pubFile)
      : { python: -1, node: -1 };
    v('R8-L5 guard live: exotic-but-real offset (-03:30) signs; consumers parse it (daemon->consumer asymmetry clean)',
      l5.ok === true && l5ver.python === 0 && l5ver.node === 0,
      l5.ok ? `py=${JSON.stringify(l5ver.pythonOut || '')} node=${JSON.stringify(l5ver.nodeOut || '')}`
            : `error=${l5.error}`);

    const unicode = body({
      issued_at: isoPlus(3600e3),
      note: 'Prüfung 🟢 Umlaut+emoji ride inside the signed bytes',
      claims: { probe: 'unicode-note' },
    });
    const l6 = await f.sign('releases', unicode);
    const l6ver = l6.ok === true
      ? consumerVerifiers({ receipt: unicode, pubkey: l6.pubkey, sig: l6.signature }, pubFile)
      : { python: -1, node: -1 };
    v('R8-L6 guard live: unicode note + issued_at signs; canonical bytes still verify in both consumers',
      l6.ok === true && l6ver.python === 0 && l6ver.node === 0,
      l6.ok ? `py=${JSON.stringify(l6ver.pythonOut || '')}` : `error=${l6.error}`);

    // Window cap FIRST (it needs the original daemon's socket; the restart
    // probe below intentionally leaves a different daemon owning the path).
    let last = null;
    for (let i = 0; i < 14 && last?.error !== 'window_cap'; i += 1) {
      last = await f.sign('releases', body({
        issued_at: isoPlus(60e3 * (i + 1)),
        claims: { probe: 'window', run: String(i) },
      }));
    }
    v('R8-L8 guard live: the window cap still engages after the fix',
      last.error === 'window_cap', `error=${last.error}`);

    // Replay across a daemon RESTART (the ledger, not the process, owns it).
    // Own grant/scope (subject auroraxo/signerd-r8): untouched window budget.
    const replayBody = body({
      subject: 'auroraxo/signerd-r8',
      issued_at: isoPlus(1800e3), claims: { probe: 'restart-replay' },
    });
    const l7a = await f.sign('replays', replayBody);
    // helper's stop() wrapper is sync and swallows the promise; await the
    // daemon itself so the journal lock is actually released before restart.
    await f.daemon.stop();
    // Reuse the SAME directory so keystore/grants/ledger persist.
    let l7;
    try {
      const { Daemon, request } = require('../../src/daemon');
      const daemon2 = new Daemon({
        socketPath: f.socketPath, keystorePath: path.join(f.dir, 'ops.key'),
        passphrase: require('./helper').PASSPHRASE, grantFile: f.grantFile, ledgerFile: f.ledgerFile,
      });
      await daemon2.start();
      l7 = await request({ socketPath: f.socketPath, grant: 'replays', body: JSON.stringify(replayBody) });
      await daemon2.stop();
    } catch (e) {
      l7 = { error: `restart-failed: ${e.message}` };
    }
    v('R8-L7 guard live: identical bytes replay-refused across a daemon restart',
      l7a.ok === true && l7.error === 'replay', `first=${l7a.ok} second=${l7.error}`);
  } finally {
    f.cleanup();
  }

  console.log(`\nprobe-live: ${failures === 0 ? 'ALL PASS' : `${failures} VIOLATION(S)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
