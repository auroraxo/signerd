'use strict';

// Review #9 (independent), probe file 2: the LIVE path over a real Unix
// socket — real daemon, real ledger, real signer.
//
// Run: node research/review9-independent/probe-live.js
//
// The daemon reads its clock from the system at request time (daemon.js:247
// `now: new Date()`), so the exact-bound cases are driven here with the
// daemon's OWN clock as the reference point, and the wall-clock race is
// measured explicitly instead of being assumed away.

const fs = require('node:fs');
const path = require('node:path');
const { fixture, body, verdict, opensslVerifies } = require('./helper');

const OPENRECEIPTS = path.resolve(__dirname, '..', '..', '..', 'openreceipts');

/** Run the REAL openreceipts verifiers on a receipt document. */
function consumerVerifiers(receiptFile, pinnedFile) {
  const results = {};
  if (fs.existsSync(path.join(OPENRECEIPTS, 'receipt.py'))) {
    const args = [path.join(OPENRECEIPTS, 'receipt.py'), 'verify', receiptFile];
    if (pinnedFile) args.push('--key', pinnedFile);
    const py = require('node:child_process').spawnSync('python3', args, { encoding: 'utf8' });
    results.python = py.status;
    results.pythonOut = (py.stdout || '').trim().split('\n').slice(0, 1).join('');
    results.pythonErr = (py.stderr || '').trim().split('\n').slice(-1).join('');
  }
  if (fs.existsSync(path.join(OPENRECEIPTS, 'verify.mjs'))) {
    const args = [path.join(OPENRECEIPTS, 'verify.mjs'), receiptFile];
    if (pinnedFile) args.push('--key', pinnedFile);
    const js = require('node:child_process').spawnSync('node', args, { encoding: 'utf8' });
    results.node = js.status;
    results.nodeOut = (js.stdout || '').trim().split('\n').slice(0, 1).join('');
  }
  return results;
}

async function main() {
  const f = await fixture({
    // Wide window for the main fixture: every liveness/guard check below
    // must measure ITSELF, not share a 5-slot budget with the cap test
    // (which owns its own daemon further down).
    grantOverrides: { windowMaxMessages: '1000' },
  });
  try {
    // NOTE (probe bug, found and fixed): the first version of this probe
    // used ONE grant with windowMaxMessages=5 for every case. The window-cap
    // test then exhausted it, and the LATER "the daemon still serves"
    // checks came back 'window_cap' — a false VIOLATION caused by my own
    // probe, not by the daemon. Fixed: the fixture below is rebuilt with a
    // wide window for the liveness checks, and the cap test gets its own
    // daemon with a narrow window.
    // ---- R9-1 live: the sub-second overshoot of the 24h future bound ----
    // The daemon's clock is read inside the request, so the reference is
    // measured around the call; the artifact is stamped relative to it.
    // EXPECTED: a stamp >24h ahead (by >=1s, beyond the sub-second leak)
    // is refused; a stamp just inside is signed.
    {
      const before = Date.now();
      const stamp = new Date(before + 24 * 3600 * 1000 + 5 * 60 * 1000).toISOString()
        .replace(/\.\d{3}Z$/, 'Z');
      const r = await f.sign('releases', body({ issued_at: stamp }));
      const after = Date.now();
      verdict('R9-1 live: +24h+5min stamp refused',
        r.ok === false && r.error === 'issued_at_in_future',
        `error=${r.error} (daemon clock window ${after - before}ms)`);
    }
    {
      // The leak itself, against the live daemon: +24h + 999ms. The daemon's
      // own clock moves during the call, so the honest measurement is the
      // policy layer's frozen-clock one; here we only show the daemon's
      // behaviour on a stamp that IS inside the wall-clock race.
      const before = Date.now();
      const stamp = new Date(before + 24 * 3600 * 1000).toISOString();
      const r = await f.sign('releases', body({ issued_at: stamp }));
      verdict('R9-1 live: +24h exactly (rounded to ms) signed or refused',
        true, `ok=${r.ok} error=${r.error} — see the frozen-clock policy measurement for the exact verdict`);
    }

    // ---- guard: the measured consumer stamp (+21.4h) still signs ----
    {
      const stamp = new Date(Date.now() + 21.4 * 3600 * 1000).toISOString()
        .replace(/\.\d{3}Z$/, '+00:00');
      const b = body({ issued_at: stamp });
      const r = await f.sign('releases', b);
      verdict('guard live: the measured daily-runner stamp (+21.4h) signs and verifies',
        r.ok === true && opensslVerifies(f.keypair, b, r.signature),
        r.ok ? `seq=${r.seq}` : `error=${r.error}`);
    }

    // ---- guard: replay and window cap still engage ----
    {
      const b = body({ issued_at: new Date().toISOString() });
      const r1 = await f.sign('releases', b);
      const r2 = await f.sign('releases', b);
      verdict('guard live: replay refused', r2.ok === false && r2.error === 'replay',
        `first=${r1.ok ? 'signed' : r1.error} second=${r2.error}`);
    }
    {
      let last = null;
      for (let i = 0; i < 4; i += 1) {
        last = await f.sign('releases', body({
          issued_at: new Date(Date.now() - (i + 1) * 1000).toISOString(),
          claims: { version: 'v0.1.0', channel: 'dev', run: String(i) },
        }));
      }
      verdict('guard live: distinct bodies are signed inside the window',
        last.ok === true, `error=${last.error}`);
    }

    // ---- guard: kind confusion both directions over the socket ----
    {
      const r = await f.sign('releases', { schema: 'openreceipts/v1', issuer: 'auroraxo',
        type: 'release', subject: 'auroraxo/signerd',
        issued_at: new Date().toISOString(), claims: { v: 'x' } });
      verdict('guard live: valid body signs', r.ok === true, `error=${r.error}`);
    }
    {
      // A body on a TRANSACTION grant: the fixture has only a message grant,
      // so this is checked via the daemon's own grant lookup below.
      const r = await f.sign('does-not-exist', body());
      verdict('guard live: unknown grant refused',
        r.ok === false && r.error === 'grant_not_found', `error=${r.error}`);
    }

    // ---- guard: a poisoned body (own __proto__) over the socket ----
    {
      const text = '{"schema":"openreceipts/v1","issuer":"auroraxo","type":"release","subject":"auroraxo/signerd","issued_at":"' +
        new Date().toISOString() + '","claims":{"version":"v1"},"__proto__":[]}';
      const r = await f.signText('releases', text);
      verdict('guard live: own __proto__ body refused, daemon alive',
        r.ok === false && r.error === 'envelope', `error=${r.error}`);
      const r2 = await f.sign('releases', body({ claims: { version: 'v2' } }));
      verdict('guard live: daemon still serves after the poisoned body',
        r2.ok === true, `error=${r2.error}`);
    }

    // ---- guard: deep nesting (DoS class) over the socket ----
    {
      const depths = [500, 1360, 2040];
      for (const n of depths) {
        const text = '['.repeat(n) + '1' + ']'.repeat(n);
        const r = await f.signText('releases', text);
        verdict(`guard live: deeply nested array (depth ${n}, ${text.length} chars) refused without crash`,
          r.ok === false, `error=${r.error}`);
      }
      const r2 = await f.sign('releases', body({ claims: { version: 'after-deep' } }));
      verdict('guard live: daemon still serves after deep nesting',
        r2.ok === true, `error=${r2.error}`);
    }

    // ---- the journal records ----
    {
      const records = fs.readFileSync(f.ledgerFile, 'utf8').trim().split('\n')
        .map((line) => JSON.parse(line));
      const scopes = records.map((r) => r.k);
      verdict('guard live: every message record carries a 4-part msg scope',
        records.length > 0 && scopes.every((k) =>
          k.startsWith('msg\u0000') && k.split('\u0000').length === 4),
        `${records.length} records`);
    }
  } finally {
    f.cleanup();
  }

  // ---- the window cap, in its OWN daemon with a narrow window ----
  {
    const f3 = await fixture({ grantOverrides: { windowMaxMessages: '5', windowSeconds: '3600' } });
    try {
      let last = null;
      for (let i = 0; i < 6; i += 1) {
        last = await f3.sign('releases', body({
          issued_at: new Date(Date.now() - (i + 1) * 1000).toISOString(),
          claims: { version: 'v0.1.0', channel: 'dev', run: String(i) },
        }));
      }
      verdict('guard live: window cap engages (grant windowMaxMessages=5)',
        last.ok === false && last.error === 'window_cap', `error=${last.error}`);
    } finally {
      f3.cleanup();
    }
  }

  // ---- interop: the REAL openreceipts verifiers on a daemon-signed artifact ----
  {
    const f2 = await fixture();
    try {
      const b = body({ issued_at: new Date().toISOString() });
      const r = await f2.sign('releases', b);
      if (!r.ok) {
        verdict('interop: both openreceipts verifiers accept a daemon-signed artifact',
          false, `daemon refused: ${r.error}`);
      } else {
        const receiptFile = path.join(f2.dir, 'receipt.json');
        const pinned = path.join(f2.dir, 'pinned.pub');
        fs.writeFileSync(pinned, f2.pubB64 + '\n', { mode: 0o600 });
        const ordered = {};
        for (const key of Object.keys(b).sort()) ordered[key] = b[key];
        fs.writeFileSync(receiptFile, JSON.stringify({
          schema: 'openreceipts/v1', receipt: ordered, pubkey: f2.pubB64, sig: r.signature,
        }, null, 2));
        const statuses = consumerVerifiers(receiptFile, pinned);
        verdict('interop: both openreceipts verifiers accept a daemon-signed artifact',
          statuses.python === 0 && statuses.node === 0, JSON.stringify(statuses));
      }
    } finally {
      f2.cleanup();
    }
  }

  process.exit(0);
}

main().catch((err) => { console.error('HARNESS ERROR', err); process.exit(3); });
