#!/usr/bin/env node
'use strict';
// Measure: does `sign-message --add-grant` write a grant that refuses the
// very body it was bootstrapped from?
//
// The bootstrap reads issuer/type/subject/claims out of --body, but hardcodes
// maxBytes: '700' (the README example's cap) while the envelope's own hard
// cap is 3072 (src/policy-message.js MAX_MESSAGE_BYTES). A receipt body that
// is well-formed and inside the envelope but larger than 700 canonical bytes
// therefore gets a grant that refuses it with `message_too_large` — a scope
// the product's own creation path wrote for exactly this body.
//
// Verdict:
//   grant-cap-lag  the bootstrap wrote maxBytes 700, the body it bootstraps
//                  from is N bytes, the first sign is refused message_too_large
//   grant-cap-ok   the bootstrap covers the body it bootstraps from
//   no-verdict     the run did not produce an answer (exit 3)

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { canonicalReceiptBytes } = require('../src/receipt-identity');

const ROOT = path.resolve(__dirname, '..');
const SIGNERD = path.join(ROOT, 'bin', 'signerd.js');
const ARTIFACT = process.argv[2] || path.join(ROOT, 'research', 'bootstrap-cap-lag-2026-11-14.json');

function run(args, opts = {}) {
  return execFileSync(process.execPath, [SIGNERD, ...args], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts,
  });
}

function main() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-caplag-'));
  const keystore = path.join(work, 'ops.key');
  const pass = path.join(work, 'pass');
  const grants = path.join(work, 'grants.json');
  const socket = path.join(work, 's.sock');
  const ledger = path.join(work, 'journal.jsonl');
  fs.writeFileSync(pass, 'measure grant cap\n', { mode: 0o600 });

  run(['keygen', '--keystore', keystore, '--passphrase-file', pass]);

  // Two claims at the policy's own per-claim ceiling (256 chars each) plus a
  // 256-char note: 937 canonical bytes, well under the envelope's 3072.
  const body = {
    schema: 'openreceipts/v1',
    issuer: 'auroraxo',
    type: 'release',
    subject: 'auroraxo/signerd',
    issued_at: '2026-11-15T21:00:00+00:00',
    claims: { a: 'x'.repeat(256), b: 'y'.repeat(256) },
    note: 'n'.repeat(256),
  };
  const bodyPath = path.join(work, 'body.json');
  fs.writeFileSync(bodyPath, JSON.stringify(body, null, 2) + '\n');
  const canonicalBytes = canonicalReceiptBytes(body).length;

  // The bootstrap itself talks to the socket (the CLI round trip follows the
  // write), and there is no daemon yet — the grant file is written BEFORE the
  // socket round trip, so the write is already done when the connect fails.
  // The connect failure is the harness's shape, not the measurement.
  let addOut = '';
  try {
    addOut = run([
      'sign-message', '--socket', socket, '--grant', 'releases',
      '--body', bodyPath, '--add-grant', '--keystore', keystore, '--grants', grants,
      '--dry',
    ]);
  } catch (err) {
    addOut = String(err.stdout || '') + String(err.stderr || '');
  }
  const grant = JSON.parse(fs.readFileSync(grants, 'utf8')).grants.releases;
  const writtenMax = Number(grant.maxBytes);

  const daemon = require('child_process').spawn(process.execPath, [
    SIGNERD, 'run', '--keystore', keystore, '--passphrase-file', pass,
    '--grants', grants, '--ledger', ledger, '--socket', socket,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  const ready = () => {
    for (let i = 0; i < 50; i += 1) { try { return fs.statSync(socket).isSocket(); } catch { /* retry */ } }
    return false;
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  (async () => {
    for (let i = 0; i < 60; i += 1) { if (ready()) break; await sleep(100); }
    if (!ready()) { console.log(JSON.stringify({ verdict: 'no-verdict', reason: 'daemon did not start' })); process.exit(3); }

    let first;
    try {
      first = run(['sign-message', '--socket', socket, '--grant', 'releases', '--body', bodyPath]);
    } catch (err) {
      first = (err.stdout || '') + (err.stderr || '');
    }
    let sign;
    try { sign = JSON.parse(first.trim().split('\n').pop()); } catch { sign = { parse_error: String(first).slice(0, 200) }; }

    daemon.kill('SIGTERM');
    const answer = {
      measuredAt: new Date().toISOString(),
      what: 'does sign-message --add-grant write a grant that refuses the body it bootstraps from?',
      bootstrap: { stderr: (addOut.trim().split('\n')[0] || '').replace(/\/tmp\/[^\s"]+/g, '<tmp>') || null },
      face: {
        writtenMaxBytes: String(grant.maxBytes),
        bodyCanonicalBytes: canonicalBytes,
        withinEnvelopeCap: canonicalBytes <= 3072,
        firstSignError: sign && sign.ok === false ? sign.error : null,
      },
      bootstrapFlags: { maxBytes: String(grant.maxBytes), claimKeys: grant.claimKeys },
      body: { canonicalBytes, withinEnvelopeCap: canonicalBytes <= 3072 },
      firstSign: sign,
    };
    if (sign && sign.ok === false && sign.error === 'message_too_large') {
      answer.verdict = 'grant-cap-lag';
      answer.summary = `--add-grant wrote maxBytes ${writtenMax}, the body it bootstraps from is ${canonicalBytes} canonical bytes (inside the envelope's 3072), and the first sign is refused message_too_large`;
    } else if (sign && sign.ok === true) {
      answer.verdict = 'grant-cap-ok';
      answer.summary = `the bootstrap's maxBytes ${writtenMax} covers the body it bootstraps from (${canonicalBytes} bytes)`;
    } else {
      answer.verdict = 'no-verdict';
      answer.summary = 'the first sign neither allowed nor refused message_too_large: ' + JSON.stringify(sign).slice(0, 300);
    }
    console.log(JSON.stringify(answer, null, 2));
    fs.writeFileSync(ARTIFACT, JSON.stringify(answer, null, 2) + '\n');
    process.exit(answer.verdict === 'no-verdict' ? 3 : 0);
  })().catch((err) => { daemon.kill('SIGTERM'); console.error(err); process.exit(3); });
}

main();
