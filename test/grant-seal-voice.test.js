'use strict';

// THE GRANT-SEAL REFUSALS SPEAK (2026-11-18).
//
// WHY (measured 2026-11-18, tools/measure-grant-seal-voice.js, on the tree
// v0.2.38 = 2f280b6, research/grant-seal-voice-prefix-2026-11-18.json):
//
//   verify-grants <tampered sealed file> --seal-passphrase-file <right>
//     grant_file_seal_mismatch:        <- code, EMPTY reason, no repair
//   verify-grants <sealed file> --seal-passphrase-file <wrong>
//     grant_file_seal_mismatch:        <- same
//   verify-grants <shape-broken seal>  --seal-passphrase-file <right>
//     grant_file_seal_invalid:         <- same
//   verify-grants <sealed file> --seal-passphrase-file <empty file>
//     seal_passphrase_required:        <- same
//   status --grants <sealed file>
//     grant_file_sealed: the grant file carries a seal (<ABSOLUTE PATH>)
//                                              <- repair, but the only
//                                                  refusal in this CLI
//                                                  whose detail was a
//                                                  host path
//
// The JOURNAL half of the same idea (ledger_mac_invalid, ledger_mac_short,
// ledger_sealed) has carried a repair since v0.2.36; the GRANT half has
// carried none since the seal shipped. The seal is the provenance half of
// this product - it is what makes a grant document's bytes trustworthy -
// and its refusal family was the one class where an operator in trouble
// learned only the NAME.
//
// THE CONTRACT:
//   D1 the first line names the face itself: `<code>: <detail>`;
//   D2 the detail is NON-EMPTY (a bare name is not a reason);
//   D3 a `fix:` line tells the operator what to change, naming a real
//      flag or command for the face;
//   D4 no repair and no detail carries a host path;
//   D5 the exit code is unchanged (a refusal stays a refusal, exit 1);
//   D6 the machine channel is unchanged (verify-grants on a GOOD sealed
//      file still answers {"ok":true} on stdout);
//   D7 the CODE is unchanged - assertions and scripts read it.
//
// HOW THE TREE IS BUILT: the checkout's own CLI against files sealed by
// the checkout's own sealDocument(). No network, no daemon.
//
// THE LADDER: D1-D4 are RED on the pre-fix tree (2f280b6), D5-D7 GREEN on
// both.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { Keypair } = require(path.join(ROOT, 'node_modules', '@solana', 'web3.js'));
const { sealDocument } = require(path.join(ROOT, 'src', 'grantseal.js'));

/** Every command this CLI offers - a repair may only name one of these. */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

function cli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-sealvoice-'));
  const cfg = path.join(dir, 'cfg');
  fs.mkdirSync(cfg, { recursive: true, mode: 0o700 });
  fs.chmodSync(cfg, 0o700);
  const sealPass = path.join(cfg, 'seal.pass');
  const wrongPass = path.join(cfg, 'wrong.pass');
  const emptyPass = path.join(cfg, 'empty.pass');
  fs.writeFileSync(sealPass, 'correct horse battery staple\n', { mode: 0o600 });
  fs.writeFileSync(wrongPass, 'a different phrase entirely\n', { mode: 0o600 });
  fs.writeFileSync(emptyPass, '\n', { mode: 0o600 });
  for (const f of [sealPass, wrongPass, emptyPass]) fs.chmodSync(f, 0o600);
  return { dir, cfg, sealPass, wrongPass, emptyPass };
}

const PASSPHRASE = 'correct horse battery staple';

function baseDoc() {
  return {
    version: 1,
    grants: {
      ops: {
        signer: Keypair.generate().publicKey.toBase58(),
        destination: Keypair.generate().publicKey.toBase58(),
        maxLamports: '1000000',
        windowMaxLamports: '5000000',
        windowSeconds: '3600',
        expiresAt: '2030-01-01T00:00:00Z',
      },
    },
  };
}

/** Write a fixture sealed by the product's OWN sealDocument(). */
function writeSealed(cfg, name, mutate) {
  const doc = baseDoc();
  const sealed = sealDocument(doc, PASSPHRASE);
  if (mutate) mutate(sealed, doc);
  const p = path.join(cfg, name);
  fs.writeFileSync(p, JSON.stringify(sealed, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(p, 0o600);
  return p;
}

function fixture(t) {
  const sb = sandbox();
  t.after(() => {
    try { fs.rmSync(sb.dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  return sb;
}

/** The voice of a refusal: code (first colon token), fix line, no host path. */
function voiceOf(res) {
  const text = String(res.stderr || '');
  const firstLine = text.split('\n').find((l) => l.trim().length > 0) || '';
  const code = (firstLine.split(':')[0] || '').trim();
  const detail = firstLine.slice(code.length).replace(/^:\s*/, '').trim();
  const escaped = code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const occurrences = code
    ? (text.match(new RegExp(`(?:^|\\n)${escaped}(?::|\\s|$)`, 'g')) || []).length
    : 0;
  return {
    code,
    detail,
    occurrences,
    hasFix: /(^|\n)\s*fix:/.test(text),
    text,
    unknownCommands: (() => {
      const found = [];
      const re = /signerd\s+([a-z][a-z-]*)/g;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!KNOWN_COMMANDS.includes(m[1])) found.push(m[1]);
      }
      return [...new Set(found)];
    })(),
    hostPath: /\/home\/|\/Users\/|\/root\//.test(text),
  };
}

test('D1-D4: a grant-seal refusal names itself, its reason and its repair, without a host path', (t) => {
  const sb = fixture(t);
  const ledger = path.join(sb.cfg, 'journal.jsonl');

  const tampered = writeSealed(sb.cfg, 'tampered.json', (sealed, doc) => {
    doc.grants.ops.destination = Keypair.generate().publicKey.toBase58();
    sealed.grants = doc.grants;
  });
  const good = writeSealed(sb.cfg, 'good.json');
  const broken = writeSealed(sb.cfg, 'broken.json', (sealed) => {
    sealed.seal.alg = 'not-hmac-sha256';
  });

  const faces = [
    {
      name: 'tampered payload, right passphrase',
      expect: 'grant_file_seal_mismatch',
      token: 'seal',
      argv: ['verify-grants', '--grants', tampered, '--seal-passphrase-file', sb.sealPass],
    },
    {
      name: 'sealed file, wrong passphrase',
      expect: 'grant_file_seal_mismatch',
      token: 'seal',
      argv: ['verify-grants', '--grants', good, '--seal-passphrase-file', sb.wrongPass],
    },
    {
      name: 'shape-broken seal block',
      expect: 'grant_file_seal_invalid',
      token: 'seal',
      argv: ['verify-grants', '--grants', broken, '--seal-passphrase-file', sb.sealPass],
    },
    {
      name: 'empty seal passphrase file',
      expect: 'seal_passphrase_required',
      token: 'passphrase',
      argv: ['verify-grants', '--grants', good, '--seal-passphrase-file', sb.emptyPass],
    },
    {
      name: 'keyless read of a sealed file (path in the detail)',
      expect: 'grant_file_sealed',
      token: 'seal',
      argv: ['status', '--grants', good, '--ledger', ledger],
      detailMustNotBePath: true,
    },
  ];

  for (const face of faces) {
    const res = cli(face.argv);
    assert.notStrictEqual(res.status, 0, `${face.name}: must refuse`);
    const v = voiceOf(res);
    // D7: the CODE is unchanged - scripts and assertions read it.
    assert.strictEqual(v.code, face.expect,
      `${face.name}: the code must reach stderr, got: ${JSON.stringify(res.stderr)}`);
    // D1: the code appears EXACTLY ONCE, as the leading token.
    assert.strictEqual(v.occurrences, 1,
      `${face.name}: the code must appear exactly once, got ${v.occurrences}: ${res.stderr}`);
    // D2: the reason must be NON-EMPTY.
    assert.ok(v.detail.length > 0,
      `${face.name}: the refusal must carry a reason, got an empty one: ${JSON.stringify(res.stderr)}`);
    // D3: a repair must be named, and it may only name real commands.
    assert.ok(v.hasFix, `${face.name}: the refusal must name a repair: ${res.stderr}`);
    assert.deepStrictEqual(v.unknownCommands, [],
      `${face.name}: the repair names a command this CLI does not offer: ${v.unknownCommands.join(', ')}`);
    assert.ok(v.text.includes(face.token),
      `${face.name}: the repair must name the flag the face is about: ${res.stderr}`);
    // D4: no host path in the refusal - repair AND reason.
    assert.ok(!v.hostPath, `${face.name}: the refusal must not carry a host path: ${res.stderr}`);
    if (face.detailMustNotBePath) {
      assert.ok(!v.detail.startsWith('/') && !v.detail.includes(sb.dir),
        `${face.name}: the reason must not BE a path: ${v.detail}`);
    }
    // D5: the exit code is unchanged - a refusal stays a refusal.
    assert.strictEqual(res.status, 1,
      `${face.name}: a refusal must exit 1: ${res.status}`);
  }
});

test('D6: the machine channel is unchanged - a GOOD sealed file verifies with ok:true', (t) => {
  const sb = fixture(t);
  const good = writeSealed(sb.cfg, 'good.json');
  const res = cli(['verify-grants', '--grants', good, '--seal-passphrase-file', sb.sealPass]);
  assert.strictEqual(res.status, 0, `a good seal must verify: ${res.stderr}`);
  const doc = JSON.parse(res.stdout.split('\n')[0]);
  assert.strictEqual(doc.ok, true, 'the machine channel must still answer ok:true');
  assert.deepStrictEqual(doc.grants, ['ops'], 'the grant names must be unchanged');
});

test('D7 GUARD: a tampered file is still refused (the fix did not weaken the seal)', (t) => {
  const sb = fixture(t);
  const tampered = writeSealed(sb.cfg, 'tampered.json', (sealed, doc) => {
    doc.grants.ops.destination = Keypair.generate().publicKey.toBase58();
    sealed.grants = doc.grants;
  });
  const res = cli(['verify-grants', '--grants', tampered, '--seal-passphrase-file', sb.sealPass]);
  assert.notStrictEqual(res.status, 0, 'a tampered sealed file must still be refused');
  assert.match(res.stderr, /grant_file_seal_mismatch/,
    `the refusal must keep its code: ${res.stderr}`);
});

test('D7b GUARD: a file with NO seal still loads keylessly (the fix did not seal by accident)', (t) => {
  const sb = fixture(t);
  const p = path.join(sb.cfg, 'plain.json');
  fs.writeFileSync(p, JSON.stringify(baseDoc(), null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(p, 0o600);
  const res = cli(['status', '--grants', p, '--ledger', path.join(sb.cfg, 'j.jsonl')]);
  assert.strictEqual(res.status, 0,
    `an unsealed file must still load without a passphrase: ${res.stderr}`);
  const doc = JSON.parse(res.stdout.split('\n')[0]);
  assert.strictEqual(doc.ok, true, 'the unsealed status must still answer ok:true');
});
