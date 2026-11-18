'use strict';

// THE JOURNAL'S REFUSALS SPEAK (2026-11-18).
//
// WHY (measured 2026-11-18, tools/measure-journal-integrity-voice.js, on
// the PUBLISHED v0.2.35 npm package):
//
//   $ signerd migrate --ledger journal.jsonl
//   legacy_wire_required: 2 legacy record(s); pass --wires <dir> or explicitly --discard-legacy
//   $ signerd migrate --ledger tampered.jsonl --discard-legacy
//   error: ledger_tampered
//   $ signerd migrate --ledger journal.jsonl --wires ./absent
//   wires_dir_unreadable: ENOENT
//
// The journal is the REPLAY SET and the ROLLING-WINDOW BUDGET. When it
// refuses, the operator is one step from trusting history they should not
// trust - and this is exactly where the README promises the opposite:
//
//   "Refusals name the flag and the fix instead of failing silently."
//
// Two defects, both measured on the published tree:
//
//   (A) NO REPAIR. The operator got the refusal's NAME and nothing else.
//       `legacy_wire_required` does not tell anybody that the product
//       offers two ways out (--wires <dir> or --discard-legacy); only the
//       source does.
//
//   (B) THE NAME WAS BURIED. Where the loader raised an error WITHOUT a
//       code (src/ledger.js raised `new Error('ledger_tampered')`), the
//       CLI's generic tail printed `err.code || 'error'` - so the line
//       read `error: ledger_tampered`. The first colon-separated token -
//       the one a caller reads - was the literal word "error", and every
//       journal refusal looked the same to a machine.
//
// THE CONTRACT (this gate):
//   D1 a journal refusal prints its own NAME as the first stderr token,
//       exactly once - never the literal "error";
//   D2 it names a repair on a `fix:` line;
//   D3 the repair names a command this CLI ACTUALLY OFFERS (rule F3);
//   D4 the repair carries no host path;
//   D5 the EXIT CODE is unchanged: a refusal still exits 1 (this gate is
//       about what is SAID, never about the channel);
//   D6 a LEGAL migration still succeeds and stays silent on stderr;
//   D7 the refusals the loader raises carry their CODE on the error, so a
//       caller can branch on it.
//
// THE LADDER: D1-D4 are RED on the pre-fix tree, D5-D7 GREEN on both.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const { chainHash, GENESIS_HASH } = require(path.join(ROOT, 'src', 'ledger.js'));

/** Every command this CLI offers - a repair may only name one of these. */
const KNOWN_COMMANDS = [
  'keygen', 'grant-add', 'grant-remove', 'build-tx', 'import', 'run',
  'sign', 'sign-message', 'status', 'seal-grants', 'verify-grants',
  'seal-journal', 'migrate',
];

function cli(args) {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-journalvoice-'));
  fs.chmodSync(d, 0o700);
  return d;
}

/** A format-1 journal with a VALID chain: the product's own chainHash. */
function legacyJournal(dir, name) {
  let prev = GENESIS_HASH;
  const lines = [];
  for (let i = 1; i <= 2; i += 1) {
    const w = crypto.createHash('sha256').update(`wire-${name}-${i}`).digest('hex');
    const body = { s: i, t: 1700000000000 + i, w, a: String(1000 * i), f: '5000', k: 'signer\0dest' };
    const rec = { ...body, h: chainHash(prev, body) };
    prev = rec.h;
    lines.push(JSON.stringify(rec));
  }
  const file = path.join(dir, name);
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  return { file, lines };
}

function voice(stderr) {
  const text = String(stderr || '');
  const first = text.split('\n').find((l) => l.trim().length > 0) || '';
  return {
    code: (first.split(':')[0] || '').trim(),
    hasFix: /(^|\n)\s*fix:/.test(text),
    text,
  };
}

/** The refusal named ITSELF: the first token is the code, not "error". */
function namesItself(res, expected) {
  const v = voice(res.stderr);
  if (v.code === '' || v.code === 'error') return false;
  return expected ? v.code === expected : true;
}

test('D1 a journal refusal names ITSELF (never the literal "error")', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    // A tampered record: the loader's refusal.
    const tampered = path.join(dir, 'tampered.jsonl');
    const lines = j.lines.map((l) => JSON.parse(l));
    lines[1].a = '999999';
    fs.writeFileSync(tampered, lines.map((r) => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });

    const cases = [
      { face: 'legacy_wire_required', res: cli(['migrate', '--ledger', j.file]) },
      { face: 'wires_dir_unreadable', res: cli(['migrate', '--ledger', j.file, '--wires', path.join(dir, 'nope')]) },
      { face: 'ledger_tampered', res: cli(['migrate', '--ledger', tampered, '--discard-legacy']) },
    ];
    for (const c of cases) {
      assert.ok(namesItself(c.res, c.face),
        `${c.face} must print its own name as the first stderr token, got: ` +
        `${voice(c.res.stderr).text.split('\n')[0]}`);
      // The name must appear EXACTLY ONCE as the leading token.
      const first = voice(c.res.stderr).text.split('\n')[0];
      assert.ok(first.startsWith(`${c.face}:`),
        `${c.face} must lead with its code, got: ${first}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D2 a journal refusal names a repair', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    const res = cli(['migrate', '--ledger', j.file]);
    assert.strictEqual(res.status, 1, `expected a refusal, got exit ${res.status}`);
    assert.ok(voice(res.stderr).hasFix,
      `the refusal must carry a fix: line, got: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D3 the repair names only commands this CLI offers', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    const res = cli(['migrate', '--ledger', j.file]);
    const re = /signerd\s+([a-z][a-z-]*)/g;
    let m;
    while ((m = re.exec(res.stderr)) !== null) {
      assert.ok(KNOWN_COMMANDS.includes(m[1]),
        `the repair names a command this CLI does not offer: signerd ${m[1]}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D4 no repair carries a host path', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    const res = cli(['migrate', '--ledger', j.file]);
    assert.ok(!/\/home\/|\/Users\/|\/root\//.test(res.stderr),
      `the repair must not carry a host path: ${res.stderr}`);
    // And it must not carry the operator's own path either: the repair
    // uses a placeholder, not the path that was passed in.
    assert.ok(!res.stderr.includes(dir),
      `the repair must not repeat the operator's path: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D5 the exit code is unchanged: a refusal still exits 1', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    assert.strictEqual(cli(['migrate', '--ledger', j.file]).status, 1);
    assert.strictEqual(cli(['migrate', '--ledger', path.join(dir, 'absent.jsonl')]).status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D6 a legal migration still succeeds and stays silent on stderr', () => {
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    const res = cli(['migrate', '--ledger', j.file, '--discard-legacy']);
    assert.strictEqual(res.status, 0, `a legal migration must succeed: ${res.stderr}`);
    assert.match(res.stdout, /"ok":true/);
    assert.strictEqual(res.stderr, '',
      `a legal migration must stay silent on stderr: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('D7 the loader\'s refusals carry their CODE on the error object', () => {
  // A caller that branches on `err.code` must be able to tell the journal
  // refusals apart. Before the fix the loader raised a bare Error, so the
  // code lived only in the message and every journal refusal was
  // indistinguishable to a caller.
  const { Ledger } = require(path.join(ROOT, 'src', 'ledger.js'));
  const dir = tmpDir();
  try {
    const j = legacyJournal(dir, 'legacy.jsonl');
    const lines = j.lines.map((l) => JSON.parse(l));
    lines[1].a = '999999';
    const tampered = path.join(dir, 'tampered.jsonl');
    fs.writeFileSync(tampered, lines.map((r) => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });
    let caught = null;
    try {
      // eslint-disable-next-line no-new
      new Ledger({ file: tampered });
    } catch (err) {
      caught = err;
    }
    assert.ok(caught, 'a tampered journal must be refused');
    assert.strictEqual(caught.code, 'ledger_tampered',
      `the error must carry its code, got ${JSON.stringify(caught.code)}`);
    assert.match(caught.message, /ledger_tampered/,
      'the message keeps naming the refusal too');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
