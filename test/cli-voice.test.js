'use strict';

// THE CLI VOICE SURFACE: a refusal the CLI PRINTS ITSELF names a fix.
//
// WHY (measured 2026-11-18, live, on this tree 4a2ae5f):
//
// The refusal voice has been closed class by class — the daemon's verdicts
// (v0.2.34), the journal-integrity family (v0.2.36), the build-tx value
// inputs (v0.2.37). What remained is the LAST class: the refusals
// bin/signerd.js prints ITSELF, outside the generic tail, each written by
// hand at its own site. Measured faces, pre-fix:
//
//   keygen --keystore <an existing keystore file>
//     -> `keystore_exists: `  — empty detail, NO fix, while the sibling
//        `import` path names `--overwrite` for the same verdict
//        (test/import-repair-surface.test.js pins THAT path only).
//   keygen --keystore <a directory> --overwrite
//     -> `keystore_write_failed: <path>: EISDIR` — a raw errno as the
//        "reason", no fix.
//   import --from <a readable file that is not a key>
//     -> `secret_key_invalid: base58` — the three ACCEPTED source formats
//        (id.json / base58 / raw 64 bytes) are named nowhere.
//   sign-message --body <not JSON> / <a JSON array>
//     -> `body_invalid: not JSON` / `body_invalid: expected a JSON object`
//        — NO fix, although src/refusal-voice.js already carries a repair
//        for exactly this code (and the generic tail would print it if
//        these two sites threw instead of hand-printing).
//   grant-add without --signer and --keystore
//     -> prose with NO code and NO fix (every sibling refusal carries a
//        code a caller can branch on).
//   keygen --passphrase-file <a file another uid owns>
//     -> code-less, fix-less.
//
// The class is the same defect every earlier voice pulse fixed elsewhere:
// a code names a condition; it does not tell the operator what to DO.
// The README promises the opposite: "Refusals name the flag and the fix
// instead of failing silently."
//
// THE CONTRACT (D = defect face, G = guard):
//   D1 an existing keystore file refuses keystore_exists WITH a fix line;
//   D2 the fix names --overwrite (the flag this command actually takes);
//   D3 a directory at the keystore path refuses with a fix, and the
//      refusal is NOT a raw errno line;
//   D4 import of a non-key source refuses secret_key_invalid WITH a fix
//      that names the accepted source formats;
//   D5 a --body that is not a JSON object answers body_invalid WITH the
//      repair the refusal-voice map already carries (fix line present,
//      names --body);
//   D6 grant-add without --signer/--keystore answers WITH a code and a
//      fix line (the shape every sibling refusal has);
//   D7 a passphrase file owned by another uid refuses with a fix line
//      (chown) — the condition stays refused, the voice names the repair.
//   G1 an existing keystore is still REFUSED (exit != 0) and, without
//      --overwrite, the file is left untouched;
//   G2 keygen --overwrite on a real file still replaces it (exit 0);
//   G3 a valid import still succeeds (exit 0);
//   G4 a valid JSON-object --body is not refused as body_invalid (the run
//      proceeds to the socket refusal);
//   G5 grant-add WITH --keystore does not answer the missing-signer code;
//   G6 a passphrase file the operator owns is accepted (exit 0).
//   X  every D face exits 2 (usage/preflight, docs/GUIDE.md's exit table):
//      exit 1 is reserved for the daemon's/policy's verdict, and none of
//      these faces ever reached a daemon.
//
// HOW THE TREE IS BUILT: the checkout's own CLI in a sandbox. No network,
// no daemon, no key material beyond throwaway test keys.
//
// THE LADDER: D1-D7 are RED on the pre-fix tree 4a2ae5f, the guards GREEN
// on both trees (measured; see the mutation ladder
// tools/mutation-ladder-cli-voice.sh).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'signerd.js');
const DEST = 'So11111111111111111111111111111111111111112';

function sh(args, opts = {}) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 60000,
    ...opts,
  });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function sandbox(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-clivoice-'));
  t.after(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  const sb = path.join(dir, 'sb');
  fs.mkdirSync(sb, { mode: 0o700 });
  const pass = path.join(sb, 'pass');
  fs.writeFileSync(pass, 'cli-voice passphrase\n', { mode: 0o600 });
  return { dir, sb, pass };
}

/** A valid solana-keygen style id.json (the real adoption input). */
function writeIdJson(file) {
  const { Keypair } = require(path.join(ROOT, 'node_modules', '@solana', 'web3.js'));
  const kp = Keypair.generate();
  fs.writeFileSync(file, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
  return kp.publicKey.toBase58();
}

function firstCode(stderr) {
  const line = String(stderr).split('\n').find((l) => l.trim().length > 0) || '';
  return (line.split(':')[0] || '').trim();
}

function hasFix(stderr) {
  return /(^|\n)\s*fix:/.test(String(stderr));
}

test('D1/D2: keygen onto an existing keystore refuses keystore_exists and names --overwrite', (t) => {
  const { sb, pass } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  assert.strictEqual(sh(['keygen', '--keystore', ks, '--passphrase-file', pass]).status, 0,
    'the first keygen must succeed');
  const before = fs.readFileSync(ks);
  const res = sh(['keygen', '--keystore', ks, '--passphrase-file', pass]);
  assert.notStrictEqual(res.status, 0, 'the second keygen must be refused');
  assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
  assert.strictEqual(firstCode(res.stderr), 'keystore_exists',
    `the code must be the refusal's own name: ${res.stderr}`);
  assert.ok(hasFix(res.stderr), `the refusal must name a repair: ${res.stderr}`);
  assert.match(res.stderr, /--overwrite/,
    `the fix must name the flag this command takes: ${res.stderr}`);
  assert.deepStrictEqual(fs.readFileSync(ks).equals(before), true,
    'a refused keygen must leave the keystore untouched');
});

test('D3: keygen --overwrite onto a DIRECTORY refuses with a fix, not a bare errno', (t) => {
  const { sb, pass } = sandbox(t);
  const target = path.join(sb, 'adir');
  fs.mkdirSync(target, { mode: 0o700 });
  const res = sh(['keygen', '--keystore', target, '--passphrase-file', pass, '--overwrite']);
  assert.notStrictEqual(res.status, 0, 'a directory must be refused');
  assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
  const code = firstCode(res.stderr);
  assert.ok(/^[a-z_]+$/.test(code), `the first line must carry a code, got: ${res.stderr}`);
  assert.ok(hasFix(res.stderr), `the refusal must name a repair: ${res.stderr}`);
  assert.match(code, /keystore/,
    `the refusal must name the keystore surface, got code: ${code}`);
  assert.ok(!/EISDIR|ENOTDIR|ENOTEMPTY/.test(res.stderr.split('\n')[0]),
    `the reason must not be a bare errno token: ${res.stderr}`);
  assert.strictEqual(fs.existsSync(target) && fs.statSync(target).isDirectory(), true,
    'a refused keygen must leave the directory untouched');
});

test('D4: import of a non-key source names the accepted formats in its fix', (t) => {
  const { sb, pass } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  assert.strictEqual(sh(['keygen', '--keystore', ks, '--passphrase-file', pass]).status, 0);
  const bad = path.join(sb, 'not-a-key.txt');
  fs.writeFileSync(bad, 'this is not a key\n', { mode: 0o600 });
  const res = sh(['import', '--keystore', ks, '--from', bad, '--passphrase-file', pass, '--overwrite']);
  assert.notStrictEqual(res.status, 0, 'a non-key source must be refused');
  assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
  assert.strictEqual(firstCode(res.stderr), 'secret_key_invalid',
    `the code must be the refusal's own name: ${res.stderr}`);
  assert.ok(hasFix(res.stderr), `the refusal must name a repair: ${res.stderr}`);
  // ALL THREE accepted source formats must be named. Measured 2026-11-18:
  // a gate that only looked for `id.json` stayed green on a face that had
  // lost the base58 and raw-64-byte formats (the example command line
  // still mentioned id.json) - the ladder's M5 was vacuous until this
  // assertion was tightened.
  assert.match(res.stderr, /id\.json/,
    `the fix must name the id.json format: ${res.stderr}`);
  assert.match(res.stderr, /base58/,
    `the fix must name the base58 format: ${res.stderr}`);
  assert.match(res.stderr, /64/,
    `the fix must name the raw 64-byte format: ${res.stderr}`);
});

test('D5: a --body that is not a JSON object answers body_invalid WITH its repair', (t) => {
  const { sb } = sandbox(t);
  const notJson = path.join(sb, 'not-json.json');
  fs.writeFileSync(notJson, 'not json at all\n', { mode: 0o600 });
  const arr = path.join(sb, 'arr.json');
  fs.writeFileSync(arr, '[1,2]\n', { mode: 0o600 });
  const sock = path.join(sb, 'never.sock');
  for (const body of [notJson, arr]) {
    const res = sh(['sign-message', '--socket', sock, '--grant', 'g', '--body', body]);
    assert.notStrictEqual(res.status, 0, `${body} must be refused`);
    assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
    assert.strictEqual(firstCode(res.stderr), 'body_invalid',
      `the code must survive: ${res.stderr}`);
    assert.ok(hasFix(res.stderr),
      `the refusal must carry the repair the voice map already holds: ${res.stderr}`);
    assert.match(res.stderr, /--body/, `the fix must name --body: ${res.stderr}`);
  }
});

test('D6: grant-add without --signer/--keystore answers with a code and a fix', (t) => {
  const { sb } = sandbox(t);
  const grants = path.join(sb, 'grants.json');
  const res = sh(['grant-add', '--grants', grants, '--name', 'n',
    '--destination', DEST, '--max-lamports', '1000',
    '--window-max-lamports', '5000', '--window-seconds', '60',
    '--expires', '2030-01-01T00:00:00Z']);
  assert.notStrictEqual(res.status, 0, 'the invocation must be refused');
  assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
  const code = firstCode(res.stderr);
  assert.ok(/^[a-z_]+$/.test(code) && code !== 'signerd',
    `the refusal must carry a code, got: ${res.stderr}`);
  assert.ok(hasFix(res.stderr), `the refusal must name a repair: ${res.stderr}`);
  assert.match(res.stderr, /--keystore/, `the fix must name a real flag: ${res.stderr}`);
});

test('D7: a passphrase file owned by ANOTHER UID refuses with a chown fix', (t) => {
  const { sb } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  const foreign = path.join(sb, 'foreign.pass');
  fs.writeFileSync(foreign, 'someone else wrote this\n', { mode: 0o600 });
  const res0 = (() => {
    try { fs.chownSync(foreign, 65534, 65534); return null; } catch { return 'direct'; }
  })();
  if (res0 !== null) {
    const sudo = spawnSync('sudo', ['-n', 'chown', '65534:65534', foreign],
      { encoding: 'utf8', timeout: 15000 });
    if (sudo.status !== 0) {
      t.skip('chown to a foreign uid is not permitted in this environment');
      return;
    }
  }
  t.after(() => {
    try { spawnSync('sudo', ['-n', 'chown', `${process.getuid()}:${process.getgid()}`, foreign], { timeout: 15000 }); } catch { /* best effort */ }
  });
  const res = sh(['keygen', '--keystore', ks, '--passphrase-file', foreign]);
  assert.notStrictEqual(res.status, 0, 'a foreign-owned passphrase file must be refused');
  assert.strictEqual(res.status, 2, `a usage refusal exits 2: ${res.stderr}`);
  const code = firstCode(res.stderr);
  assert.ok(/^[a-z_]+$/.test(code), `the refusal must carry a code, got: ${res.stderr}`);
  assert.ok(hasFix(res.stderr), `the refusal must name a repair: ${res.stderr}`);
  assert.match(res.stderr, /chown/, `the fix must name chown: ${res.stderr}`);
});

// ---- GUARDS: the conditions stay refused; the legal paths keep working. ----

test('G2: keygen --overwrite on a real file still replaces it (exit 0)', (t) => {
  const { sb, pass } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  assert.strictEqual(sh(['keygen', '--keystore', ks, '--passphrase-file', pass]).status, 0);
  const res = sh(['keygen', '--keystore', ks, '--passphrase-file', pass, '--overwrite']);
  assert.strictEqual(res.status, 0, `--overwrite must still replace: ${res.stderr}`);
  const doc = JSON.parse(res.stdout.trim().split('\n').pop());
  assert.ok(doc.publicKey, 'the replacement must print the new public key');
  // G1 again, after the overwrite: still refused without --overwrite.
  const again = sh(['keygen', '--keystore', ks, '--passphrase-file', pass]);
  assert.notStrictEqual(again.status, 0, 'without --overwrite it must stay refused');
});

test('G3: a valid import still succeeds', (t) => {
  const { sb, pass } = sandbox(t);
  const idJson = path.join(sb, 'id.json');
  writeIdJson(idJson);
  const ks = path.join(sb, 'ops.key');
  const res = sh(['import', '--keystore', ks, '--from', idJson, '--passphrase-file', pass]);
  assert.strictEqual(res.status, 0, `a valid import must succeed: ${res.stderr}`);
});

test('G4: a real JSON-object body is not refused as body_invalid', (t) => {
  const { sb } = sandbox(t);
  const good = path.join(sb, 'body.json');
  fs.writeFileSync(good, JSON.stringify({
    schema: 'openreceipts/v1', issuer: 'x', type: 'y', subject: 'z',
    claims: {}, issued_at: new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  }), { mode: 0o600 });
  const sock = path.join(sb, 'never.sock');
  const res = sh(['sign-message', '--socket', sock, '--grant', 'g', '--body', good]);
  assert.notStrictEqual(firstCode(res.stderr), 'body_invalid',
    `a valid object must pass the shape check: ${res.stderr}`);
});

test('G5: grant-add WITH --keystore does not answer the missing-signer code', (t) => {
  const { sb, pass } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  assert.strictEqual(sh(['keygen', '--keystore', ks, '--passphrase-file', pass]).status, 0);
  const grants = path.join(sb, 'grants.json');
  const res = sh(['grant-add', '--grants', grants, '--name', 'n', '--keystore', ks,
    '--destination', DEST, '--max-lamports', '1000',
    '--window-max-lamports', '5000', '--window-seconds', '60',
    '--expires', '2030-01-01T00:00:00Z']);
  assert.strictEqual(res.status, 0, `grant-add with --keystore must succeed: ${res.stderr}`);
});

test('G6: an own-uid passphrase file is still accepted', (t) => {
  const { sb, pass } = sandbox(t);
  const ks = path.join(sb, 'ops.key');
  const res = sh(['keygen', '--keystore', ks, '--passphrase-file', pass]);
  assert.strictEqual(res.status, 0, `an owner passphrase file must be accepted: ${res.stderr}`);
});
