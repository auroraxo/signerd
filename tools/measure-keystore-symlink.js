#!/usr/bin/env node
'use strict';
// TWO-TREE MEASUREMENT: does the KEYSTORE path follow symlinks, or does it
// refuse them by name like the grant path has since v0.2.20/v0.2.21?
//
// The grant side is pinned history (grant_file_symlink: writeGrantFile,
// appendGrantToFile, extendGrantFile, seal-grants — all refuse a link at the
// path before the first byte, and loadGrantFile reads with O_NOFOLLOW). The
// keystore side is the SAME kind of file — it holds the encrypted secret the
// daemon signs with, behind the same mode/owner/directory rules — and it was
// never swept. This tool asks the product's own functions, no shell:
//
//   K1  keygen onto a symlink to an EXISTING file (no --overwrite):
//       defect face = the write goes THROUGH the link (or the verdict names
//       the wrong thing); fixed face = keystore_symlink, victim untouched.
//   K2  keygen onto a DANGLING symlink, no --overwrite: existsSync follows,
//       sees nothing, and writeFileSync CREATES THE TARGET OUTSIDE the path
//       the operator named. Fixed: refused by name, nothing created anywhere.
//   K3  keygen --overwrite onto a symlink to an existing file: the documented
//       operator repair must not become an arbitrary-file-overwrite
//       primitive. Fixed: keystore_symlink, victim byte-identical.
//   K4  import onto a symlink (with --overwrite): the migration path uses the
//       same writer, so it must carry the same rule. Fixed: refused.
//   K5  loadKeystore through a symlink: the judge of the state. Fixed:
//       refused by name (the grant loader has refused links via O_NOFOLLOW
//       all along; the keystore loader followed them and reported the mode
//       of whatever it landed on).
//   K6  readKeystorePublicKey through a symlink: same surface, same rule.
//   K7  the write itself: an interrupted keystore write must not be able to
//       leave a TRUNCATED secret document. Measured by construction: the
//       writer creates a same-directory temp (O_EXCL), fsyncs, and renames.
//       Detection: after a writeKeystore that fails AFTER the document was
//       built (secret invalid is caught earlier; here we wrap fs so that the
//       rename reveals whether a temp+rename path is used at all), the
//       published file is either absent or the OLD complete bytes — never a
//       truncated prefix.
//
// Guards (must be GREEN on BOTH trees, so the measurement cannot pass by
// breaking the ordinary path):
//   G1  keygen -> load -> public key round trip on a real file; mode 0600;
//       no leftover temp files in the directory.
//   G2  keygen onto a REAL existing file without --overwrite stays
//       keystore_exists.
//   G3  loadKeystore keeps refusing loose modes (0644 -> keystore_mode).
//
// NO HOST PATHS in the artifact: basenames only.
//
// Usage:
//   node tools/measure-keystore-symlink.js --tree <dir-of-src>  [--out file]
// The runner (see the research artifact) materialises a tree with
// `git archive v0.2.21 | tar -x` and points --tree at it.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}

const TREE = path.resolve(arg('tree', process.cwd()));
const OUT = arg('out', '');
const KS = path.join(TREE, 'src', 'keystore.js');
if (!fs.existsSync(KS)) {
  process.stderr.write(`no src/keystore.js under --tree ${TREE}\n`);
  process.exit(2);
}
// bs58 + web3 live in the repo working tree; the extracted tree may not ship
// node_modules, so resolve deps from there when absent.
const DEPS = fs.existsSync(path.join(TREE, 'node_modules')) ? TREE : process.cwd();
const Module = require('node:module');
const origResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (!request.startsWith('.') && !request.startsWith('node:')) {
    try {
      return origResolve.call(this, path.join(DEPS, 'node_modules', request), ...rest);
    } catch { /* fall through to normal resolution */ }
  }
  return origResolve.call(this, request, ...rest);
};
const { createKeystore, loadKeystore, writeKeystore, importKeystore, readKeystorePublicKey } = require(KS);

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'ks-sym-')); }
function isSymlink(p) { try { return fs.lstatSync(p).isSymbolicLink(); } catch { return false; } }
function codeOf(fn) {
  try { fn(); return { threw: false }; }
  catch (err) { return { threw: true, code: err && err.code ? String(err.code) : String(err && err.message) }; }
}

const results = [];
function face(id, expectRefusal, run) {
  const r = run();
  r.id = id;
  r.expected = expectRefusal ? 'named refusal, nothing touched outside the named path' : 'unchanged behaviour';
  results.push(r);
  return r;
}

// K1: symlink to existing victim, no overwrite
face('K1', true, () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(victim, link);
  const outcome = codeOf(() => createKeystore({ file: link, passphrase: 'p' }));
  const after = fs.readFileSync(victim, 'utf8');
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    victimOverwrittenThroughLink: after !== original,
    defect: !outcome.threw || after !== original || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K2: dangling symlink, no overwrite
face('K2', true, () => {
  const dir = tmp();
  const outside = tmp();
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(path.join(outside, 'ops.key'), link);
  const outcome = codeOf(() => createKeystore({ file: link, passphrase: 'p' }));
  const createdOutside = fs.existsSync(path.join(outside, 'ops.key'));
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    createdThroughDanglingLinkOutsideNamedPath: createdOutside,
    defect: createdOutside || !outcome.threw || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K3: --overwrite through a symlink is not an arbitrary-overwrite primitive
face('K3', true, () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(victim, link);
  const outcome = codeOf(() => createKeystore({ file: link, passphrase: 'p', overwrite: true }));
  const after = fs.readFileSync(victim, 'utf8');
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    victimOverwrittenThroughLink: after !== original,
    defect: after !== original || !outcome.threw || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K4: import (migration writer) onto a symlink
face('K4', true, () => {
  const dir = tmp();
  const victim = path.join(dir, 'victim.dat');
  const original = 'PRECIOUS PRE-EXISTING CONTENT\n';
  fs.writeFileSync(victim, original);
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(victim, link);
  const secret = Buffer.alloc(64, 7); // deterministic 64-byte shape; Keypair derives from it
  let kp;
  try {
    const { Keypair } = require(path.join(DEPS, 'node_modules', '@solana', 'web3.js'));
    // valid keypair so writeKeystore's validation passes and the WRITE is reached
    kp = Keypair.generate();
  } catch { return { refusal: 'harness-error', defect: false, skipped: true }; }
  const outcome = codeOf(() => importKeystore({
    file: link, passphrase: 'p', from: (() => {
      const s = path.join(dir, 'src.id.json');
      fs.writeFileSync(s, JSON.stringify(Array.from(kp.secretKey)));
      return s;
    })(), overwrite: true,
  }));
  const after = fs.readFileSync(victim, 'utf8');
  void secret;
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    victimOverwrittenThroughLink: after !== original,
    defect: after !== original || !outcome.threw || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K5: the LOADER through a symlink
face('K5', true, () => {
  const dir = tmp();
  const real = path.join(dir, 'real.key');
  createKeystore({ file: real, passphrase: 'p' });
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(real, link);
  const outcome = codeOf(() => loadKeystore({ file: link, passphrase: 'p' }));
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    loadedThroughLink: !outcome.threw,
    defect: !outcome.threw || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K6: the public-key reader through a symlink
face('K6', true, () => {
  const dir = tmp();
  const real = path.join(dir, 'real.key');
  createKeystore({ file: real, passphrase: 'p' });
  const link = path.join(dir, 'ops.key');
  fs.symlinkSync(real, link);
  const outcome = codeOf(() => readKeystorePublicKey({ file: link }));
  return {
    refusal: outcome.threw ? outcome.code.split(':')[0] : null,
    readThroughLink: !outcome.threw,
    defect: !outcome.threw || !String(outcome.code).startsWith('keystore_symlink'),
  };
});

// K7: write shape — truncation window. A same-directory temp plus a rename
// means an interrupted write can only leave the OLD complete bytes; an
// in-place writeFileSync truncates the target BEFORE the content exists.
// Method: observe the calls the writer makes and fail the LAST channel that
// can carry the full document — the rename when there is one (no bytes were
// ever written to the target), or the write itself when there is not.
face('K7', true, () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  const oldBytes = fs.readFileSync(file);
  const realWrite = fs.writeFileSync;
  const realRename = fs.renameSync;
  const calls = { directToTarget: 0, renameToTarget: 0 };
  fs.writeFileSync = function (fdOrPath, ...rest) {
    if (fdOrPath === file) calls.directToTarget += 1;
    return realWrite.call(fs, fdOrPath, ...rest);
  };
  fs.renameSync = function (from, to) {
    if (to === file) {
      calls.renameToTarget += 1;
      fs.writeFileSync = realWrite; fs.renameSync = realRename;
      const e = new Error('measured: injected rename failure');
      e.code = 'EIO';
      throw e;
    }
    return realRename.apply(fs, arguments);
  };
  const outcome = codeOf(() => writeKeystore({ file, passphrase: 'p2', secretKey: makeSecret(), overwrite: true }));
  fs.writeFileSync = realWrite; fs.renameSync = realRename;
  const usesAtomicPath = calls.renameToTarget > 0 && calls.directToTarget === 0;
  const intact = fs.readFileSync(file).equals(oldBytes);
  // On the UNFIXED tree the writer truncates the target directly: the
  // injected failure lands inside that write and the published file is torn
  // (0 or prefix bytes) — that is the defect. On the fixed tree the rename
  // never happened and the OLD complete bytes stand untouched.
  return {
    writesThroughRename: calls.renameToTarget > 0,
    truncatesTargetDirectly: calls.directToTarget > 0,
    injectedFailureMadeWriterThrow: outcome.threw,
    publishedFileStillOldCompleteBytes: intact,
    defect: !usesAtomicPath || !intact,
  };
});

function makeSecret() {
  const { Keypair } = require(path.join(DEPS, 'node_modules', '@solana', 'web3.js'));
  return Keypair.generate().secretKey;
}

// Guards
const guards = [];
function guard(id, run) { const r = run(); r.id = id; guards.push(r); return r; }

guard('G1', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  const created = createKeystore({ file, passphrase: 'right' });
  const loaded = loadKeystore({ file, passphrase: 'right' });
  const mode = fs.statSync(file).mode & 0o777;
  const leftovers = fs.readdirSync(dir).filter((n) => n !== 'ops.key');
  const ok = loaded.publicKey.toBase58() === created.publicKey && mode === 0o600 && leftovers.length === 0;
  return { ok, mode: mode.toString(8), leftovers: leftovers.length };
});

guard('G2', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  const outcome = codeOf(() => createKeystore({ file, passphrase: 'p' }));
  return { ok: outcome.threw && outcome.code === 'keystore_exists', code: outcome.code || null };
});

guard('G3', () => {
  const dir = tmp();
  const file = path.join(dir, 'ops.key');
  createKeystore({ file, passphrase: 'p' });
  fs.chmodSync(file, 0o644);
  const outcome = codeOf(() => loadKeystore({ file, passphrase: 'p' }));
  return { ok: outcome.threw && outcome.code === 'keystore_mode', code: outcome.code || null };
});

const violations = results.filter((r) => r.defect === true).length;
const verdict = violations === 0
  ? (results.some((r) => r.skipped) ? 'partly-skipped' : 'keystore-symlink-rule-holds')
  : 'keystore-symlink-defect-present';
const artifact = {
  tool: 'tools/measure-keystore-symlink.js',
  measuredAt: new Date().toISOString(),
  tree: path.basename(TREE) === 'signerd' ? 'working-tree' : 'extracted-tree',
  faces: results,
  guards,
  violations,
  guardFailures: guards.filter((g) => !g.ok).length,
  verdict,
};
const text = JSON.stringify(artifact, null, 2) + '\n';
if (OUT) fs.writeFileSync(OUT, text); else process.stdout.write(text);
process.exit(violations === 0 && guards.every((g) => g.ok) ? 0 : 1);
