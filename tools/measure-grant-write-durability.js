#!/usr/bin/env node
// Measure the grant-file write durability on TWO trees: the PRE-FIX tree and
// the FIXED tree, with the SAME probe.
//
// WHAT IT MEASURES: whether a grant-file write (create / append / remove)
// makes the DIRECTORY ENTRY durable — i.e. whether the parent directory is
// fsynced after the rename, and whether the temp file itself is fsynced.
//
// The probe patches fs.fsyncSync and fs.renameSync on the shared node:fs
// module object (src/grantadd.js looks the methods up on the module at call
// time) and resolves each fd through /proc/self/fd to tell a file fd from a
// DIRECTORY fd.
//
// WHY THE PROBE IS INSTRUMENTED AND NOT OBSERVED FROM OUTSIDE: the write is
// atomic and fast; a strace of the whole CLI would also capture the loader's
// reads. The event log is exactly the write path.
//
// Usage:
//   node tools/measure-grant-write-durability.js --out research/<file>.json
//   node tools/measure-grant-write-durability.js --out ... --prefix <sha>
// The prefix tree is materialized with `git archive <sha>` into a temp dir.
//
// EXIT: 0 when the measurement itself is sound (the pre-fix tree SHOWS the
// defect — otherwise the instrument is broken and this tool fails), 1 when the
// fixed tree still shows a defect.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const args = process.argv.slice(2);
function opt(name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}

const OUT = opt('out', null);
const PREFIX = opt('prefix', null);
const REPO = path.resolve(__dirname, '..');

const GRANT = {
  signer: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
  destination: '8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR',
  maxLamports: '100000',
  windowMaxLamports: '1000000',
  windowSeconds: '60',
  expiresAt: '2099-01-01T00:00:00Z',
};

/** Run `fn` with fsync/rename watched; returns the ordered event log. */
function watch(fn) {
  const originalFsync = fs.fsyncSync;
  const originalRename = fs.renameSync;
  const events = [];
  fs.fsyncSync = function watched(fd) {
    let isDir = false;
    let target = null;
    try {
      target = fs.readlinkSync(`/proc/self/fd/${fd}`);
      isDir = fs.statSync(`/proc/self/fd/${fd}`).isDirectory();
    } catch { /* /proc may be absent */ }
    events.push({ kind: 'fsync', isDir, target });
    return originalFsync.call(fs, fd);
  };
  fs.renameSync = function watched(from, to) {
    events.push({ kind: 'rename', from, to });
    return originalRename.call(fs, from, to);
  };
  try {
    fn();
  } finally {
    fs.fsyncSync = originalFsync;
    fs.renameSync = originalRename;
  }
  return events;
}

/** The event facts of one write: dir fsync present? after the rename? */
function facts(events) {
  const fsyncs = events.filter((e) => e.kind === 'fsync');
  const dirFsyncs = fsyncs.filter((e) => e.isDir);
  const fileFsyncs = fsyncs.filter((e) => !e.isDir);
  const renameIdx = events.findIndex((e) => e.kind === 'rename');
  const dirIdx = events.findIndex((e) => e.kind === 'fsync' && e.isDir);
  return {
    dirFsyncCount: dirFsyncs.length,
    tempFileFsyncCount: fileFsyncs.length,
    renameSeen: renameIdx >= 0,
    dirFsyncAfterRename: renameIdx >= 0 && dirIdx > renameIdx,
    order: events.map((e) => e.kind + (e.isDir ? '(dir)' : '')),
  };
}

/** Measure one tree's three write paths. */
function measureTree(root) {
  const grantadd = require(path.join(root, 'src', 'grantadd.js'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-durability-'));
  const file = path.join(dir, 'grants.json');

  const createEvents = watch(() => {
    grantadd.writeGrantFile({ file, name: 'one', grant: GRANT });
  });
  const appendEvents = watch(() => {
    grantadd.extendGrantFile({ file, name: 'two', grant: GRANT });
  });
  const removeEvents = watch(() => {
    grantadd.removeGrantFromFile({ file, name: 'two' });
  });

  const out = {
    create: facts(createEvents),
    append: facts(appendEvents),
    remove: facts(removeEvents),
  };
  // The document the revocation left behind: the revoked grant must be gone.
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    out.removalApplied = Object.keys(doc.grants).join(',');
  } catch (err) {
    out.removalApplied = `unreadable: ${err.code || err.message}`;
  }
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

function main() {
  const fixed = measureTree(REPO);
  const result = {
    tool: 'tools/measure-grant-write-durability.js',
    generatedAt: '2026-11-11',
    measuredAt: new Date().toISOString(),
    fixed,
  };

  if (PREFIX) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-prefix-'));
    const tree = path.join(tmp, 'tree');
    fs.mkdirSync(tree);
    const tarFd = fs.openSync(path.join(tree, 'out.tar'), 'w');
    try {
      execFileSync('git', ['archive', PREFIX], {
        cwd: REPO,
        stdio: ['ignore', tarFd, 'inherit'],
        maxBuffer: 64 * 1024 * 1024,
      });
    } finally {
      fs.closeSync(tarFd);
    }
    execFileSync('tar', ['-xf', path.join(tree, 'out.tar'), '-C', tree]);
    fs.rmSync(path.join(tree, 'out.tar'));
    // The prefix tree ships source only; its requires need the same
    // dependency tree the working checkout has (an instrument necessity, not
    // a product path).
    fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(tree, 'node_modules'), 'dir');
    result.prefixSha = PREFIX;
    result.prefix = measureTree(tree);
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  const defectsIn = (m) => {
    const missing = [];
    for (const key of ['create', 'append', 'remove']) {
      const f = m[key];
      if (f.dirFsyncCount < 1) missing.push(`${key}: no directory fsync`);
      else if (f.renameSeen && !f.dirFsyncAfterRename) missing.push(`${key}: directory fsync not after the rename`);
      if (f.tempFileFsyncCount < 1) missing.push(`${key}: no temp-file fsync`);
    }
    return missing;
  };

  result.prefixDefects = result.prefix ? defectsIn(result.prefix) : null;
  result.fixedDefects = defectsIn(fixed);
  result.verdict = result.fixedDefects.length === 0
    ? (result.prefix && result.prefixDefects.length > 0 ? 'fixed' : 'no-defect-visible')
    : 'defect-present';

  // The instrument must be able to SEE the defect: if the pre-fix tree shows
  // nothing, the measurement proves nothing.
  if (result.prefix && result.prefixDefects.length === 0) {
    console.error('NO VERDICT: the pre-fix tree shows no defect — the instrument is broken');
    process.exit(2);
  }
  if (result.fixedDefects.length > 0) {
    console.error(`defect still present: ${result.fixedDefects.join('; ')}`);
    process.exit(1);
  }

  if (OUT) {
    fs.mkdirSync(path.dirname(path.resolve(OUT)), { recursive: true });
    fs.writeFileSync(path.resolve(OUT), JSON.stringify(result, null, 2) + '\n');
  }
  console.log(JSON.stringify(result, null, 2));
}

main();
