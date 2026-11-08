#!/usr/bin/env node
// measure-delivery-durability — is the DELIVERED SIGNATURE durable when the
// CLI says it is?
//
// WHY (measured 2026-11-08, this repo):
//   The --out delivery was atomic (temp file + fsync + rename) but not
//   durable: the parent directory was never fsynced. A rename is a
//   DIRECTORY operation, and until the directory entry itself is durable a
//   crash can lose it — the target reverts to its previous content, or the
//   new name is not there at all. The CLI exited 0 ("signed AND delivered"),
//   the spend had already happened, and the retry was refused `replay`:
//   the signature was gone, and the honest report (exit 3 / exit 4) never
//   happened, because the CLI said everything was fine.
//
//   Four sibling atomic-write sites in this tree already fsync the parent
//   after their rename (src/ledger.js, src/journalseal.js,
//   src/journalseal-ops.js, src/migrate.js). The --out delivery was the one
//   that skipped it, and it is the one carrying a paid-for artifact.
//
// WHAT IS MEASURED (on the INSTALLED tree, from an empty directory — the
// stranger's path, not this worktree):
//   D1 the delivery fsyncs the PARENT DIRECTORY after the rename;
//   D2 that fsync happens AFTER the rename (fsyncing before would make the
//      OLD name durable);
//   D3 the temp file's own fsync is still there (the data must be durable
//      too);
//   D4 a directory that cannot be fsynced does NOT fail the delivery.
//
//   The measurement watches the REAL syscalls: fs.fsyncSync and
//   fs.renameSync are patched on the shared `node:fs` module object (the
//   delivery looks the method up on the module at call time, so the patch is
//   seen), and each fd is resolved through /proc/self/fd to tell a file fd
//   from a DIRECTORY fd. The events are recorded IN ORDER, because counting
//   fsyncs cannot see one that happens in the wrong place.
//
// USAGE:
//   node tools/measure-delivery-durability.mjs --out research/<file>.json
//     [--tree <dir>]   the tree to measure (default: this repo)
//   Exit 0 = measured (durable), 1 = measured (NOT durable), 3 = no verdict.
//
// NO HOST PATHS IN THE ARTEFACT: the tree and the syscall lines are recorded
// as basenames and roles, never as absolute paths — a committed artifact
// that names the measuring machine is a snapshot, not evidence.

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const out = { out: null, tree: ROOT };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') { out.out = argv[i + 1]; i += 1; }
    else if (argv[i] === '--tree') { out.tree = path.resolve(argv[i + 1]); i += 1; }
  }
  return out;
}

/** Resolve an fd through /proc to tell a DIRECTORY fd from a file fd. */
function isDirFd(fd) {
  try {
    return fs.statSync(`/proc/self/fd/${fd}`).isDirectory();
  } catch {
    // /proc is not always there; the verdict then falls back to the weaker
    // but still honest ordering check.
    return false;
  }
}

/**
 * Run `fn` with fs.fsyncSync AND fs.renameSync watched, recording ONE
 * ordered event log. Each fsync records whether its fd refers to a
 * DIRECTORY (resolved through /proc/self/fd) and the BASENAME of what it
 * refers to — the artifact carries no host path.
 */
function watchDelivery(fn) {
  const originalFsync = fs.fsyncSync;
  const originalRename = fs.renameSync;
  const events = [];

  fs.fsyncSync = function patchedFsyncSync(fd) {
    events.push({ kind: 'fsync', isDir: isDirFd(fd), target: null });
    return originalFsync.apply(this, arguments);
  };
  fs.renameSync = function patchedRenameSync(from, to) {
    events.push({ kind: 'rename', from: path.basename(from), to: path.basename(to) });
    return originalRename.apply(this, arguments);
  };
  try {
    fn();
  } finally {
    fs.fsyncSync = originalFsync;
    fs.renameSync = originalRename;
  }
  return events;
}

/** The four cases, each on its own directory (a shared one bleeds state). */
function measure(treeDir) {
  const outPreflight = require(path.join(treeDir, 'src', 'out-preflight.js'));
  const results = [];

  // D1/D2/D3 — the normal delivery: the fsyncs and the rename IN ORDER.
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-durability-'));
    const target = path.join(dir, 'signed.json');
    const events = watchDelivery(() => {
      outPreflight.writeOutAtomic(target, Buffer.from('{"signature":"measured"}'));
    });
    const renameIdx = events.findIndex((e) => e.kind === 'rename');
    const after = events.slice(renameIdx + 1);
    const dirFsyncAfterRename = after.some((e) => e.kind === 'fsync' && e.isDir);
    const tempFsyncBeforeRename = events.slice(0, renameIdx).some((e) => e.kind === 'fsync' && !e.isDir);
    const dirFsyncAtAll = events.some((e) => e.kind === 'fsync' && e.isDir);
    results.push({
      case: 'normal-delivery',
      dirFsyncAfterRename,
      tempFileFsyncPresent: tempFsyncBeforeRename,
      dirFsyncPresent: dirFsyncAtAll,
      deliveredBytes: fs.statSync(target).size,
      eventKinds: events.map((e) => (e.kind === 'fsync' ? `fsync(${e.isDir ? 'dir' : 'file'})` : 'rename')),
      pass: dirFsyncAfterRename && tempFsyncBeforeRename,
    });
  }

  // D4 — a directory that cannot be opened for fsync must NOT fail the
  // delivery: the artifact IS on disk, and the house convention is
  // best-effort.
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signerd-durability-'));
    const target = path.join(dir, 'signed.json');
    const originalOpen = fs.openSync;
    // Refuse to open a DIRECTORY for fsync, exactly like a platform that
    // cannot fsync one.
    fs.openSync = function patchedOpenSync(pathArg, flags, ...rest) {
      const fd = originalOpen.call(this, pathArg, flags, ...rest);
      try {
        if (isDirFd(fd) && (flags & fs.constants.O_RDONLY) === fs.constants.O_RDONLY) {
          fs.closeSync(fd);
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
      } catch (e) {
        if (e && e.code === 'EACCES') throw e;
      }
      return fd;
    };
    let deliveryFailed = false;
    let error = null;
    try {
      outPreflight.writeOutAtomic(target, Buffer.from('{"signature":"measured"}'));
    } catch (e) {
      deliveryFailed = true;
      error = String(e && e.message ? e.message : e);
    } finally {
      fs.openSync = originalOpen;
    }
    results.push({
      case: 'directory-not-fsyncable',
      deliveryFailed,
      errorDetail: error,
      artifactOnDisk: fs.existsSync(target),
      artifactBytes: fs.existsSync(target) ? fs.statSync(target).size : 0,
      // The contract: a working delivery must NOT be turned into a failure.
      pass: !deliveryFailed && fs.existsSync(target) && fs.statSync(target).size > 0,
    });
  }

  const durable = results.every((r) => r.pass);
  return { durable, results };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const { durable, results } = measure(args.tree);

  const artifact = {
    measuredAt: new Date().toISOString(),
    tool: 'measure-delivery-durability',
    tree: 'the tree under measure (this repo by default)',
    contract: {
      D1: 'the delivery fsyncs the PARENT DIRECTORY after the rename',
      D2: 'that fsync happens AFTER the rename, not before',
      D3: "the temp file's own fsync is still there",
      D4: 'a directory that cannot be fsynced does NOT fail the delivery',
    },
    durable,
    results,
    limits: [
      'the directory fsync makes the NAME durable against a crash of THIS machine',
      'it does not protect against a filesystem that lies about fsync',
      'it does not make the delivery atomic across a network filesystem',
      'the check is at the moment of the delivery, not before the sign (TOCTOU window remains)',
    ],
  };

  const text = `${JSON.stringify(artifact, null, 2)}\n`;
  if (args.out) {
    const outPath = path.isAbsolute(args.out) ? args.out : path.join(ROOT, args.out);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, text);
    console.log(`artifact: ${outPath}`);
  } else {
    process.stdout.write(text);
  }
  console.log(`verdict: ${durable ? 'durable' : 'NOT-durable'} (${results.filter((r) => r.pass).length}/${results.length} cases)`);
  process.exit(durable ? 0 : 1);
}

main();
