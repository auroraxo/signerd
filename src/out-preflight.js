'use strict';

/**
 * Preflight and deliver `--out`.
 *
 * WHY (measured live 2026-11-07, tree b58d378 — the tree that shipped the
 * v0.2.6 preflight):
 *
 * The original check answered for the PATH IT WAS GIVEN, while the write
 * follows symlinks and lands somewhere else. Measured on a live daemon:
 *
 *   * a DANGLING SYMLINK as --out passed (`existsSync` follows the link and
 *     reports "absent", so the target branch never ran) -> the daemon SIGNS
 *     (journal +366 bytes, budget charged, replay identity recorded) -> the
 *     write follows the link -> ENOENT, exit 1, stdout EMPTY -> the retry is
 *     permanently refused `replay`. The signature existed for a millisecond
 *     and is gone.
 *   * a symlink to /dev/full passed (char device, mode 666: only
 *     `isDirectory()` was consulted) -> SIGNS -> ENOSPC -> same loss.
 *   * a FIFO as --out passed (`isFile()` was never asked) -> SIGNS ->
 *     `open(O_WRONLY)` on a FIFO with no reader BLOCKS FOREVER. The daemon
 *     had already been paid for a write that never happens.
 *   * no symlink at all: `ulimit -f 0` makes the path pass every permission
 *     question and still fail the write -> EFBIG after signing.
 *
 * So the preflight now validates the RESOLVED target — the path the write
 * will actually use — and refuses anything that is not a regular file or a
 * creatable path in a writable directory, before a single byte of budget is
 * committed.
 *
 * THE OTHER HALF: the preflight cannot see the future (a full disk, a file
 * tightened between check and write, TOCTOU), so delivery is ATOMIC — write
 * a temp file in the same directory, fsync, then rename. Consequences:
 *   * a FAILED write never touches the previous content of `--out`
 *     (writeFileSync opened with O_TRUNC: measured, a 200-byte file became 0
 *     bytes when the write then threw EFBIG), and
 *   * a successful write lands 0600 regardless of what mode the target had
 *     before (measured: an existing 0644 file kept 0644, so a signed wire
 *     was left world-readable — `writeFileSync`'s mode only applies on
 *     create).
 *
 * The caller decides what a delivery failure MEANS; see `outWriteFix`.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** Symlink hops before we call it a loop — a chain this long is an attack. */
const MAX_SYMLINK_HOPS = 32;

/**
 * Follow the final component's symlink chain and report what is really there.
 *
 * lstat at every hop, never `stat`: the answer we need is "what kind of node
 * sits at the path the write will open", including a link pointing at a node
 * that does not exist yet.
 */
function resolveOutTarget(outPath) {
  const original = path.resolve(outPath);
  let current = original;
  for (let hop = 0; hop <= MAX_SYMLINK_HOPS; hop += 1) {
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        return { ok: true, original, target: current, exists: false, symlinked: current !== original };
      }
      if (err && err.code === 'ELOOP') {
        return {
          ok: false, code: 'out_symlink_loop', path: original, target: current,
          message: `the output path ${original} is a symlink loop`,
        };
      }
      return {
        ok: false, code: 'out_unreadable', path: original, target: current,
        message: `the output path cannot be inspected: ${err && err.message ? err.message : String(err)}`,
      };
    }
    if (!stat.isSymbolicLink()) {
      return {
        ok: true, original, target: current, exists: true, symlinked: current !== original, stat,
      };
    }
    // One hop. Relative link targets resolve against the LINK's directory.
    const link = fs.readlinkSync(current);
    current = path.resolve(path.dirname(current), link);
  }
  return {
    ok: false, code: 'out_symlink_loop', path: original, target: current,
    message: `the output path ${original} is a symlink loop (${MAX_SYMLINK_HOPS}+ hops)`,
  };
}

/**
 * Can a signature be delivered to `outPath`? Answers BEFORE anything is
 * requested or signed, against the resolved node the write will hit.
 *
 * Returns `{ ok: true }` or `{ ok: false, code, path, parent, message }`.
 */
function checkOutWritable(outPath) {
  if (typeof outPath !== 'string' || outPath.length === 0) return { ok: true };

  const resolved = resolveOutTarget(outPath);
  if (!resolved.ok) return resolved;

  // The note about where a link points matters for the repair line.
  const note = resolved.symlinked
    ? ` (the link points at ${resolved.target})`
    : '';

  if (resolved.exists) {
    const stat = resolved.stat;
    if (stat.isDirectory()) {
      return {
        ok: false,
        code: 'out_is_directory',
        path: resolved.original,
        target: resolved.target,
        message: `the output path ${resolved.original} is an existing directory${note}`,
      };
    }
    if (!stat.isFile()) {
      // FIFO, char device, socket, block device: a node we can neither write
      // atomically nor verify afterwards. A FIFO with no reader blocks the
      // open forever; /dev/full accepts the open and fails the write.
      const kind = stat.isFIFO() ? 'a FIFO'
        : stat.isCharacterDevice() ? 'a character device'
          : stat.isSocket() ? 'a socket'
            : stat.isBlockDevice() ? 'a block device'
              : 'not a regular file';
      return {
        ok: false,
        code: 'out_not_regular_file',
        path: resolved.original,
        target: resolved.target,
        message: `the output path ${resolved.original} is ${kind}, not a regular file${note}`,
      };
    }
    try {
      fs.accessSync(resolved.target, fs.constants.W_OK);
    } catch (err) {
      return {
        ok: false,
        code: 'out_unwritable',
        path: resolved.original,
        target: resolved.target,
        message: `the output file ${resolved.original} is not writable${note}: ${err && err.message ? err.message : String(err)}`,
      };
    }
  }

  // The PARENT decides two things: whether a missing target can be created,
  // and — because delivery is atomic (temp file + rename) — whether an
  // EXISTING target can be replaced at all. So this is checked in both
  // branches, never only for the missing case.
  const dir = path.dirname(resolved.target);
  try {
    const dirStat = fs.statSync(dir);
    if (!dirStat.isDirectory()) {
      return {
        ok: false,
        code: 'out_parent_not_directory',
        path: resolved.original,
        target: resolved.target,
        parent: dir,
        message: `the parent path ${dir} is not a directory${note}`,
      };
    }
    fs.accessSync(dir, fs.constants.W_OK);
  } catch (err) {
    // ENOENT here means the directory the write would land in is missing —
    // the dangling-symlink case: the LINK's directory exists, the link's
    // TARGET directory does not. Say so plainly instead of "not writable".
    const missing = err && err.code === 'ENOENT';
    return {
      ok: false,
      code: 'out_parent_unwritable',
      path: resolved.original,
      target: resolved.target,
      parent: dir,
      message: missing
        ? `the output directory ${dir} does not exist${note}`
        : `the output directory ${dir} is not writable${note}: ${err && err.message ? err.message : String(err)}`,
    };
  }

  return { ok: true };
}

/** The repair line for a preflight refusal. */
function outPreflightFix(check) {
  if (check.code === 'out_is_directory') {
    return `  fix: give --out a FILE path, not a directory (e.g. ${check.path}.json)`;
  }
  if (check.code === 'out_not_regular_file' || check.code === 'out_symlink_loop') {
    return `  fix: point --out at a regular file path, not ${check.target || check.path}`;
  }
  return `  fix: create the directory first (mkdir -p ${check.parent}) or point --out at a writable path`;
}

/**
 * Deliver `bytes` to `outPath` atomically: temp file in the SAME directory
 * (rename needs same-filesystem), fsync, rename over the target.
 *
 * On failure the target keeps whatever it held before — the temp file is
 * removed and the rename never ran — and the error is returned as data
 * instead of thrown, because the caller may still hold a signature it must
 * not lose.
 */
function writeOutAtomic(outPath, bytes) {
  // Resolve FIRST so the write lands on the node the preflight approved.
  // Without this, rename would REPLACE a symlink with a regular file — the
  // preflight says "the target behind this link is fine" and the delivery
  // then destroys the link instead of writing through it.
  let target;
  try {
    const resolved = resolveOutTarget(outPath);
    target = resolved.ok ? resolved.target : path.resolve(outPath);
  } catch {
    target = path.resolve(outPath);
  }
  const dir = path.dirname(target);
  const tmp = path.join(
    dir,
    `.${path.basename(target)}.signerd-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  let fd;
  try {
    // 'wx': if our own temp name somehow exists, that is not a file to reuse.
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    // rename is atomic within the directory: no reader ever sees a truncated
    // or half-written target, and the new node carries the temp's 0600.
    fs.renameSync(tmp, target);
    // The rename is a DIRECTORY operation: until the directory entry itself
    // is durable, a crash can lose it — the target reverts to its previous
    // content, or the new name is not there at all. The temp file's own
    // fsync made the DATA durable, not the NAME.
    //
    // Measured 2026-11-08 (strace on this tree, one delivery): openat(tmp)
    // -> fsync(tmp) -> rename(tmp, target), and NO fsync of the directory.
    // Four sibling atomic-write sites in this repo already fsync the parent
    // after their rename (src/ledger.js, src/journalseal.js,
    // src/journalseal-ops.js, src/migrate.js); the --out delivery was the one
    // that skipped it, and it is the one carrying a paid-for artefact: the
    // CLI exited 0, so the operator believes the signature is at --out.
    //
    // Best effort, like every other site here: the artefact IS on disk at
    // this point, so a platform that cannot fsync a directory must not turn
    // a successful delivery into a failure.
    try {
      const dfd = fs.openSync(dir, 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch { /* platform-dependent; the delivery itself already succeeded */ }
    return { ok: true, path: target };
  } catch (err) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch { /* the temp is removed below */ }
    }
    try { fs.unlinkSync(tmp); } catch { /* it never existed, or is gone */ }
    return {
      ok: false,
      code: 'out_write_failed',
      path: target,
      errno: (err && err.code) || 'EIO',
      message: err && err.message ? err.message : String(err),
    };
  }
}

/** The repair line for a delivery failure (post-signing). */
function outWriteFix(delivery) {
  return '  fix: the signature is on stdout — write it out yourself, the daemon already signed';
}

module.exports = { checkOutWritable, outPreflightFix, writeOutAtomic, outWriteFix, resolveOutTarget };
