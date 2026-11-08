'use strict';

/**
 * Verified stdout delivery: a write that has not been PROVEN to land is not
 * a delivery.
 *
 * WHY (measured live 2026-11-08, tree 0059c7a — the tree that shipped
 * v0.2.9, whose README says "On exit 3 the signed wire ... is still on
 * stdout"):
 *
 * The CLI wrote its response with `process.stdout.write(...)` and then called
 * `process.exit(...)`. Two facts about that combination, both measured:
 *
 *   1. `process.exit()` does NOT flush a pending stdout write. The bytes are
 *      queued, the process is gone, nothing reached the kernel.
 *   2. When the channel itself FAILS, the failure is reported
 *      ASYNCHRONOUSLY — as an `error` event on the stream. An immediate
 *      `process.exit()` runs first, so the error never surfaces either. The
 *      process reports success on a channel that refused every byte.
 *
 * Measured on the published v0.2.9 behaviour, against a live daemon that
 * really signed (journal 366 -> 732 bytes — the spend happened):
 *
 *   stdout -> a REGULAR FILE under `ulimit -f 0` (RLIMIT_FSIZE=0), i.e. the
 *   ordinary CI/operator capture `signerd sign ... > signed.json` on a
 *   filesystem that cannot grow:
 *        exit 3, stdout 0 bytes, stderr 0 bytes,
 *        the --out file unchanged, the journal holds only hashes (no
 *        signature), the retry of the same wire is refused `replay`.
 *        Paid for, unrecoverable, and exit 3 — whose whole meaning is "the
 *        artifact is here" — said otherwise.
 *
 *   stdout -> /dev/full (opens, fails every write with ENOSPC): same shape,
 *   same loss.
 *
 *   stdout -> /dev/null: the write SUCCEEDS and the bytes are discarded. A
 *   "verified" write that only checks for no-error would still be lying here,
 *   because nothing retains what was written.
 *
 * THE RULE: the response must be on fd 1 BEFORE the process claims it is,
 * written with a synchronous write whose full length is checked, and the
 * CHANNEL must be one that retains bytes.
 *
 * MECHANICS, measured (not assumed):
 *
 *   * `fs.writeSync(1, buf)` returns bytes written. Under RLIMIT_FSIZE it
 *     can write PART of the payload and fail on the next call
 *     (`ulimit -f 1`, 1885-byte payload -> 1024 written, then EFBIG). A
 *     partial write is a FAILED delivery: a truncated artifact is not an
 *     artifact. The loop must therefore require the full length.
 *   * /dev/full throws ENOSPC; a pipe whose reader is gone throws EPIPE; a
 *     non-blocking pipe that is momentarily full throws EAGAIN — the one
 *     transient case, retried bounded instead of failing a delivery.
 *   * A zero-length write is NOT a probe: it succeeds on /dev/full (no bytes
 *     to fail on) and on a closed stdout. The probe that means something is
 *     the real payload.
 *   * RLIMIT_FSIZE=0 makes ANY regular-file write throw EFBIG, so a delivery
 *     that must go to a file fails loudly here rather than vanishing.
 */

/** How long a single EAGAIN wait sleeps (ms), and how many times we retry. */
const EAGAIN_SLEEP_MS = 10;
const EAGAIN_RETRIES = 200;

/**
 * Sleep synchronously — on the exit path the event loop is not an option.
 * Falls back to a spin so a runtime without Atomics.wait still delivers.
 */
function sleepSync(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    return;
  } catch {
    /* fall through to the spin */
  }
  const end = Date.now() + ms;
  while (Date.now() < end) { /* spin */ }
}

/**
 * Write `text` to `fd` synchronously, in full, and report whether it landed.
 *
 * Returns `{ ok: true, bytes }` or
 * `{ ok: false, bytes, code, errno, message }` — `bytes` says how much DID
 * land, so a truncated delivery is reported as a truncated delivery instead
 * of being rounded up to "delivered".
 *
 * Never throws: the caller is on the exit path and may be holding a signature
 * it must not lose to an exception.
 */
function writeFdSync(fd, text) {
  const buf = Buffer.from(String(text), 'utf8');
  let written = 0;
  let lastError = null;
  let eagain = 0;

  while (written < buf.length) {
    let n;
    try {
      n = require('node:fs').writeSync(fd, buf, written, buf.length - written);
    } catch (err) {
      if (err && err.code === 'EAGAIN') {
        // Transient: the pipe is momentarily full. Give the reader a turn.
        eagain += 1;
        if (eagain > EAGAIN_RETRIES) {
          lastError = { code: 'EAGAIN', message: `stdout stayed full for ${EAGAIN_RETRIES} retries` };
          break;
        }
        sleepSync(EAGAIN_SLEEP_MS);
        continue;
      }
      lastError = {
        code: (err && err.code) || 'EIO',
        message: err && err.message ? err.message : String(err),
      };
      break;
    }
    if (n > 0) {
      written += n;
      eagain = 0;
      continue;
    }
    // 0 bytes with payload outstanding: the channel is refusing data
    // without an error. That is a failure, not a reason to spin.
    lastError = { code: 'EIO', message: 'write returned 0 bytes' };
    break;
  }

  if (lastError) {
    return { ok: false, bytes: written, code: lastError.code, errno: lastError.code, message: lastError.message };
  }
  return { ok: true, bytes: written };
}

/** Write `text` to stdout, verified. See {@link writeFdSync}. */
function writeStdoutSync(text) {
  return writeFdSync(1, text);
}

/**
 * Write `text` to stderr, verified.
 *
 * The exit-3 path prints its explanation HERE, after it has learned whether
 * the recovery channel worked — so this write must survive too, or the
 * operator is left with an exit code and no words.
 */
function writeStderrSync(text) {
  return writeFdSync(2, text);
}

/**
 * Does fd 1 RETAIN what is written to it?
 *
 * A write can succeed and still lose the artifact: /dev/null and /dev/zero
 * accept bytes and keep nothing, so "no error" is not proof of delivery.
 * `/proc/self/fd/1` names the target; anything else (pipe, tty, file) keeps
 * what it is given. When /proc is unavailable, we assume retention and let
 * the write itself decide — a false "yes" here is the same assumption this
 * module exists to remove, so the answer is documented, not silent.
 *
 * Returns `{ retains: boolean, target: string|null, checked: boolean }`.
 */
function stdoutRetainsBytes() {
  let target = null;
  try {
    target = require('node:fs').readlinkSync('/proc/self/fd/1');
  } catch {
    // No /proc (not Linux) or fd 1 is not a symlink we can resolve: the
    // write result is the only evidence available, so defer to it.
    return { retains: true, target: null, checked: false };
  }
  const discard = target === '/dev/null' || target === '/dev/zero';
  return { retains: !discard, target, checked: true };
}

module.exports = { writeFdSync, writeStdoutSync, writeStderrSync, stdoutRetainsBytes };
