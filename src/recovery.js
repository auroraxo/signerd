'use strict';

/**
 * The recovery channel, VERIFIED — and the exit code that tells the truth
 * when it cannot carry the artifact.
 *
 * WHY THIS MODULE EXISTS (measured live 2026-11-08 on the tree that shipped
 * v0.2.9, whose README says: "On exit 3 the signed wire (or the signed
 * receipt document) is still on stdout"):
 *
 * Exit 3 means "the daemon signed, the file delivery failed". The product's
 * promise for that exit is that the PAID-FOR artifact is recoverable from
 * stdout. Nothing checked whether stdout could carry it. Measured, with a
 * live daemon that really signed (the journal grew 366 -> 732 bytes, so the
 * spend happened):
 *
 *   * stdout -> a REGULAR FILE under `ulimit -f 0` (RLIMIT_FSIZE=0) — the
 *     ordinary capture pattern `signerd sign ... > signed.json` on a
 *     filesystem that cannot grow: the CLI wrote the response with
 *     `process.stdout.write(...)` and immediately called `process.exit(3)`.
 *     Node reports a failed write on a file ASYNCHRONOUSLY (as an `error`
 *     event on the stream), so the error never surfaced and the pending
 *     write was never flushed: exit 3, stdout 0 bytes, stderr 0 bytes, the
 *     --out file unchanged, the retry refused `replay`, and the journal
 *     holds only hashes. Paid for, unrecoverable, and exit 3 — whose whole
 *     meaning is "the artifact is here" — said otherwise.
 *   * stdout -> /dev/full (every write fails with ENOSPC): the same loss.
 *   * stdout -> /dev/null: the write SUCCEEDS and the bytes are DISCARDED.
 *     A "no error" check is still a lie here, because nothing retains what
 *     was written.
 *
 * THE CONTRACT, restated so it can be checked:
 *
 *   * The artifact goes to stdout with a SYNCHRONOUS write whose full length
 *     is verified (`src/stdout.js`).
 *   * The channel must RETAIN what it is given — /dev/null and /dev/zero
 *     accept bytes and keep nothing.
 *   * When the artifact is on stdout, the exit is 3 ("signed, the file
 *     delivery failed") and stderr says so with the repair.
 *   * When the artifact is NOWHERE — the file delivery failed AND stdout
 *     could not carry it — the exit is 4 ("signed, and unrecoverable") and
 *     stderr says `recovery_failed` with what was tried. Never exit 3: exit
 *     3 PROMISES the artifact is on stdout, and this is the one place the
 *     product promised truth.
 *
 * Exit 4 is new. It is not a refusal (exit 1 says "no signature was made" —
 * false here) and not a usage error (exit 2). It says exactly what happened:
 * the daemon signed, and the artifact is not reachable from this run.
 */

const { writeStdoutSync, writeStderrSync, stdoutRetainsBytes } = require('./stdout');

/**
 * Exit 4: the signature was made and NOTHING carries it.
 *
 * 0 = signed and delivered | 1 = refused, nothing signed | 2 = usage |
 * 3 = signed, the file delivery failed (the artifact IS on stdout) |
 * 4 = signed, and the artifact is UNRECOVERABLE (it is nowhere).
 */
const EXIT_UNRECOVERABLE = 4;

/**
 * Write `payload` to stdout and report what the channel actually did.
 *
 * Returns `{ ok: true, bytes }` or
 * `{ ok: false, code, message, retention }` where `code` is
 * `stdout_discards` (the channel keeps nothing) or `stdout_write_failed`
 * (the write itself failed).
 */
function putStdout(payload) {
  const retention = stdoutRetainsBytes();
  if (!retention.retains) {
    return {
      ok: false,
      code: 'stdout_discards',
      message: `stdout points at ${retention.target}, which keeps nothing written to it`,
      retention,
    };
  }
  const w = writeStdoutSync(payload);
  if (!w.ok) {
    return {
      ok: false,
      code: 'stdout_write_failed',
      message: `${w.code}: ${w.message}`,
      write: w,
      retention,
    };
  }
  return { ok: true, bytes: w.bytes, retention };
}

/**
 * The words for a dead recovery channel. Named, not silent: a run that lost
 * a paid-for signature must say so with the reason and the repair.
 */
function recoveryFailedText(put, extra) {
  const why = extra ? ` (${extra})` : '';
  return (
    `recovery_failed: the signed artifact could not be delivered to stdout${why}: ${put.message}\n` +
    `  the daemon already signed, so the spend happened; the artifact is NOT recoverable from this run\n` +
    `  fix: sign again with a fresh wire and a writable --out ` +
    `(the journal records the spend, but only hashes — the signature itself is gone)\n`
  );
}

/**
 * The exit-3 path: the artifact was signed, the --out delivery failed.
 *
 * Delivers the artifact to stdout, VERIFIED, and decides the exit code:
 * 3 when the artifact really landed, 4 when it could not.
 *
 * `subject` is the artifact's name in the operator's words ("the signature",
 * "the receipt") so the message reads the way the README does, and
 * `fixLine` is the repair from `src/out-preflight.js` — it is only printed
 * when the artifact really is on stdout, because that is what it promises.
 */
function deliverRecovery({ payload, outPath, outError, subject, fixLine }) {
  const outLine =
    `out_write_failed: ${subject} was produced but could not be written to ${outPath}: ${outError.message}\n`;
  const put = putStdout(payload);
  if (put.ok) {
    return {
      exitCode: 3,
      stderr: outLine + `${fixLine}\n`,
      delivered: true,
    };
  }
  return {
    exitCode: EXIT_UNRECOVERABLE,
    stderr: outLine + recoveryFailedText(put),
    delivered: false,
  };
}

/**
 * The ordinary response path.
 *
 * `artifact` says whether the payload IS the paid-for artifact (there is no
 * --out file, so stdout is the only channel that carries it). `ok` says
 * whether the daemon actually signed.
 *
 * A failed stdout write is therefore:
 *   * fatal (exit 4, `recovery_failed`) when the payload carried a signature
 *     that only stdout could carry — the artifact would be lost;
 *   * a reportable hiccup otherwise: the file carries the artifact, or the
 *     payload is a refusal with no artifact in it. The words still have to
 *     reach the operator, so they go to stderr, and the exit code is the
 *     caller's (unchanged).
 */
function deliverResponse({ payload, artifact, ok, exitCode }) {
  const put = putStdout(payload);
  if (put.ok) return { exitCode, stderr: '', delivered: true };
  if (artifact && ok) {
    return {
      exitCode: EXIT_UNRECOVERABLE,
      stderr: recoveryFailedText(put, 'the response carried the signed artifact'),
      delivered: false,
    };
  }
  // If the stdout failure was merely that the destination was /dev/null
  // (the operator chose to discard the JSON metadata), and NO artifact was
  // at stake (it's either on disk, or this is a refusal / dry run), do not
  // complain: /dev/null is an intentional discard.
  if (put.code === 'stdout_discards') {
    return { exitCode, stderr: '', delivered: false };
  }
  return {
    exitCode,
    stderr:
      `stdout_write_failed: the response could not be written to stdout: ${put.message}\n` +
      `  fix: capture stdout on a channel that keeps bytes (a pipe or a file) — ` +
      `the response is repeated on stderr here\n` +
      payload,
    delivered: false,
  };
}

/**
 * Write a response to stdout, verified, and report a failed write on
 * stderr. For the paths where no artifact is at stake — the exit code stays
 * the caller's, but the CLI is never silently mute.
 */
function emit(payload) {
  const put = putStdout(payload);
  if (!put.ok) {
    writeStderrSync(
      `stdout_write_failed: the response could not be written to stdout: ${put.message}\n` + payload);
  }
  return put;
}

module.exports = {
  EXIT_UNRECOVERABLE,
  putStdout,
  deliverRecovery,
  deliverResponse,
  emit,
};
