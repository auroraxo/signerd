'use strict';

/**
 * The socket path is a CAPABILITY: whoever can bind it can impersonate the
 * signing daemon. That is why the daemon protects its directory, its mode
 * and its owner (src/daemon.js).
 *
 * It also means the PATH ITSELF has a domain, and the domain is the one the
 * KERNEL enforces - not the one this codebase guesses.
 *
 * MEASURED 2026-11-09 on this host (Linux, `struct sockaddr_un`):
 *
 *   * `sun_path` is 108 BYTES (the `char sun_path[108]` field of
 *     `struct sockaddr_un` in the platform's `sys/un.h`). A bind/connect
 *     round trip works at 108 bytes and fails with EINVAL at 109.
 *   * the kernel measures BYTES of the string it was given, not characters:
 *     a path of 90 CHARACTERS that is 135 bytes (45x "a" plus 45x "ä") was
 *     refused with EINVAL, while 105 ASCII bytes were accepted.
 *
 * The defect this module fixes (measured on the pre-fix tree, tree dc75e63):
 *
 *   1. The daemon checked `path.resolve(socketPath).length > 100` - the
 *      CHARACTER count of the RESOLVED path, against a limit that is
 *      neither 100 nor about characters. Three consequences, all measured:
 *        a) a legitimate 105-byte path was REFUSED ("socket_path_too_long")
 *           although the kernel accepts it - a false refusal of a working
 *           setup;
 *        b) a 90-character / 135-byte path PASSED the check and died later
 *           at bind time with a raw `EINVAL: listen EINVAL: invalid
 *           argument ...` - the daemon's own refusal surface was BYPASSED
 *           and the operator got an errno instead of a code, a value and a
 *           repair;
 *        c) the check measured the RESOLVED path while the kernel judges the
 *           string that is actually passed to bind() - two different strings,
 *           so the verdict could be about a path the kernel never sees.
 *   2. The refusal carried NO detail at all: `socket_path_too_long: ` - an
 *      empty value, no limit, no byte count, no repair. The house rule
 *      (test/grant-refusal-voice.test.js) says a refusal names its code
 *      exactly once AND its repair.
 *   3. The CLIENT never preflighted the path: `signerd sign --socket <121
 *      bytes>` printed `EINVAL: connect EINVAL /home/.../signerd.sock -
 *      Local (undefined:undefined)` - a raw errno, a mangled message and the
 *      literal text "(undefined:undefined)".
 *
 * ONE source of truth, so the daemon and the client cannot drift apart
 * again: both judge the string they will pass to the kernel, in bytes.
 */

/**
 * The kernel's limit: `char sun_path[108]` in `struct sockaddr_un`.
 *
 * Measured on this host: 108 bytes bind and connect, 109 bytes are EINVAL.
 */
const SUN_PATH_MAX_BYTES = 108;

/** The size of the path in BYTES - the unit the kernel actually measures. */
function socketPathBytes(socketPath) {
  return Buffer.byteLength(socketPath, 'utf8');
}

/**
 * Can this socket path be bound (daemon) / connected to (client)?
 *
 * Returns `{ ok: true, path, bytes }` or
 * `{ ok: false, code, path, bytes, limit, message }`.
 */
function checkSocketPath(socketPath) {
  if (typeof socketPath !== 'string' || socketPath.length === 0) {
    return {
      ok: false,
      code: 'socket_path_required',
      path: socketPath,
      bytes: 0,
      limit: SUN_PATH_MAX_BYTES,
      message: 'no socket path was given',
    };
  }
  const bytes = socketPathBytes(socketPath);
  if (bytes > SUN_PATH_MAX_BYTES) {
    return {
      ok: false,
      code: 'socket_path_too_long',
      path: socketPath,
      bytes,
      limit: SUN_PATH_MAX_BYTES,
      message: `the socket path is ${bytes} bytes; this OS allows at most ${SUN_PATH_MAX_BYTES} bytes in a unix socket path`,
    };
  }
  return { ok: true, path: socketPath, bytes };
}

/** The repair line for a socket-path refusal. */
function socketPathFix(check) {
  if (!check || check.code === 'socket_path_required') {
    return '  fix: pass --socket <file>   # the path the daemon listens on, and the client connects to';
  }
  return `  fix: use a shorter --socket path (<= ${check.limit} bytes), e.g. ~/.local/share/signerd/signerd.sock`;
}

module.exports = {
  SUN_PATH_MAX_BYTES, socketPathBytes, checkSocketPath, socketPathFix,
};
