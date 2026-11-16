'use strict';

/**
 * THE SOCKET STATE, IN THE PRODUCT'S VOICE.
 *
 * WHY (measured 2026-11-16, published v0.2.30):
 *
 * The transport refusal names its own repair:
 *
 *   fix: the socket connection failed; check that --socket names a running
 *        signerd daemon (signerd status --socket <path>)
 *
 * ... and the CLI answered `unknown_flag: --socket`, exit 2. The named
 * repair could not be RUN - the operator was told to run a command the
 * product refuses. That breaks the repo's own rule F3 ("the refusal names
 * a repair the CLI actually offers", src/cli-flags.js) and it is the worst
 * kind of defect: the product answers a question with an instruction that
 * leads nowhere.
 *
 * So the repair is now a real command (`signerd status --socket <path>`,
 * bin/signerd.js), and this module is the ONE place that decides what a
 * socket's state MEANS - the same way src/socketpath.js is the one place
 * that decides what a socket path may be, and src/socketprobe.js the one
 * place that decides whether a daemon is listening.
 *
 * The three verdicts the probe can return (src/socketprobe.js):
 *   'live'    - somebody is listening right now.
 *   'stale'   - a socket file exists but nothing is listening (a daemon
 *               that died without cleaning up).
 *   'absent'  - there is no socket file at that path.
 *   'unknown' - the probe could not tell (EAGAIN, ENOMEM, timeout, ...).
 *               The caller MUST refuse and MUST NOT guess.
 *
 * Every refusal names the CLASS of the failure, not the errno: an operator
 * needs to know what to DO, and "ENOENT" is not an action. The errno is
 * still used to CLASSIFY (a missing file and a refused connection are
 * different problems with different repairs), but it never reaches the
 * operator as the reason.
 */

/** The repair for a socket path on which no daemon answers. */
const START_FIX =
  'start the daemon on that path: signerd run --keystore <file> ' +
  '--passphrase-file <file> --grants <file> --ledger <file> --socket <path>';

/** The repair for a socket file nobody listens on. */
function staleFix(socketPath) {
  const where = socketPath === undefined ? '<path>' : socketPath;
  return `the daemon died without cleaning up; remove the stale socket file (rm ${where}) ` +
    'and start the daemon again';
}

/**
 * What a probe verdict MEANS for the operator.
 *
 * Returns `{ code, detail, fix }` for the three refusals, and `null` for
 * 'live' (there is nothing to refuse - the daemon answers).
 *
 * The codes are the product's own vocabulary: one code per situation, one
 * repair each, and the repair is a command that runs.
 */
function socketStateRefusal(state, socketPath) {
  const where = socketPath === undefined ? 'the socket path' : socketPath;
  if (state === 'absent') {
    return {
      code: 'socket_missing',
      detail: `no socket file at ${where}: the daemon is not running there`,
      fix: `${START_FIX}; check it with signerd status --socket ${where}`,
    };
  }
  if (state === 'stale') {
    return {
      code: 'socket_stale',
      detail: `a socket file exists at ${where} but nothing is listening on it`,
      fix: `${staleFix(socketPath)}; check it with signerd status --socket ${where}`,
    };
  }
  if (state === 'unknown') {
    return {
      code: 'socket_state_unknown',
      detail: `the state of the socket at ${where} could not be proven`,
      fix:
        'the state is never guessed: check that the daemon process is alive ' +
        `and that you may reach ${where}, then try again`,
    };
  }
  return null;
}

/**
 * What a CONNECT failure MEANS for the operator.
 *
 * The errno classifies; it never speaks. The connect error and the probe
 * verdict describe the same three situations from two sides:
 *
 *   ENOENT        - nothing is there at all          -> socket_missing
 *   ECONNREFUSED  - the file is there, nobody listens -> socket_stale
 *   EACCES        - the path may not be reached      -> socket_not_reachable
 *   anything else - the truth could not be established -> socket_connect_failed
 *
 * `unknown` (a code this module does not know) is deliberately NOT given a
 * specific repair: a wrong repair is worse than none (the same rule
 * src/cli-flags.js follows when it refuses to guess a flag).
 */
function socketConnectRefusal(err, socketPath) {
  const code = err && typeof err.code === 'string' ? err.code : '';
  const where = socketPath === undefined ? 'the socket path' : socketPath;
  if (code === 'ENOENT') {
    return {
      code: 'socket_missing',
      detail: `no socket file at ${where}: the daemon is not running there`,
      fix: `${START_FIX}; check it with signerd status --socket ${where}`,
    };
  }
  if (code === 'ECONNREFUSED') {
    return {
      code: 'socket_stale',
      detail: `a socket file exists at ${where} but nothing is listening on it`,
      fix: `${staleFix(socketPath)}; check it with signerd status --socket ${where}`,
    };
  }
  if (code === 'EACCES') {
    return {
      code: 'socket_not_reachable',
      detail: `the socket at ${where} may not be reached by this process`,
      fix:
        `the socket is a capability: only its owner may talk to it - ` +
        `check who owns ${where} and run this command as that user`,
    };
  }
  return {
    code: 'socket_connect_failed',
    detail: `the daemon socket at ${where} could not be reached`,
    fix:
      `the socket connection failed; check that --socket names a running ` +
      `signerd daemon (signerd status --socket ${where})`,
  };
}

module.exports = {
  socketStateRefusal, socketConnectRefusal, START_FIX, staleFix,
};
