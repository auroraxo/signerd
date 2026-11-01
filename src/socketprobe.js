'use strict';

// Classify the state of a daemon socket path BEFORE binding it.
//
// WHY: the socket path is a capability. Whoever can bind it can impersonate
// the signing daemon, so a second start() must never remove a LIVE daemon's
// socket file. The previous probe was a single `connect()` whose outcome was
// collapsed into two verdicts: "connected" -> alive, "anything else" -> dead.
// That collapse is the hole: an error that does NOT mean "nobody is
// listening" was read as "nobody is listening".
//
// Measured (research/review5): a listening socket whose accept queue is
// saturated refuses NEW connects with EAGAIN, not ECONNREFUSED. The old
// probe read EAGAIN as "dead", unlinked the live socket and bound its own at
// the documented client path - every client trusting that path then talked to
// an impostor.
//
// Three verdicts, because the truth has three states:
//   'live'    - somebody is listening right now.
//   'stale'   - a socket file exists but nothing is listening: safe to
//               replace.
//   'unknown' - the probe could not tell (EAGAIN, ENOMEM, timeout, ...).
//               The caller MUST refuse; never unlink on 'unknown'.
//
// Only ECONNREFUSED (and ENOENT) prove that no process is listening on the
// path. Everything else is ambiguous and is treated as ambiguous.

const fs = require('node:fs');
const net = require('node:net');

const PROBE_TIMEOUT_MS = 500;

// A path that does not exist at all, or is not a socket, is never a live
// daemon's socket: a crashed daemon leaves a socket file, and anything else
// is a stray file. Either way it may be replaced.
function pathKind(socketPath) {
  let stat;
  try {
    stat = fs.lstatSync(socketPath);
  } catch (err) {
    if (err.code === 'ENOENT') return 'absent';
    // We cannot even look at the path: that is not proof of death either.
    return 'unknown';
  }
  if (!stat.isSocket()) return 'plain_file';
  return 'socket';
}

/**
 * Probe `socketPath`.
 *
 * Returns 'absent' | 'stale' | 'live' | 'unknown'.
 * 'unknown' means: do not touch the path, refuse the start.
 */
function classifySocketPath(socketPath, timeoutMs = PROBE_TIMEOUT_MS) {
  const kind = pathKind(socketPath);
  if (kind === 'absent') return 'absent';
  if (kind === 'plain_file') return 'stale';
  if (kind === 'unknown') return 'unknown';

  return new Promise((resolve) => {
    let settled = false;
    const finish = (verdict) => {
      if (settled) return;
      settled = true;
      try { probe.destroy(); } catch { /* already gone */ }
      resolve(verdict);
    };
    const probe = net.connect(socketPath);
    probe.once('connect', () => finish('live'));
    probe.once('error', (err) => {
      // ECONNREFUSED: the path exists, but no process is listening on it.
      // That is the ONLY error that proves the socket is stale.
      if (err.code === 'ECONNREFUSED') return finish('stale');
      // ENOENT: the file vanished between the lstat and the connect.
      if (err.code === 'ENOENT') return finish('absent');
      // Everything else (EAGAIN on a saturated accept queue, ENOMEM,
      // EMFILE, EACCES, ...) says nothing about liveness.
      return finish('unknown');
    });
    probe.setTimeout(timeoutMs, () => finish('unknown'));
  });
}

module.exports = { classifySocketPath, pathKind, PROBE_TIMEOUT_MS };
