'use strict';

// ONE SOURCE OF TRUTH for reading an OPERATOR-SUPPLIED input file.
//
// WHY (measured 2026-11-14 against the PUBLISHED v0.2.22 tree):
//
//   The product's contract is that every refusal is a NAMED reason plus a
//   repair, and that the exit code says WHAT happened:
//
//     exit 0  signed and delivered
//     exit 1  the daemon or the policy refused (no signature was made)
//     exit 2  a usage / preflight refusal (no signature was made)
//
//   Three read paths did not honour that contract. A path that could not
//   be READ crashed out of the CLI with a raw Node errno:
//
//     signerd run --passphrase-file <missing>
//       -> "ENOENT: no such file or directory, lstat '...'", exit 1
//     signerd run --passphrase-file <mode 000>
//       -> "EACCES: permission denied, open '...'", exit 1
//     signerd sign --tx <a directory>
//       -> "EISDIR: illegal operation on a directory, read", exit 1
//     signerd sign --tx <mode 000>
//       -> "EACCES: permission denied, open '...'", exit 1
//     signerd sign-message --body <missing|a directory|mode 000>
//       -> "ENOENT: ..." / "EISDIR: ..." / "EACCES: ...", exit 1
//
//   A typo in a path is a USAGE refusal (exit 2), not a policy refusal, and
//   a raw errno names no reason the operator can act on. The `--tx` MISSING
//   case had already been given the product's voice on 2026-11-05
//   (`tx_missing` + a repair line); the rest of the class was never swept.
//
// WHAT THIS MODULE DOES (and does not):
//
//   It classifies a read failure into exactly three reasons - `missing`,
//   `not_a_file`, `unreadable` - so every caller names the SAME reason for
//   the SAME failure. The VOICE (the code name and the repair line) stays
//   with the caller, because the repair differs per input.
//
//   `follow: false` (the default) judges the path itself with lstat: a
//   symlink is NOT a regular file and the caller refuses it by name - the
//   rule the passphrase path has carried since v0.2.20 (R6-6).
//
//   `follow: true` judges the RESOLVED path with stat: a symlink to a
//   regular file is read through, exactly as before - the link is not the
//   defect, and refusing it would change a documented flow.
//
//   Nothing here decides WHETHER a read is allowed; it only says WHAT
//   went wrong. The rules stay in one place: this file.

const fs = require('node:fs');

/**
 * Map a Node fs error onto one of the three reasons of this class.
 * ENOENT / ENOTDIR -> the path is not there.
 * EISDIR / ELOOP   -> there is something there, but it is not a file.
 * everything else   -> the file is there and cannot be read.
 */
function classifyReadError(err) {
  if (!err || typeof err.code !== 'string') return 'unreadable';
  if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return 'missing';
  if (err.code === 'EISDIR' || err.code === 'ELOOP') return 'not_a_file';
  return 'unreadable';
}

/**
 * Read an operator-supplied file.
 *
 * Returns { ok: true, bytes } or { ok: false, reason, detail } where
 * reason is one of 'missing' | 'not_a_file' | 'unreadable'.
 */
function readOperatorFile(filePath, { follow = false } = {}) {
  let stat;
  try {
    stat = follow ? fs.statSync(filePath) : fs.lstatSync(filePath);
  } catch (err) {
    return { ok: false, reason: classifyReadError(err), detail: (err && err.code) || 'unknown' };
  }
  if (!stat.isFile()) {
    return { ok: false, reason: 'not_a_file', detail: 'not a regular file' };
  }
  try {
    return { ok: true, bytes: fs.readFileSync(filePath) };
  } catch (err) {
    return { ok: false, reason: classifyReadError(err), detail: (err && err.code) || 'unknown' };
  }
}

module.exports = { readOperatorFile, classifyReadError };
