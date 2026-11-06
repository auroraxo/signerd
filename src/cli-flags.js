'use strict';

// THE FLAG SURFACE: a flag the operator SET must never be silently ignored.
//
// WHY (measured 2026-11-06, this repo):
//
// The CLI used to parse `--flag value` into a map and then read only the
// flags it knew about; every other flag was dropped without a word. For a
// cosmetic flag that is invisible. For a SECURITY flag it is a FAIL-OPEN:
//
//   signerd run --keystore k --passphrase-file p --grants g --ledger l \
//               --socket s --grant-seal-passphrasefile p     <- typo: no dash
//
// The daemon looked for --grant-seal-passphrase-file, did not find it, and
// started WITHOUT sealed mode while reporting {"ok":true}. Measured against
// a grant file that was sealed and then TAMPERED (cap raised, HMAC broken):
//
//   correct flag:  grant_file_seal_mismatch  -> the daemon REFUSES to start
//   typo'd flag:   {"ok":true}               -> the daemon STARTS, unsealed
//
// One missing dash turned the sealed-mode guarantee off. Sealed mode exists
// to refuse exactly that file.
//
// The same class, second measurement: `grant-add --seal-passphrase-file`
// without `--append` accepted the flag and then IGNORED it, writing an
// UNSEALED file while the operator had asked for a sealed one. The --append
// path already refuses the same situation (`grant_file_unsealed`) - two
// behaviours for one flag. They are now one behaviour: refuse, name the
// repair, write nothing.
//
// THE RULES (pure, offline-pinnable; bin/signerd.js is the only caller):
//   F1 a flag the addressed command does not take is refused BEFORE anything
//      is read, written or started, with `unknown_flag: --<name>` and the
//      flags that command does take;
//   F2 a positional argument the command does not read is refused the same
//      way (`unknown_argument`) - a mistyped command or flag value must not
//      be dropped either;
//   F3 the refusal names a repair the CLI actually offers (closest flag
//      when there is one);
//   F4 an unknown COMMAND is not a flag question: bin keeps printing the
//      usage banner for it, because tools/measure-documented-flags.mjs
//      reads that banner to classify an unknown command.
//
// LIMITS: this is argument hygiene, not a sandbox - a flag that IS in the
// list can still be given a wrong value (the value validators judge that).
// It says nothing about flags of other commands: `keygen --grants x` is
// refused because keygen has no grants, not because the value is wrong.
const FLAG_DISTANCE_MAX = 3;

/**
 * The flags each command reads, straight from bin/signerd.js. A flag is
 * listed iff the dispatch for that command actually reads it - listing a
 * flag the code ignores would recreate the defect from the other side.
 */
const COMMAND_FLAGS = {
  keygen: ['keystore', 'passphrase-file', 'overwrite'],
  import: ['keystore', 'from', 'passphrase-file', 'overwrite'],
  run: [
    'keystore', 'passphrase-file', 'grants', 'ledger', 'socket',
    'grant-seal-passphrase-file', 'journal-seal-passphrase-file',
  ],
  'build-tx': ['keystore', 'to', 'lamports', 'out', 'blockhash'],
  sign: ['socket', 'grant', 'tx', 'out'],
  'grant-add': [
    'grants', 'name', 'signer', 'keystore', 'destination', 'max-lamports',
    'window-max-lamports', 'window-seconds', 'expires', 'append',
    'seal-passphrase-file',
  ],
  'grant-remove': ['grants', 'name', 'seal-passphrase-file'],
  'sign-message': ['socket', 'grant', 'body', 'out', 'add-grant', 'keystore', 'grants'],
  status: [
    'grants', 'ledger', 'grant-seal-passphrase-file', 'journal-seal-passphrase-file',
  ],
  'seal-grants': ['grants', 'seal-passphrase-file', 'out'],
  'verify-grants': ['grants', 'seal-passphrase-file'],
  'seal-journal': ['journal', 'journal-seal-passphrase-file'],
  migrate: ['ledger', 'wires', 'discard-legacy'],
};

/** Damerau-free Levenshtein distance, capped for a short flag name. */
function editDistance(a, b) {
  const rows = a.length + 1;
  const cols = b.length + 1;
  let prev = new Array(cols);
  let cur = new Array(cols);
  for (let j = 0; j < cols; j += 1) prev[j] = j;
  for (let i = 1; i < rows; i += 1) {
    cur[0] = i;
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    const swap = prev;
    prev = cur;
    cur = swap;
  }
  return prev[cols - 1];
}

/**
 * The flag a command takes that is closest to the one the operator typed -
 * the repair the refusal names. null when nothing is close enough: a wrong
 * suggestion is worse than none (measured rule: name a repair the CLI
 * actually offers).
 */
function closestFlag(typed, supported) {
  let best = null;
  let bestDistance = FLAG_DISTANCE_MAX + 1;
  for (const flag of supported) {
    const distance = editDistance(typed, flag);
    if (distance < bestDistance) { bestDistance = distance; best = flag; }
  }
  return bestDistance <= FLAG_DISTANCE_MAX ? best : null;
}

/**
 * The rule: does this invocation carry only flags the command takes?
 *
 * `args` is the parsed argument map (`_` is ignored - it holds the command
 * and any positionals). `positionals` are the non-flag tokens after the
 * command; a command that reads none of them must not receive any.
 *
 * Returns { ok: true } or { ok: false, code, flag|argument, supported }.
 */
function checkFlags(command, args, positionals) {
  const supported = COMMAND_FLAGS[command];
  if (supported === undefined) return { ok: true }; // unknown command: not this rule
  const known = new Set(supported);
  for (const key of Object.getOwnPropertyNames(args)) {
    if (key === '_') continue;
    if (!known.has(key)) {
      return { ok: false, code: 'unknown_flag', flag: key, supported: [...supported].sort() };
    }
  }
  const extra = (positionals || []).slice(1); // [0] is the command itself
  if (extra.length > 0) {
    return {
      ok: false, code: 'unknown_argument', argument: extra[0], supported: [...supported].sort(),
    };
  }
  return { ok: true };
}

module.exports = { COMMAND_FLAGS, checkFlags, closestFlag, editDistance };
