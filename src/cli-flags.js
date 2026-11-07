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
//
// THE FLAG ARITY SURFACE (measured 2026-11-07, live, on the pre-fix tree):
//
// The rule above answers "is this flag KNOWN?". It cannot answer "is this
// flag USED the way you typed it?" - and the parser turns tokens into a MAP,
// so three shapes vanish without a word:
//
//  1. a flag given TWICE. The map keeps the LAST value.
//     `run --grants narrow.json --grants wide.json` enforced wide.json and
//     signed 500005000 lamports that narrow.json (cap 1000) refuses with
//     `amount`. The operator named narrow.json FIRST and never heard about
//     the second one.
//  2. a value-taking flag given NO value. `args[x]` becomes `true`, and the
//     code reads `typeof args[x] === 'string'` - so the flag reads as ABSENT.
//     `run ... --grant-seal-passphrase-file` (path forgotten) therefore
//     started the daemon WITHOUT sealed mode on a sealed-and-tampered grant
//     file: the correct flag refuses `grant_file_seal_mismatch`, the flag
//     with no value answered `{"ok":true}`. The 2026-11-06 typo fix closed
//     this failure through SPELLING; it re-entered through ARITY.
//  3. a SWITCH given a value. `--dry true` made `args.dry` the STRING
//     "true", `args.dry === true` false, and the request went out as a REAL
//     sign: exit 0, a real signature, 368 bytes appended to the journal,
//     `--out` written. The README promises a non-boolean dry is "never
//     degraded into a real signature" - the CLI degraded it anyway.
//
// The rules (pure, offline-pinnable; bin/signerd.js is the only caller):
//   A1 a flag given TWICE is refused (`duplicate_flag`), naming the flag
//      and both values - signerd cannot know which one you meant, and
//      last-wins silently swaps scope, files and caps;
//   A2 a value-taking flag given NO value is refused (`missing_value`),
//      before it can read as "absent" and switch a security feature off;
//   A3 a switch given a value is refused (`flag_takes_no_value`) - a dry
//      must never become a real sign;
//   A4 the refusal happens BEFORE anything is read, written or started.
//
// WHAT THIS DOES NOT DO: it says nothing about the VALUE of a flag - a
// value that is present but wrong is judged by the value validators, as
// before. And a flag that is simply ABSENT is still answered `missing --x`
// by requireArg: arity covers a flag that was TYPED, not one forgotten.
const FLAG_DISTANCE_MAX = 3;

/**
 * The flags that are SWITCHES: they take no value by design. A value here
 * is a mistake worth refusing - `--dry true` must not become a real sign.
 *
 * Listed per command, because the same name can be a switch in one command
 * and a value flag in another (`--out` is a path, `--dry` is a switch).
 */
const SWITCH_FLAGS = {
  keygen: ['overwrite'],
  import: ['overwrite'],
  'grant-add': ['append'],
  sign: ['dry'],
  'sign-message': ['dry', 'add-grant'],
  migrate: ['discard-legacy'],
};

/**
 * Parse a command line into { args, problems }.
 *
 * `args` is the parsed map (the same shape the old parseArgs produced), so
 * the callers keep working unchanged. `problems` is the list of ARITY
 * violations: every flag that was given twice, every value-taking flag
 * without a value, every switch with a value. The caller refuses on the
 * first problem, before anything is read, written or started.
 *
 * The problems carry the values that were typed, so the refusal can say
 * WHICH file was meant twice, not only WHICH flag.
 *
 * `argv[0]` is the command; the arity rule only fires for a command signerd
 * actually has (an unknown command is answered by the usage banner, and a
 * flag signerd does not take is answered by the flag surface above - this
 * rule is about flags that ARE known and were used with the wrong shape).
 */
function parseArgv(argv) {
  const { args, raw } = parseTokens(argv);
  const command = argv.length > 0 && !argv[0].startsWith('--') ? argv[0] : undefined;
  return { args, problems: arityProblems(command, raw) };
}

/**
 * The token walk itself: the same shape for every surface that refuses by
 * arity. `raw` holds the CANDIDATE problems; which of them apply is decided
 * against a flag table afterwards (arityProblems / arityProblemsFor).
 */
function parseTokens(argv) {
  const args = { _: [] };
  const raw = [];
  const seen = new Map(); // flag -> the value it was first given
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) { args._.push(token); continue; }
    const key = token.slice(2);
    const next = argv[i + 1];
    const hasValue = !(next === undefined || next.startsWith('--'));
    if (seen.has(key)) {
      raw.push({ code: 'duplicate_flag', flag: key, first: seen.get(key), second: hasValue ? next : true });
      if (hasValue) i += 1;
      continue;
    }
    seen.set(key, hasValue ? next : true);
    if (hasValue) { args[key] = next; i += 1; } else { args[key] = true; }
    // Candidate arity problems: which one applies depends on whether the
    // surface treats the flag as a value flag or as a switch.
    raw.push(hasValue
      ? { code: 'flag_takes_no_value', flag: key, value: next }
      : { code: 'missing_value', flag: key });
  }
  return { args, raw };
}

/**
 * The arity rule against an EXPLICIT surface (the same rule as below, but
 * the caller names the flags instead of looking them up by command). The
 * example client uses it: its flags are not signerd commands, but the rule
 * that a flag given twice, a value flag with no value and a switch given a
 * value must be refused is the same rule.
 */
function arityProblemsFor(supportedList, switchList, raw) {
  const known = new Set(supportedList);
  const switches = new Set(switchList || []);
  const out = [];
  for (const p of raw) {
    if (!known.has(p.flag)) continue; // the flag surface owns this one
    if (p.code === 'duplicate_flag') { out.push(p); continue; }
    if (p.code === 'missing_value') {
      if (switches.has(p.flag)) continue; // a switch without a value is right
      out.push(p);
      continue;
    }
    if (p.code === 'flag_takes_no_value') {
      if (!switches.has(p.flag)) continue; // not a switch: its value is right
      out.push(p);
    }
  }
  return out;
}

/**
 * The arity rule for ONE command: which of the candidate problems actually
 * apply. A flag the command does not take is NOT an arity question - the
 * flag surface owns it (unknown_flag) - and a switch without a value is
 * exactly right, so both are dropped here.
 */
function arityProblems(command, problems) {
  const supported = COMMAND_FLAGS[command];
  if (supported === undefined) return []; // unknown command: not this rule
  return arityProblemsFor(supported, SWITCH_FLAGS[command], problems);
}

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
  sign: ['socket', 'grant', 'tx', 'out', 'dry'],
  'grant-add': [
    'grants', 'name', 'signer', 'keystore', 'destination', 'max-lamports',
    'window-max-lamports', 'window-seconds', 'expires', 'append',
    'seal-passphrase-file',
  ],
  'grant-remove': ['grants', 'name', 'seal-passphrase-file'],
  'sign-message': ['socket', 'grant', 'body', 'out', 'add-grant', 'keystore', 'grants', 'dry'],
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
  return checkFlagsFor(supported, args, (positionals || []).slice(1)); // [0] is the command itself
}

/**
 * The same rule against an EXPLICIT flag list (used by the example client):
 * every flag read must be listed, and every positional must be one the
 * surface reads - a mistyped flag or a stray token is refused, not dropped.
 */
function checkFlagsFor(supportedList, args, extraPositionals) {
  const known = new Set(supportedList);
  for (const key of Object.getOwnPropertyNames(args)) {
    if (key === '_') continue;
    if (!known.has(key)) {
      return { ok: false, code: 'unknown_flag', flag: key, supported: [...supportedList].sort() };
    }
  }
  const extra = extraPositionals || [];
  if (extra.length > 0) {
    return {
      ok: false, code: 'unknown_argument', argument: extra[0], supported: [...supportedList].sort(),
    };
  }
  return { ok: true };
}

/**
 * THE EXAMPLE CLIENT'S FLAG SURFACE (measured 2026-11-07, live).
 *
 * `examples/user-zero-client.js` is the documented way for a user-zero
 * adopter to ask for a signature without holding a key, and it ships in the
 * npm package. It kept its own parseArgs, which dropped every flag it did
 * not know and let the last value win for every flag given twice. Measured
 * against the real daemon, before the fix:
 *
 *   --totally-unknown x          -> exit 0, a REAL signature, 366 journal
 *                                    bytes. The flag vanished.
 *   --lamports 22 --lamports 999 -> exit 0, a REAL signature for 999.
 *   --out (no value)             -> exit 0, a REAL signature; --out read as
 *                                    absent.
 *   --hold yes                   -> exit 0, a REAL signature.
 *   --dry                        -> exit 0, a REAL signature - the REVERSE
 *                                    of what the flag means.
 *
 * The client is the first thing a user-zero adopter touches, and a client
 * that drops flags signs what the operator did not ask for. It now uses the
 * SAME rules as the daemon CLI (the surface, the arity, the repair).
 *
 * The flags are listed here, next to the daemon's, so there is ONE place
 * that says which flags exist - a surface that lives in two files drifts.
 */
const CLIENT_FLAGS = [
  'socket', 'grant', 'from', 'to', 'lamports', 'blockhash', 'out', 'hold', 'dry',
];

/** The client's switches: they take no value by design. */
const CLIENT_SWITCH_FLAGS = ['hold', 'dry'];

module.exports = {
  COMMAND_FLAGS, SWITCH_FLAGS, checkFlags, closestFlag, editDistance,
  parseArgv, arityProblems, parseTokens, arityProblemsFor, checkFlagsFor,
  CLIENT_FLAGS, CLIENT_SWITCH_FLAGS,
};
