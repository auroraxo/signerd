'use strict';

// THE REFUSAL VOICE for a verdict that comes back over the socket.
//
// WHY (measured 2026-11-17, tools/measure-daemon-refusal-voice.js, this
// tree): a policy refusal from the daemon reached the operator as
//
//     stdout: {"ok":false,"error":"destination","detail":{...}}
//     stderr: (0 bytes)
//
// while EVERY other refusal class in this CLI prints a code AND a repair:
// a transport refusal, a client-verification refusal, an unknown flag, a
// grant-file refusal, an unreadable input file. The README promises it:
// "Refusals name the flag and the fix instead of failing silently."
//
// The daemon's own verdict is the one class that stayed mute on stderr -
// and it is the class this product exists for ("die Verweigerung ist das
// Produkt"). An agent holding a grant needs to be told WHAT TO DO when its
// request is refused, not only which name the refusal wears.
//
// THE RULES THIS MODULE KEEPS:
//
//   1. ONE place maps a refusal code to a repair. The daemon attaches the
//      repair to the frame it already answers with; the CLI prints
//      `<code>` + `  fix: ...` on stderr. Neither side invents wording.
//   2. A repair names a command this CLI ACTUALLY OFFERS (src/cli-flags.js
//      rule F3). `test/refusal-voice.test.js` enforces coverage of every
//      code the source can emit, so a NEW refusal code cannot ship mute.
//   3. A repair never carries a host path. It says `<grants>`, `<ledger>`,
//      `<keystore>` — the operator substitutes their own. Measured as a
//      guard (G3 in the measurement tool), not asserted from memory.
//   4. The MACHINE channel does not change: `ok`/`error`/`detail` stay
//      exactly as they were. A refusal is still data the example client
//      (src/client.js) reads as `answer.error`.
//
// `facts` may carry a GRANT NAME (`grant`) for the refusals where the name
// is the actionable part. It never carries a path (rule 3).

/**
 * Codes whose repair depends on WHICH request was refused.
 *
 * `envelope` is one code emitted by two different rules: src/policy.js
 * refuses a transaction outside the offline-decidable envelope, and
 * src/policy-message.js refuses a receipt body outside openreceipts/v1.
 * One word, two repairs - the old map silently kept whichever duplicate key
 * the JS object literal last, which is how a transaction refusal ended up
 * telling the operator about receipt fields (caught by
 * test/refusal-voice.test.js before it shipped).
 *
 * The daemon knows which one it ran: a request that carried a `body` is a
 * message-grant request, anything else is a transaction request.
 */
const KIND_SCOPED = {
  envelope: {
    transaction: 'the transaction is outside the envelope this daemon decides offline (one signer, one System transfer) — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
    message: 'the receipt carries a field openreceipts/v1 does not allow — keep exactly schema, issuer, type, subject, claims, issued_at',
  },
};

/**
 * Code -> repair text (without the `fix: ` prefix).
 *
 * Commands referenced here, all real:
 *   keygen, grant-add, grant-remove, build-tx, import, run, sign,
 *   sign-message, status, seal-grants, verify-grants, seal-journal, migrate
 */
const REPAIRS = {
  // ---- the transaction envelope (src/policy.js) -------------------------
  invalid_wire: 'the --tx file is not a readable unsigned transaction — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  noncanonical_wire: 'the transaction bytes do not round-trip — rebuild it instead of editing it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  version_or_alt: 'only legacy System transfers are signed here; this wire is a versioned (v0) transaction — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  duplicate_key: 'the transfer does not have three distinct account keys — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  signer_or_fee_payer: 'the transaction fee payer is not this grant\'s signer — build the transaction with the keystore the grant pins: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  destination: 'this grant pins ONE destination — send to it, or scope the new one: signerd grant-add --grants <grants> --name <grant> --append --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  program: 'only a System transfer is signed here — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  instruction_accounts: 'the instruction is not a plain System transfer — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  instruction_data: 'the instruction data is not a System transfer (opcode 2) — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  amount: 'the transfer exceeds the grant\'s per-transaction cap (maxLamports) — lower --lamports, or widen the scope: signerd grant-add --grants <grants> --name <grant> --append --max-lamports <u64> --destination <pubkey> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',

  // ---- the grant the daemon read ----------------------------------------
  invalid_grant: 'a grant field is missing or malformed — recreate the grant: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  invalid_grant_window: 'the grant\'s rolling window is unusable (windowMaxLamports must be at least the 5000-lamport base fee, windowSeconds a whole number) — recreate it: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  expired: 'the grant\'s expiresAt has passed — renew the scope: signerd grant-add --grants <grants> --name <grant> --append --expires <iso in the future> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs>',
  invalid_clock: 'the host clock is not a real instant, so no grant can be judged — fix the host clock and retry',

  // ---- the journal and the rolling window --------------------------------
  replay: 'this message was already signed once and the journal keeps that record — sign a NEW transaction (a fresh blockhash): signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',
  window_cap: 'the grant\'s rolling window is spent — wait for the window to pass, or widen it: signerd grant-add --grants <grants> --name <grant> --append --window-max-lamports <u64> --window-seconds <secs> --destination <pubkey> --max-lamports <u64> --expires <iso>',
  ledger_inconsistent: 'the journal is inconsistent and was not trusted — start the daemon once so it can repair the tail, then retry',
  ledger_unavailable: 'the journal could not be reached — check it with: signerd status --grants <grants> --ledger <ledger>',
  invalid_message: 'the receipt body is empty or unreadable — pass a JSON file: signerd sign-message --socket <file> --grant <name> --body <json-file>',
  ledger_anchor_unwritable: 'the journal\'s seal floor could not be written — make the journal directory owner-only and writable: chmod 700 $(dirname <ledger>)',
  invalid_amount: 'the grant\'s maxLamports is not a u64 — recreate the grant: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',

  // ---- the key (src/signer.js, src/signer-message.js) --------------------
  signer_unavailable: 'the daemon has no signing key loaded — restart it with the keystore: signerd run --keystore <keystore> --passphrase-file <file> --grants <grants> --ledger <ledger> --socket <file>',
  signer_key_mismatch: 'the grant pins a public key this keystore does not hold — re-derive the grant from the keystore: signerd sign-message --add-grant --keystore <keystore> --body <file>, or signerd grant-add --keystore <keystore> ...',
  sign_failed: 'the daemon could not produce a signature — nothing was returned; check the daemon\'s log before retrying',
  sign_verify_failed: 'the daemon\'s own signature check failed, so no signature was returned — check the daemon\'s log; retry with a fresh transaction: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',

  // ---- the openreceipts/v1 message envelope (src/policy-message.js) -----
  invalid_body: 'the receipt body is not a JSON object — pass a JSON file: signerd sign-message --socket <file> --grant <name> --body <json-file>',
  invalid_schema: 'the receipt schema is not openreceipts/v1 — set "schema": "openreceipts/v1"',
  issuer: 'the receipt\'s issuer is not the one this grant pins — use the pinned value, or scope this issuer: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  type: 'the receipt\'s type is not the one this grant pins — use the pinned value, or scope this type: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  subject: 'the receipt\'s subject is not the one this grant pins — use the pinned value, or scope this subject: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  claims: 'the receipt\'s claims are outside what this grant permits (names, count, value types) — bootstrap the grant from the body: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  message_too_large: 'the receipt exceeds this grant\'s maxBytes — trim the claims, or widen the scope: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  issued_at_in_future: 'the receipt claims an issued_at in the future — set it to an instant that has already passed',

  // ---- the request and the grant lookup (src/daemon.js) ------------------
  request_invalid: 'the request frame is malformed (it needs a `grant` and exactly one of `wire`/`body`) — build it with: signerd sign ... or signerd sign-message ...',
  body_invalid: 'the `body` file must hold a JSON OBJECT (the receipt itself) — pass a JSON file: signerd sign-message --socket <file> --grant <name> --body <json-file>',
  grant_not_found: 'no grant by that name is in the grant file — list the names: signerd status --grants <grants> --ledger <ledger>, or create it: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  grant_kind_mismatch: 'a message body was sent to a transaction grant (or a wire to a message grant) — use signerd sign for transaction grants and signerd sign-message for message grants',
  daemon_not_running: 'the daemon is not running — start it: signerd run --keystore <keystore> --passphrase-file <file> --grants <grants> --ledger <ledger> --socket <file>',
  ledger_lock_lost: 'another process owns this journal now — stop the other daemon, then check: signerd status --socket <file>',
  one_request_per_connection: 'exactly one request is answered per connection — open a new connection for each request',
  internal_error: 'the daemon hit an unexpected error — check the daemon\'s log and retry',

  // ---- the grant file as the loader judged it ----------------------------
  // The loader refuses the WHOLE file when it is unusable; the repair is the
  // same shape for the family, with the family-specific wording.
  grant_file_unreadable: 'the grant file cannot be read — create or repair it: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  grant_file_invalid: 'the grant file is not a valid grant document — recreate it: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  grant_file_mode: 'the grant file is readable or writable by others — owner-only it: chmod 600 <grants>',
  grant_file_owner: 'the grant file is not owned by this user — chown it back to yourself: chown $(id -u) <grants> && chmod 600 <grants>',
  grant_file_dir_mode: 'the grant file\'s directory allows group/other access — owner-only it: chmod 700 $(dirname <grants>)',
  grant_file_dir_owner: 'the grant file\'s directory is not owned by this user — chown it back to yourself: chown $(id -u) $(dirname <grants>) && chmod 700 $(dirname <grants>)',
  grant_file_dir_unreadable: 'the grant file\'s directory cannot be read — check its path and permissions: ls -ld $(dirname <grants>)',
  grant_file_symlink: 'the grant file path is a symlink — replace the link with a real file, then point --grants at the intended file',
  grant_file_sealed: 'the grant file carries a seal and no passphrase was given — read it with: signerd run ... --grant-seal-passphrase-file <file> (or add that flag to this command)',
  grant_file_unsealed: 'a seal passphrase was given but the grant file carries no seal - drop the passphrase flag, or seal the file first: signerd seal-grants --grants <grants> --seal-passphrase-file <file>',
  grant_file_seal_invalid: 'the grant file\'s seal block is not a seal this version can read (version, algorithm or key-derivation parameters do not match) - re-seal the file after checking it by hand: signerd seal-grants --grants <grants> --seal-passphrase-file <file>',
  grant_file_seal_key_missing: 'a verified read was asked for but no seal key was derived - pass the seal passphrase with --grant-seal-passphrase-file <file> (or --seal-passphrase-file on verify-grants/seal-grants)',
  grant_file_seal_mismatch: 'the grant file\'s contents do not match its seal (an edit after sealing, or a different passphrase than the one it was sealed with) - if the edit was yours, re-seal: signerd seal-grants --grants <grants> --seal-passphrase-file <file>; if it was not, treat the file as forged and restore it from a backup',
  grant_file_key_mismatch: 'more than one key is named in a file that holds ONE key — drop the foreign grant: signerd grant-remove --grants <grants> --name <grant>',
  grant_file_exists: 'a grant file already exists there — add to it instead: signerd grant-add --grants <grants> --name <grant> --append ...',
  grant_file_write_failed: 'the grant file could not be written — check the directory is writable and has space: ls -ld $(dirname <grants>)',
  grant_file_locked: 'another writer holds this grant file\'s lock (a concurrent grant-add/grant-remove/seal-grants, or a dead writer\'s stale lock) — retry once it finished: signerd status --grants <grants> --ledger <ledger>',
  grant_file_lock_failed: 'the grant file\'s lock could not be claimed — check the directory is writable: ls -ld $(dirname <grants>)',
  grant_signer_mismatch: 'the grant pins a signer this daemon\'s keystore is not — rebuild the grant from this keystore: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  grant_key_mismatch: 'the grant pins a public key this keystore does not hold — re-derive it from the keystore: signerd sign-message --add-grant --keystore <keystore> --body <file>',
  grant_name_invalid: 'the grant name has characters this daemon does not accept — use letters, digits, `_`, `-`, `.` or `+`',
  grant_invalid: 'the grant document is not shaped the way this daemon reads it — recreate it: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  grant_unknown_field: 'the grant file carries a field this daemon does not know — remove it; a typo in a security file is never an extra rule',
  grant_exists: 'a grant with that name already exists — add a different scope with --append',
  grant_expired_at_creation: 'the expiry is already in the past — pass an instant in the FUTURE: --expires 2030-01-01T00:00:00Z',
  grant_field_invalid: 'a grant field holds a value this daemon cannot honour — see the grant-add usage for the field\'s domain',
  grant_not_found_cli: 'no grant by that name is in the grant file — list the names: signerd status --grants <grants> --ledger <ledger>',

  // ---- the transport and the frame ---------------------------------------
  request_too_large: 'the request frame must stay within 25600 bytes — shrink the body, not the cap',
  response_too_large: 'the answer frame must stay within 8192 bytes — treat the socket as untrusted and retry',
  response_invalid: 'the answer was not a verdict from this daemon — check that --socket names the daemon you started, not another service',
  connection_closed: 'the daemon closed the connection before a verdict arrived — check the daemon is running: signerd status --socket <file>',
  request_timeout: 'no verdict arrived in time — check the daemon: signerd status --socket <file>',
  socket_missing: 'no daemon has ever bound that path — start it: signerd run --keystore <keystore> --passphrase-file <file> --grants <grants> --ledger <ledger> --socket <file>',
  socket_stale: 'a dead daemon left the socket file behind — remove it and start the daemon again: rm <file> && signerd run --keystore <keystore> --passphrase-file <file> --grants <grants> --ledger <ledger> --socket <file>',
  socket_not_reachable: 'the daemon at that path cannot be reached — check it: signerd status --socket <file>',
  socket_connect_failed: 'the socket connection failed — check it: signerd status --socket <file>',
  socket_state_unknown: 'the socket state cannot be proven, so it is refused rather than guessed — check it: signerd status --socket <file>',

  // ---- the journal and the tools that judge it (2026-11-18) --------------
  // WHY: the journal-integrity refusals were the last mute class. Measured
  // on the published v0.2.35 (tools/measure-journal-integrity-voice.js,
  // research/journal-integrity-voice-published-v0235-2026-11-18.json): the
  // operator got a NAME (or, where the loader raised a bare Error, not even
  // that - the name was buried as "error: ledger_tampered") and NO repair,
  // on the exact surface where history itself is untrustworthy. The README
  // promises the opposite: "Refusals name the flag and the fix."
  //
  // Rules (the same as above): every repair names a command this CLI offers
  // (F3), never a host path - the operator's <ledger> placeholder stands for
  // their own path; the repair must be RUNNABLE as printed.
  ledger_missing: 'no journal exists at that path yet - the daemon creates it on its first append; check the path: signerd status --grants <grants> --ledger <ledger>',
  ledger_not_a_file: 'the journal path is not a regular file - point --ledger at the journal file itself, not at a directory or a link: signerd status --grants <grants> --ledger <ledger>',
  ledger_unreadable: 'the journal cannot be read - check the path and its permissions: ls -l <ledger>',
  ledger_mode: 'the journal is readable or writable by others - owner-only it: chmod 600 <ledger>',
  ledger_owner: 'the journal is not owned by this user - chown it back to yourself: chown $(id -u) <ledger> && chmod 600 <ledger>',
  ledger_dir_mode: 'the journal\'s directory allows group/other WRITING, so anyone could swap the journal - owner-only the directory: chmod 700 $(dirname <ledger>)',
  ledger_dir_owner: 'the journal\'s directory is not owned by this user - chown it back to yourself: chown $(id -u) $(dirname <ledger>) && chmod 700 $(dirname <ledger>)',
  ledger_dir_invalid: 'the journal\'s path is not a directory - point --ledger at a path inside a real directory',
  ledger_corrupt: 'the journal is structurally broken (a record no loader version ever wrote) - restore it from a backup; do not hand-edit history',
  ledger_tampered: 'a journal record was edited after it was written (the chain no longer verifies) - restore the journal from a backup; a journal whose chain does not verify is never trusted, and hand-editing it does not repair it',
  ledger_mac_invalid: 'a SEALED journal record was edited (the keyed chain refuses it) - restore from a backup; if none exists, note the refusal and do not sign against this history',
  ledger_mac_short: 'the journal\'s keyed chain is incomplete (a sealed record lost its MAC) - restore from a backup; do not hand-repair history',
  ledger_torn_tail: 'the journal\'s last line was cut off (a crash mid-append) - start the daemon once and it repairs the torn tail itself, then retry',
  ledger_sealed: 'this journal is SEALED and no passphrase was given - it is never read unsealed: pass the seal key (--journal-seal-passphrase-file <file>), or migrate/seal with the matching flag',
  ledger_unsealed_journal: 'a seal passphrase was given but the journal carries no seal - drop the flag for an unsealed journal, or seal it: signerd seal-journal --journal <ledger> --journal-seal-passphrase-file <file>',
  ledger_legacy_format: 'this journal is format 1 (no message identity) - migrate it before use: signerd migrate --ledger <ledger> --wires <dir-of-saved-wires> (or --discard-legacy to accept the loss explicitly)',
  ledger_locked: 'a LIVE daemon holds this journal\'s lock - stop it first (a crashed daemon\'s lock is taken over automatically): signerd status --socket <file>',
  ledger_lock_failed: 'the journal lock could not be claimed - check the journal\'s directory is writable: ls -ld $(dirname <ledger>)',
  ledger_anchor_missing: 'the journal is shorter than its seal floor claims (truncation, or the floor is gone) - restore both files from a backup; a journal and a floor that disagree are never trusted',
  ledger_anchor_invalid: 'the journal\'s seal floor file is unusable - check it: ls -l <ledger>.anchor',
  ledger_anchor_mode: 'the journal\'s seal floor is readable or writable by others - owner-only it: chmod 600 <ledger>.anchor',
  ledger_anchor_owner: 'the journal\'s seal floor is not owned by this user - chown it back to yourself: chown $(id -u) <ledger>.anchor && chmod 600 <ledger>.anchor',
  ledger_anchor_dir: 'the seal floor\'s path is not a directory - point --ledger at a path inside a real directory',
  ledger_anchor_mismatch: 'the seal floor does not witness this journal (a rollback of one of the two) - restore both from a backup; the floor says how much history the daemon approved',
  ledger_changed: 'the journal changed while the migration was judging it (a daemon is still writing) - stop the daemon, then retry: signerd migrate --ledger <ledger> ...',
  ledger_file_required: 'no journal path was given - pass it: --ledger <ledger>',
  journal_seal_passphrase_required: 'this journal is sealed and the seal key is required - pass it: --journal-seal-passphrase-file <file>',
  journal_seal_key_invalid: 'the journal seal passphrase is empty - write it into a 0600 file and pass that file',
  journal_seal_chain_invalid: 'the journal\'s chain could not be verified under the seal key - the journal does not match this passphrase\'s history; use the passphrase it was sealed with',
  seal_self_check_failed: 'seal-journal verified its own output and it did not parse - nothing was changed; report this as a bug with the journal (never hand-edit it)',
  migration_self_check_failed: 'the migration verified its own output and it did not parse - nothing was changed, the backup was not written; report this as a bug with the journal',
  legacy_wire_required: 'this journal is format 1 and needs its message identity restored - either hand back the original wires: signerd migrate --ledger <ledger> --wires <dir>, or accept the loss explicitly: --discard-legacy',
  legacy_wire_missing: 'the wires directory does not hold the original wire for every legacy record - collect every wire the clients kept (--out files) into one directory and pass it: signerd migrate --ledger <ledger> --wires <dir>',
  wires_dir_unreadable: 'the wires directory cannot be read - check the path: ls -ld <dir-of-saved-wires>',
  lease_unavailable: 'the kernel lease helper could not be used - build it by hand once: cc -O2 -o tools/leasecheck tools/leasecheck.c (it ships next to the package), then retry',

  // ---- the refusals THIS CLI mints itself (2026-11-18) -------------------
  // WHY: the refusal voice was closed class by class — the daemon's
  // verdicts (v0.2.34), the journal-integrity family (v0.2.36), the
  // build-tx value inputs (v0.2.37), the import source file (v0.2.24
  // sweep). What remained were the refusals bin/signerd.js prints at its
  // OWN ad-hoc sites, each written by hand: the keystore faces keygen and
  // import raise, the --body shape check, grant-add's signer requirement,
  // the passphrase-file ownership rule. Measured on the tree 4a2ae5f
  // (tools/measure-cli-voice.js, research/cli-voice-prefix-2026-11-18.json):
  // 7 of 7 faces violated the contract — a code with no repair, a bare
  // errno as the reason, prose with no code at all.
  //
  // The same rules as everywhere else: the repair names a command or a
  // flag this CLI actually offers, and it never carries a host path — the
  // operator substitutes their own (<keystore>, <file>, <id.json>).
  keystore_exists: 'a keystore already exists at that path - replace it with --overwrite (the old key is then gone), or point --keystore at a different path',
  keystore_write_failed: 'the keystore could not be written - point --keystore at a writable path that is a FILE, not a directory: signerd keygen --keystore <keystore> --passphrase-file <file>',
  keystore_symlink: 'the keystore path is a symlink - remove the link and point --keystore at the intended file',
  keystore_path_required: 'no keystore path was given - pass it: --keystore <keystore>',
  keystore_unreadable: 'the keystore file cannot be read - check the path and its permissions: ls -l <keystore>',
  passphrase_required: 'a passphrase is required - pass it with --passphrase-file <file> (a file holding the passphrase, owner-only): signerd keygen --keystore <keystore> --passphrase-file <file>',
  seal_passphrase_required: 'the grant-seal passphrase file is empty - write the passphrase into the file (it must not be empty or newline-only), keep it owner-only, and pass it again: --grant-seal-passphrase-file <file> / --seal-passphrase-file <file>',
  keystore_mode: 'the keystore file is readable or writable by others - owner-only it: chmod 600 <keystore>',
  keystore_auth_failed: 'the passphrase does not open this keystore - check the passphrase (it is the one this keystore was created with)',
  keystore_invalid: 'the keystore file is not a keystore this version can read - create one: signerd keygen --keystore <keystore> --passphrase-file <file>',
  keystore_dir_mode: 'the keystore\'s directory allows group/other WRITING, so anyone could swap the keystore - owner-only it: chmod 700 <keystore-dir>',
  keystore_dir_owner: 'the keystore\'s directory is not owned by this user - chown it back to yourself: chown $(id -u) <keystore-dir>',
  keystore_dir_unreadable: 'the keystore\'s directory cannot be read - check its path: ls -ld <keystore-dir>',
  secret_key_invalid: 'the source file does not hold a Solana secret key - pass a solana-keygen id.json (a JSON array of 64 numbers), a base58 secret key, or a raw 64-byte file: signerd import --keystore <keystore> --from <id.json> --passphrase-file <file>',
  import_source_required: 'no source file was given - pass it: --from <id.json>',
  import_source_is_target: 'the source and the keystore are the same file - point --from at the plaintext key you want to adopt: signerd import --keystore <keystore> --from <id.json> --passphrase-file <file>',
  import_source_unreadable: 'the source file cannot be read - check the path and its permissions: ls -l <id.json>',
  grant_add_signer_required: 'the signer is not stated and cannot be derived - give it, or let it be read from the keystore: signerd grant-add --grants <grants> --name <grant> --keystore <keystore> --destination <pubkey> --max-lamports <u64> --window-max-lamports <u64> --window-seconds <secs> --expires <iso>',
  passphrase_file_mode: 'the passphrase file is readable by others - owner-only it: chmod 600 <file>',
  passphrase_file_owner: 'the passphrase file is not owned by this user - chown it back to yourself: chown $(id -u) <file> && chmod 600 <file>',
  passphrase_file_dir_mode: 'the passphrase file\'s directory allows group/other WRITING, so anyone could replace the file there - owner-only it: chmod 700 <file-dir>',
  passphrase_file_dir_owner: 'the passphrase file\'s directory is not owned by this user - chown it back to yourself: chown $(id -u) <file-dir>',
};

/**
 * The repair for a refusal code, or null when this module does not know it.
 *
 * A null must not be printed as an empty `fix:` line: a repair line that
 * says nothing is the same defect this module exists to close. The caller
 * prints the code alone in that case, and the coverage test in
 * test/refusal-voice.test.js is what keeps null out of real traffic.
 *
 * @param {string} code   the refusal's machine-readable code
 * @param {object} [facts] optional `{ grant }` — a GRANT NAME, never a path
 * @returns {string|null}
 */
function refusalFix(code, facts) {
  const kind = facts && (facts.kind === 'transaction' || facts.kind === 'message')
    ? facts.kind : null;
  let text = null;
  if (kind !== null && Object.prototype.hasOwnProperty.call(KIND_SCOPED, code) &&
      Object.prototype.hasOwnProperty.call(KIND_SCOPED[code], kind)) {
    text = KIND_SCOPED[code][kind];
  } else if (Object.prototype.hasOwnProperty.call(REPAIRS, code)) {
    text = REPAIRS[code];
  }
  if (text === null) return null;
  const grant = facts && typeof facts.grant === 'string' ? facts.grant : null;
  if (grant === null) return text;
  // The grant name is the actionable part of the lookup refusals: naming it
  // back to the operator removes the "which grant did I mean?" step. A grant
  // name can never be a path (the loader rejects `/`), so this stays within
  // rule 3.
  //
  // The placeholder is replaced literally, NOT with a word boundary: `\b`
  // does not match before `<` (a non-word character), so `\b<grant>\b`
  // silently replaced nothing. And `<grant>` is not a prefix of `<grants>`
  // (the next character is `s`, not `>`), so the file placeholder is safe.
  return text.split('<grant>').join(grant);
}

module.exports = { refusalFix, REPAIRS, KIND_SCOPED };
