#!/usr/bin/env bash
# Daily live consumer check for signerd.
#
# Usage: DAY=YYYY-MM-DD ./run.sh
#   DAY selects the artifact directory research/consumer-live-<DAY>/ and the
#   issued_at timestamps of the receipt bodies. Default: today (UTC).
#
# What it proves, end to end on this machine, EVERY day:
#   1. the PKCS8 issuer key imports into the signerd keystore (PEM -> seed -> raw64),
#   2. a message grant pinned to the site-derived public key signs,
#   3. receipt.py --via-signerd produces a document that BOTH openreceipts
#      verifiers accept against the REPO's pinned key keys/auroraxo.pub,
#   4. the client never creates a key file (OPENRECEIPTS_HOME stays absent),
#   5. an overdrawn window is refused structurally (window_cap, no file),
#   6. a replayed receipt body is refused after a daemon restart,
#   7. R6-1 (review #6): an EMPTY seal passphrase file must REFUSE to start,
#      not silently degrade to unsealed mode.
#   8. DRY-RUN FALSIFICATION: `--dry` of the identical receipt body is
#      allowed, signs nothing, writes nothing (--out + journal), and the SAME
#      body still signs for real afterwards (a dry that leaked a replay entry
#      would refuse here).
#
# Everything secret lives in a mktemp dir that is removed at the end.
# The day directory holds only the public receipt and the report.
set -euo pipefail

DAY="${DAY:-$(date -u +%F)}"
SIGNERD="$HOME/github_repos/signerd"
OPENRECEIPTS="$HOME/github_repos/openreceipts"
ISSUER_KEY="$HOME/.openreceipts/auroraxo.key"
PINNED="$OPENRECEIPTS/keys/auroraxo.pub"
OUTDIR="$SIGNERD/research/consumer-live-$DAY"

cd "$SIGNERD"
WORK="$(mktemp -d /tmp/signerd-live-consumer-XXXXXX)"
export LIVE_WORK="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
chmod 700 "$WORK"

echo "== 0. preconditions (day $DAY) =="
test -f "$ISSUER_KEY" || { echo "no issuer key at $ISSUER_KEY"; exit 1; }
test -f "$PINNED" || { echo "no pinned key"; exit 1; }
test -x tools/leasecheck || npm run build >/dev/null

PASSPHRASE_FILE="$WORK/pass"
umask 077
printf 'live consumer run %s %s\n' "$DAY" "$(date -u +%s)" > "$PASSPHRASE_FILE"
chmod 600 "$PASSPHRASE_FILE"

echo "== 1. derive raw64 from the PKCS8 key, import into keystore =="
node -e '
const fs = require("node:fs");
const { createPrivateKey, createPublicKey } = require("node:crypto");
const { Keypair } = require("@solana/web3.js");
const pem = fs.readFileSync(process.env.ISSUER_KEY ?? process.argv[1], "utf8");
const priv = createPrivateKey({ key: pem, format: "pem" });
const der = priv.export({ type: "pkcs8", format: "der" });
const seed = Buffer.from(der.subarray(der.length - 32));
const opensslPub = Buffer.from(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));
const kp = Keypair.fromSeed(seed);
if (!Buffer.from(kp.publicKey.toBytes()).equals(opensslPub)) { console.error("seed/pubkey mismatch"); process.exit(1); }
fs.writeFileSync(process.argv[2], Buffer.concat([Buffer.from(kp.secretKey.subarray(0, 64))]));
seed.fill(0);
console.log("raw64 written, pubkey matches OpenSSL derivation");
' "$ISSUER_KEY" "$WORK/issuer.raw"

node "$SIGNERD"/bin/signerd.js import --keystore "$WORK/ops.key" --passphrase-file "$PASSPHRASE_FILE" \
  --from "$WORK/issuer.raw" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const o=JSON.parse(d);console.log("keystore publicKey:",o.publicKey);});'
shred -u "$WORK/issuer.raw" 2>/dev/null || rm -f "$WORK/issuer.raw"

echo "== 2. grant pinned to the site-derived public key =="
node -e '
const fs = require("node:fs");
const { createPrivateKey, createPublicKey } = require("node:crypto");
const pem = fs.readFileSync(process.argv[1], "utf8");
const raw = createPublicKey(createPrivateKey({ key: pem, format: "pem" }))
  .export({ type: "spki", format: "der" }).subarray(-32);
fs.writeFileSync(process.argv[2], raw.toString("base64") + "\n");
' "$ISSUER_KEY" "$WORK/issuer.pub"
PUB="$(cat "$WORK/issuer.pub")"
PINNED_VAL="$(cat "$PINNED")"
if [ "$PUB" != "$PINNED_VAL" ]; then echo "site pubkey != pinned key"; exit 1; fi
echo "site pubkey == pinned key ($PUB)"

node -e '
const fs = require("node:fs");
const expires = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
fs.writeFileSync(process.argv[1], JSON.stringify({ version: 1, grants: {
  releases: { kind: "message", issuer: "auroraxo", type: "release", subject: "auroraxo/signerd",
    pubkey: process.argv[2], maxBytes: "700", expiresAt: expires,
    windowMaxMessages: "4", windowSeconds: "3600" },
}}, null, 2));
' "$WORK/grants.json" "$PUB"
chmod 600 "$WORK/grants.json"

echo "== 3. start the daemon =="
node "$SIGNERD"/bin/signerd.js run --keystore "$WORK/ops.key" --passphrase-file "$PASSPHRASE_FILE" \
  --grants "$WORK/grants.json" --ledger "$WORK/journal.jsonl" --socket "$WORK/signerd.sock" \
  > "$WORK/daemon.out" 2>&1 &
DAEMON_PID=$!
cleanup_daemon() { kill "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup_daemon EXIT
for i in $(seq 1 50); do [ -S "$WORK/signerd.sock" ] && break; sleep 0.2; done
test -S "$WORK/signerd.sock" || { echo "daemon did not start"; cat "$WORK/daemon.out"; exit 1; }

echo "== 4. client: receipt.py --via-signerd (empty OPENRECEIPTS_HOME) =="
CLIENT_HOME="$WORK/client-home"   # never created by a correct client
RECEIPT_OUT="$WORK/receipt.json"

# 4a. DRY-RUN FALSIFICATION (card next step 2026-11-06):
# The identical receipt body the real client is about to sign is previewed
# through `--dry` FIRST:
#   - must answer { ok: true, dry: true, allowed: true },
#   - must NOT produce a signature,
#   - must NOT write to --out,
#   - must NOT touch the journal (bytes before == bytes after),
#   - the SAME body is then signed for real in step 4b; a dry run that had
#     leaked anything into the journal would refuse with `replay`.
JOURNAL="$WORK/journal.jsonl"
JOURNAL_BYTES() { if [ -f "$JOURNAL" ]; then wc -c < "$JOURNAL"; else echo 0; fi; }
JOURNAL_BEFORE="$(JOURNAL_BYTES)"
DRY_BODY="$WORK/dry-body.json"
DRY_OUT="$WORK/dry-out.json"
node -e '
const fs = require("node:fs");
const day = process.argv[1];
const body = {
  schema: "openreceipts/v1",
  issuer: "auroraxo",
  type: "release",
  subject: "auroraxo/signerd",
  claims: { "message-grant": "live", "via": "signerd" },
  note: "receipt signed through the signerd daemon, no key in the client",
  issued_at: `${day}T21:00:00+00:00`,
};
fs.writeFileSync(process.argv[2], JSON.stringify(body, null, 2) + "\n");
' "$DAY" "$DRY_BODY"

DRY_RES="$(node "$SIGNERD"/bin/signerd.js sign-message \
  --socket "$WORK/signerd.sock" --grant releases \
  --body "$DRY_BODY" --out "$DRY_OUT" --dry)"
echo "dry preview response: $DRY_RES"
node -e '
const res = JSON.parse(process.argv[1]);
if (!res.ok || !res.dry || !res.allowed) {
  console.error("dry run refused:", res);
  process.exit(1);
}
if (res.signature !== undefined) {
  console.error("dry run produced signature:", res);
  process.exit(1);
}
if (res.budgetConsumed !== false) {
  console.error("dry run consumed budget:", res);
  process.exit(1);
}
' "$DRY_RES"

if [ -e "$DRY_OUT" ]; then
  echo "FAIL: --dry wrote the --out file"; exit 1
fi
JOURNAL_AFTER_DRY="$(JOURNAL_BYTES)"
if [ "$JOURNAL_BEFORE" -ne "$JOURNAL_AFTER_DRY" ]; then
  echo "FAIL: --dry mutated the journal ($JOURNAL_BEFORE -> $JOURNAL_AFTER_DRY)"; exit 1
fi
echo "OK: dry preview allowed, 0 bytes journaled, --out untouched"

# 4b. REAL CLIENT RUN: identical body, client has no key material
cd "$OPENRECEIPTS"
OPENRECEIPTS_HOME="$CLIENT_HOME" python3 receipt.py sign \
  --issuer auroraxo --type release --subject auroraxo/signerd \
  --claim message-grant=live --claim via=signerd \
  --note "receipt signed through the signerd daemon, no key in the client" \
  --issued-at "${DAY}T21:00:00+00:00" \
  --via-signerd "$WORK/signerd.sock" --grant releases \
  --out "$RECEIPT_OUT"

if [ -e "$CLIENT_HOME" ]; then echo "FAIL: client created OPENRECEIPTS_HOME"; exit 1; fi
echo "OK: client home does not exist (no key material touched)"

echo "== 5. both verifiers, against the REPO pinned key =="
python3 receipt.py verify "$RECEIPT_OUT" --key "$PINNED"
node verify.mjs --key "$PINNED" "$RECEIPT_OUT" >/dev/null && echo "OK: verify.mjs accepts it"

echo "== 6. overdraw (window 4): after 1 + 3 signs the next must be refused =="
for i in 1 2 3; do
  OPENRECEIPTS_HOME="$CLIENT_HOME" python3 receipt.py sign \
    --issuer auroraxo --type release --subject auroraxo/signerd \
    --claim window-test=$i --issued-at "${DAY}T21:0$i:00+00:00" \
    --via-signerd "$WORK/signerd.sock" --grant releases \
    --out "$WORK/w$i.json" >/dev/null
done
if OPENRECEIPTS_HOME="$CLIENT_HOME" python3 receipt.py sign \
  --issuer auroraxo --type release --subject auroraxo/signerd \
  --claim window-test=4 --issued-at "${DAY}T21:04:00+00:00" \
  --via-signerd "$WORK/signerd.sock" --grant releases \
  --out "$WORK/w4.json" 2>"$WORK/w4.err"; then
  echo "FAIL: overdrawn window was accepted"; exit 1
fi
grep -q "refused: window_cap" "$WORK/w4.err" || { echo "FAIL: expected window_cap, got:"; cat "$WORK/w4.err"; exit 1; }
test ! -e "$WORK/w4.json" || { echo "FAIL: refused sign wrote a file"; exit 1; }
echo "OK: 4th sign refused (window_cap), no file written"

echo "== 7. restart the daemon, replay the same body =="
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true
node "$SIGNERD"/bin/signerd.js run --keystore "$WORK/ops.key" --passphrase-file "$PASSPHRASE_FILE" \
  --grants "$WORK/grants.json" --ledger "$WORK/journal.jsonl" --socket "$WORK/signerd.sock" \
  >> "$WORK/daemon.out" 2>&1 &
DAEMON_PID=$!
for i in $(seq 1 50); do [ -S "$WORK/signerd.sock" ] && break; sleep 0.2; done
test -S "$WORK/signerd.sock" || { echo "daemon did not restart"; cat "$WORK/daemon.out"; exit 1; }

# replay: same type/subject/issued_at as the first receipt body
if OPENRECEIPTS_HOME="$CLIENT_HOME" python3 receipt.py sign \
  --issuer auroraxo --type release --subject auroraxo/signerd \
  --claim message-grant=live --claim via=signerd \
  --note "receipt signed through the signerd daemon, no key in the client" \
  --issued-at "${DAY}T21:00:00+00:00" \
  --via-signerd "$WORK/signerd.sock" --grant releases \
  --out "$WORK/replay.json" 2>"$WORK/replay.err"; then
  echo "FAIL: replay accepted"; exit 1
fi
grep -q "refused: replay" "$WORK/replay.err" || { echo "FAIL: expected replay, got:"; cat "$WORK/replay.err"; exit 1; }
test ! -e "$WORK/replay.json" || { echo "FAIL: replay wrote a file"; exit 1; }
echo "OK: replay refused across a daemon restart, no file written"

echo "== 8. R6-1: an EMPTY seal passphrase must refuse to start =="
: > "$WORK/empty-pass"
chmod 600 "$WORK/empty-pass"
if node "$SIGNERD"/bin/signerd.js run --keystore "$WORK/ops.key" --passphrase-file "$PASSPHRASE_FILE" \
  --grants "$WORK/grants.json" --ledger "$WORK/journal2.jsonl" --socket "$WORK/empty.sock" \
  --grant-seal-passphrase-file "$WORK/empty-pass" > "$WORK/empty.out" 2>&1; then
  echo "FAIL: daemon started with an empty seal passphrase (sealed mode silently off)"; exit 1
fi
grep -q "seal_passphrase_required" "$WORK/empty.out" \
  || { echo "FAIL: expected seal_passphrase_required, got:"; cat "$WORK/empty.out"; exit 1; }
test ! -e "$WORK/empty.sock" || { echo "FAIL: refused daemon left a socket"; exit 1; }
echo "OK: empty seal passphrase refused at startup (seal_passphrase_required)"

echo "== 9. copy the artifact + report for the repo =="
mkdir -p "$OUTDIR"
cp "$RECEIPT_OUT" "$OUTDIR/receipt.json"
node -e '
const fs = require("node:fs");
const path = require("node:path");
const work = process.argv[1];
const out = path.join(process.argv[2], "report.json");
const doc = JSON.parse(fs.readFileSync(path.join(work, "receipt.json"), "utf8"));
fs.writeFileSync(out, JSON.stringify({
  generatedAt: new Date().toISOString(),
  day: process.argv[3],
  what: "receipt signed through a signerd daemon via receipt.py --via-signerd; issuer key held only by the daemon",
  clientKeyMaterial: "none — OPENRECEIPTS_HOME never created",
  verifiedAgainst: "openreceipts/keys/auroraxo.pub (pinned, both verifiers)",
  checks: {
    both_verifiers_accept: true,
    site_pubkey_equals_pinned: true,
    overdrawn_window_refused: "window_cap, no file written",
    replay_after_restart_refused: "replay, no file written",
    empty_seal_passphrase_refused: "seal_passphrase_required, daemon did not start",
    dry_preview_allowed: true,
    dry_wrote_no_signature: true,
    dry_journaled_bytes: 0,
    dry_out_untouched: true,
    real_sign_after_dry_succeeded: true,
    receipt: doc,
  },
}, null, 2) + "\n");
console.log("report written");
' "$WORK" "$OUTDIR" "$DAY"

echo "ALL LIVE CONSUMER CHECKS PASSED ($DAY)"
