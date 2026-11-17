#!/usr/bin/env bash
# MUTATION LADDER for the daemon refusal voice (src/refusal-voice.js +
# src/daemon.js + bin/signerd.js).
#
# Each mutation breaks ONE property of the fix. The ladder is CAUGHT when the
# mutated tree fails the gate; the tree must be byte-identical afterwards.
#
# Usage: bash tools/mutation-ladder-refusal-voice.sh
set -u
cd "$(dirname "$0")/.." || exit 1
REPO="$PWD"
GATE="test/refusal-voice.test.js"
WORK="$(mktemp -d)"
trap 'restore; rm -rf "$WORK"' EXIT

snapshot() {
  cp src/refusal-voice.js "$WORK/refusal-voice.js"
  cp src/daemon.js "$WORK/daemon.js"
  cp bin/signerd.js "$WORK/signerd.js"
}
restore() {
  [ -f "$WORK/refusal-voice.js" ] && cp "$WORK/refusal-voice.js" src/refusal-voice.js
  [ -f "$WORK/daemon.js" ] && cp "$WORK/daemon.js" src/daemon.js
  [ -f "$WORK/signerd.js" ] && cp "$WORK/signerd.js" bin/signerd.js
  return 0
}
snapshot

run_gate() {
  # Only the ladder under test; a full-suite run per mutation is too slow.
  node --test "$GATE" 2>&1 | grep -E "^# (pass|fail)|^ℹ (pass|fail)" | tr -d '\n'
  echo
}

caught() {  # $1 = label
  local out
  out=$(node --test "$GATE" 2>&1)
  if echo "$out" | grep -qE "^ℹ fail [1-9]"; then
    echo "  CAUGHT  $1"
  else
    echo "  VACUUM  $1  <-- the gate passed on a broken tree"
    MUTATION_VACUUM=1
  fi
  restore
}

echo "mutation ladder for the daemon refusal voice"
echo "baseline:"
node --test "$GATE" 2>&1 | grep -E "^ℹ (pass|fail)" | sed 's/^/  /'

# M1: the daemon attaches no repair at all -> D1/D2 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/daemon.js'; s0=open(p).read(); s=s0
s=s.replace("if (response && response.ok === false && typeof response.fix !== 'string') {",
            "if (false && response && response.ok === false && typeof response.fix !== 'string') {",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M1 daemon attaches no fix"

# M2: the CLI prints nothing to stderr on a refusal -> D1 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='bin/signerd.js'; s0=open(p).read(); s=s0
s=s.replace("      const refusal = refusalText(response, { grant, kind: 'transaction' });\n      if (refusal !== null) writeStderrSync(refusal);",
            "      const refusal = null;",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M2 CLI prints no refusal on stderr (sign)"

# M3: the repair is emptied -> D2 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
# M3 real: drop the fix LINE from the CLI printer.
p='bin/signerd.js'; s0=open(p).read(); s=s0
s=s.replace("""  return fix === null
    ? `${code}\\n`
    : `${code}\\n  fix: ${fix}\\n`;""",
            """  return `${code}\\n`;""",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M3 CLI drops the fix line"

# M4: the repair names a command this CLI does not offer -> D3 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/refusal-voice.js'; s0=open(p).read(); s=s0
s=s.replace("  destination: 'this grant pins ONE destination",
            "  destination: 'signerd grant-list --all shows it — this grant pins ONE destination",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M4 repair names an unknown command (grant-list)"

# M5: the repair leaks a host path -> D4 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/refusal-voice.js'; s0=open(p).read(); s=s0
s=s.replace("  destination: 'this grant pins ONE destination",
            "  destination: '/home/aurora/signerd was the path — this grant pins ONE destination",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M5 repair leaks a host path"

# M6: the machine channel is changed (a refusal no longer says ok:false) -> D5 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/daemon.js'; s0=open(p).read(); s=s0
s=s.replace("        if (fix !== null) response.fix = fix;\n      }",
            "        if (fix !== null) response.fix = fix;\n        if (response.error === 'destination') response.ok = true;\n      }",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M6 machine channel corrupted (ok:false -> true)"

# M7: the happy path starts chattering -> D6 must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='bin/signerd.js'; s0=open(p).read(); s=s0
s=s.replace("""function refusalText(response, facts) {
  if (response === null || typeof response !== 'object') return null;""",
            """function refusalText(response, facts) {
  if (response === null || typeof response !== 'object') return null;
  return 'refusal chatter\\n  fix: noise\\n';""",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M7 happy path starts chattering on stderr"

# M8: the kind-scoped envelope collapses to the message wording -> D1 must fail
# for a TRANSACTION refusal outside the envelope.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/refusal-voice.js'; s=open(p).read()
s=s.replace("""    transaction: 'the transaction is outside the envelope this daemon decides offline (one signer, one System transfer) — rebuild it: signerd build-tx --keystore <keystore> --to <pubkey> --lamports <u64> --out <tx>',""",
            """    transaction: 'the receipt carries a field openreceipts/v1 does not allow — keep exactly schema, issuer, type, subject, claims, issued_at',""",1)
assert "receipt carries a field openreceipts/v1 does not allow" in s, "M8 pattern not found - the mutation did NOT apply"
open(p,'w').write(s)
PY
caught "M8 transaction envelope repair points at receipt fields"

# M9: the grant-name substitution is dropped -> the grant-name test must fail.
python3 - <<'PY' || { echo '  FATAL: a mutation python failed - the ladder result would be false'; exit 1; }
p='src/refusal-voice.js'; s0=open(p).read(); s=s0
s=s.replace("  return text.split('<grant>').join(grant);",
            "  return text;",1)
assert s != s0, 'mutation did NOT apply (no-op)'
open(p,'w').write(s)
PY
caught "M9 grant name never reaches the repair"

echo "tree byte-identical after restore:"
# Compared against the ladder's OWN snapshot, not against HEAD: src/refusal-voice.js
# is a new (untracked) file, so `git diff` says nothing about it.
same=1
for f in refusal-voice.js daemon.js signerd.js; do
  case "$f" in
    refusal-voice.js) target="src/refusal-voice.js" ;;
    daemon.js) target="src/daemon.js" ;;
    signerd.js) target="bin/signerd.js" ;;
  esac
  cmp -s "$WORK/$f" "$target" || { echo "  NO - $target differs"; same=0; }
done
[ "$same" = "1" ] && echo "  yes" 
if [ "${MUTATION_VACUUM:-0}" = "1" ]; then
  echo "RESULT: VACUUM - at least one mutation passed the gate"
  exit 1
fi
echo "RESULT: 9/9 CAUGHT, tree byte-identical"
