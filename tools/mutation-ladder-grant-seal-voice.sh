#!/usr/bin/env bash
# MUTATION LADDER for the grant-seal voice
# (src/refusal-voice.js + src/grantseal.js + src/grantfile.js).
#
# Each mutation breaks ONE property of the fix. The ladder is CAUGHT when the
# mutated tree fails a gate; the tree must be byte-identical afterwards.
#
# GATES = the new class gate (test/grant-seal-voice.test.js) plus the
# coverage gate that shares the repair map (test/refusal-voice-coverage.test.js)
# - M2 is only visible to the coverage gate (an EMPTY repair still prints a
#   `fix:` line), M3 only to the class gate (dropping the DETAIL does not
#   touch the map), M6 only to the class gate (the coverage scrape is gone).
#
# Two lessons from earlier ladders, built in:
#   - every step VERIFIES the mutation applied (the python step asserts its
#     needle, the ladder greps the mutated tree before judging; a no-op that
#     counts as CAUGHT is a vacuum);
#   - the restore is compared against a PRE-LADDER SNAPSHOT of the files,
#     never against git HEAD.
#
# Usage: bash tools/mutation-ladder-grant-seal-voice.sh
set -u
cd "$(dirname "$0")/.." || exit 1
GATES="test/grant-seal-voice.test.js test/refusal-voice-coverage.test.js"
WORK="$(mktemp -d)"
trap 'restore; rm -rf "$WORK"' EXIT

FILES="src/refusal-voice.js src/grantseal.js src/grantfile.js src/grantadd.js test/refusal-voice-coverage.test.js"

snapshot() {
  for f in $FILES; do cp "$f" "$WORK/$(basename "$f")"; done
}
restore() {
  for f in $FILES; do
    [ -f "$WORK/$(basename "$f")" ] && cp "$WORK/$(basename "$f")" "$f"
  done
  return 0
}
snapshot

MUTATION_VACUUM=0

echo "mutation ladder for the grant-seal voice"
echo "baseline:"
node --test $GATES 2>&1 | grep -E "^ℹ (pass|fail)" | sed 's/^/  /'

caught() {  # $1 = label
  local out
  out=$(node --test $GATES 2>&1)
  if echo "$out" | grep -qE "^ℹ fail [1-9]"; then
    echo "  CAUGHT  $1"
  else
    echo "  VACUUM  $1  <-- a gate passed on a broken tree"
    MUTATION_VACUUM=1
  fi
  restore
}

applied() {  # kept for symmetry with earlier ladders; each step greps directly
  return 0
}

# M1: drop the grant_file_seal_mismatch repair - coverage C1 (grantseal is
# scraped now) AND the class gate D3 must catch it.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "grant_file_seal_mismatch: 'the grant file\\'s contents do not match its seal"
assert needle in s, "M1 needle missing"
i = s.index(needle)
j = s.index('\n', i) + 1
open('src/refusal-voice.js', 'w').write(s[:i] + s[j:])
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M1"; MUTATION_VACUUM=1; }
grep -q "grant_file_seal_mismatch: " src/refusal-voice.js && { echo "    M1 NOT APPLIED (entry still present)"; MUTATION_VACUUM=1; } || echo "    M1 applied (entry gone)"
caught "M1 the mismatch repair is dropped"

# M2: an EMPTY repair - only the coverage gate C1b sees this (an empty fix
# still prints a `fix:` line to the operator).
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "  seal_passphrase_required: 'the grant-seal passphrase file is empty"
assert needle in s, "M2 needle missing"
i = s.index(needle)
j = s.index('\n', i) + 1
open('src/refusal-voice.js', 'w').write(s[:i] + "  seal_passphrase_required: '',\n" + s[j:])
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M2"; MUTATION_VACUUM=1; }
grep -q "seal_passphrase_required: ''" src/refusal-voice.js && echo "    M2 applied" || { echo "    M2 NOT APPLIED"; MUTATION_VACUUM=1; }
caught "M2 an empty repair (coverage gate C1b)"

# M3: the mismatch DETAIL is dropped again (the bare-name refusal the sweep
# found) - only the class gate D2 sees this; the map is untouched.
python3 - <<'EOF'
s = open('src/grantseal.js').read()
needle = "      detail: 'the contents do not match this seal (edited after sealing, or a different passphrase than the one it was sealed with)',\n"
assert needle in s, "M3 needle missing"
open('src/grantseal.js', 'w').write(s.replace(needle, "", 1))
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M3"; MUTATION_VACUUM=1; }
grep -q "the contents do not match this seal" src/grantseal.js && { echo "    M3 NOT APPLIED"; MUTATION_VACUUM=1; } || echo "    M3 applied (detail gone)"
caught "M3 the mismatch detail is dropped (class gate D2)"

# M4: a repair carries a host path - D4 (class gate) and C4 (coverage).
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "grant_file_seal_invalid: 'the grant file\\'s seal block is not a seal this version can read"
assert needle in s, "M4 needle missing"
s = s.replace(needle, "grant_file_seal_invalid: '/home/operator seal block is not a seal this version can read", 1)
open('src/refusal-voice.js', 'w').write(s)
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M4"; MUTATION_VACUUM=1; }
grep -q "grant_file_seal_invalid: '/home/operator" src/refusal-voice.js && echo "    M4 applied" || { echo "    M4 NOT APPLIED"; MUTATION_VACUUM=1; }
caught "M4 a repair carries a host path"

# M5: the repair names a command this CLI does not offer - D3 and C3.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "re-seal: signerd seal-grants"
assert needle in s, "M5 needle missing"
s = s.replace("re-seal: signerd seal-grants", "re-seal: signerd seal-documents", 1)
open('src/refusal-voice.js', 'w').write(s)
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M5"; MUTATION_VACUUM=1; }
grep -q "signerd seal-documents" src/refusal-voice.js && echo "    M5 applied" || { echo "    M5 NOT APPLIED"; MUTATION_VACUUM=1; }
caught "M5 a repair names an unoffered command"

# M6: the coverage gate stops scraping the seal family AND one repair is
# dropped - the class gate ALONE must still catch the missing repair (the
# two gates are independent, not one leaning on the other).
python3 - <<'EOF'
s = open('test/refusal-voice-coverage.test.js').read()
# BOTH scrape sites: the modules list AND the seal-family pattern entry -
# removing only the list entry would leave multiPatternFiles scraping
# grantseal.js, and the mutation would be a no-op for the coverage gate.
needle = "'ledger.js', 'daemon.js', 'keystore.js', 'grantseal.js',"
assert needle in s, "M6 needle missing"
s = s.replace(needle, "'ledger.js', 'daemon.js', 'keystore.js',", 1)
needle1b = "    'grantseal.js': /(?:fail|new Error|reason:)\\s*\\(?\\s*'([a-z_]+)'/g,\n"
assert needle1b in s, "M6 needle1b missing"
s = s.replace(needle1b, "", 1)
open('test/refusal-voice-coverage.test.js', 'w').write(s)
# Drop a repair the CLASS GATE covers face-by-face (D3): with the scrape
# gone, only the class gate can catch this.
t = open('src/refusal-voice.js').read()
needle2 = "grant_file_seal_mismatch: 'the grant file\\'s contents do not match its seal"
assert needle2 in t, "M6b needle missing"
i = t.index(needle2)
j = t.index('\n', i) + 1
open('src/refusal-voice.js', 'w').write(t[:i] + t[j:])
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M6"; MUTATION_VACUUM=1; }
grep -q "'ledger.js', 'daemon.js', 'keystore.js', 'grantseal.js'," test/refusal-voice-coverage.test.js && { echo "    M6 NOT APPLIED (modules list)"; MUTATION_VACUUM=1; } || echo "    M6 applied (modules list)"
grep -q "reason:)\\s\*" test/refusal-voice-coverage.test.js && { echo "    M6b NOT APPLIED (seal pattern still there)"; MUTATION_VACUUM=1; } || echo "    M6b applied (seal pattern gone)"
grep -q "grant_file_seal_mismatch: " src/refusal-voice.js && { echo "    M6c NOT APPLIED (repair still there)"; MUTATION_VACUUM=1; } || echo "    M6c applied (repair gone)"
caught "M6 coverage stops scraping grantseal + a repair is dropped (class gate alone)"

# M7: the resolved path comes back into the grant_file_sealed reason - the
# class gate D4 (host-path rule on RAW stderr) must catch it.
python3 - <<'EOF'
s = open('src/grantfile.js').read()
needle = "      'the grant file carries a seal but no passphrase was given: ' +"
assert needle in s, "M7 needle missing"
s = s.replace(needle, "      `the grant file carries a seal (${resolved}) but no passphrase was given: ` +", 1)
open('src/grantfile.js', 'w').write(s)
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M7"; MUTATION_VACUUM=1; }
grep -qF 'carries a seal (${resolved})' src/grantfile.js && echo "    M7 applied" || { echo "    M7 NOT APPLIED"; MUTATION_VACUUM=1; }
caught "M7 the host path returns to the sealed reason"

# M8: a DUPLICATE key in the repair map - coverage C2.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "  grant_file_seal_invalid: 'the grant file\\'s seal block"
assert needle in s, "M8 needle missing"
i = s.index(needle)
open('src/refusal-voice.js', 'w').write(
    s[:i] + "  grant_file_seal_invalid: 'MUTATION - a duplicate key silently wins',\n" + s[i:])
EOF
[ $? -eq 0 ] || { echo "  APPLIED-FAIL M8"; MUTATION_VACUUM=1; }
grep -q "MUTATION - a duplicate key silently wins" src/refusal-voice.js && echo "    M8 applied" || { echo "    M8 NOT APPLIED"; MUTATION_VACUUM=1; }
caught "M8 a duplicate key in the repair map"

restore

echo "restore check (must be byte-identical to the pre-ladder snapshot):"
CLEAN=1
for f in $FILES; do
  if diff -q "$WORK/$(basename "$f")" "$f" >/dev/null; then
    echo "  byte-identical: $f"
  else
    echo "  TREE NOT RESTORED: $f"
    CLEAN=0
  fi
done

if [ "$MUTATION_VACUUM" = "1" ] || [ "$CLEAN" = "0" ]; then
  echo "LADDER FAILED (vacuum or unrestored tree)"
  exit 1
fi
echo "ladder complete: 8/8 CAUGHT"
