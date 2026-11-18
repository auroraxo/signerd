#!/usr/bin/env bash
# MUTATION LADDER for the journal-integrity voice
# (src/refusal-voice.js + src/ledger.js + bin/signerd.js).
#
# Each mutation breaks ONE property of the fix. The ladder is CAUGHT when the
# mutated tree fails a gate; the tree must be byte-identical afterwards.
#
# GATES = the new class gate (test/journal-integrity-voice.test.js) plus the
# coverage gate that shares the repair map (test/refusal-voice-coverage.test.js)
# - M6 is only visible to the coverage gate, because an EMPTY repair still
# prints a `fix:` line.
#
# Usage: bash tools/mutation-ladder-journal-integrity-voice.sh
set -u
cd "$(dirname "$0")/.." || exit 1
GATES="test/journal-integrity-voice.test.js test/refusal-voice-coverage.test.js test/refusal-voice.test.js"
WORK="$(mktemp -d)"
trap 'restore; rm -rf "$WORK"' EXIT

snapshot() {
  cp src/refusal-voice.js "$WORK/refusal-voice.js"
  cp src/ledger.js "$WORK/ledger.js"
  cp bin/signerd.js "$WORK/signerd.js"
}
restore() {
  [ -f "$WORK/refusal-voice.js" ] && cp "$WORK/refusal-voice.js" src/refusal-voice.js
  [ -f "$WORK/ledger.js" ] && cp "$WORK/ledger.js" src/ledger.js
  [ -f "$WORK/signerd.js" ] && cp "$WORK/signerd.js" bin/signerd.js
  return 0
}
snapshot

MUTATION_VACUUM=0

echo "mutation ladder for the journal-integrity voice"
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

# M1: drop ONE repair from the map (legacy_wire_required) - D2 must catch it.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "  legacy_wire_required: 'this journal is format 1"
i = s.index(needle)
j = s.index('\n', i) + 1
open('src/refusal-voice.js', 'w').write(s[:i] + s[j:])
EOF
caught "M1 drop the legacy_wire_required repair"

# M2: the generic tail never consults the map (the pre-fix behaviour) - D2.
python3 - <<'EOF'
s = open('bin/signerd.js').read()
needle = "const mapped = refusalFix(code);"
assert needle in s
s = s.replace(needle, "const mapped = null; // MUTATION: the map is never consulted", 1)
open('bin/signerd.js', 'w').write(s)
EOF
caught "M2 generic tail never consults the map"

# M3: the loader's refusals lose their code again (a bare Error) - D1/D7.
python3 - <<'EOF'
s = open('src/ledger.js').read()
needle = "if (chainHash(lastHash, record) !== record.h) throw ledgerRefusal('ledger_tampered');"
assert needle in s
s = s.replace(needle, "if (chainHash(lastHash, record) !== record.h) throw new Error('ledger_tampered');", 1)
open('src/ledger.js', 'w').write(s)
EOF
caught "M3 ledger_tampered back to a bare Error"

# M4: the repair carries a host path - D4 (and the coverage C4 rule).
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "ledger_mode: 'the journal is readable or writable by others - owner-only it: chmod 600 <ledger>',"
assert needle in s
s = s.replace(needle,
  "ledger_mode: 'the journal is readable or writable by others - owner-only it: chmod 600 /home/operator/<ledger>',", 1)
open('src/refusal-voice.js', 'w').write(s)
EOF
caught "M4 a repair carries a host path"

# M5: the repair names a command this CLI does not offer - D3 (and C3).
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "wires_dir_unreadable: 'the wires directory cannot be read - check the path: ls -ld <dir-of-saved-wires>',"
assert needle in s
s = s.replace(needle,
  "wires_dir_unreadable: 'the wires directory cannot be read - check it: signerd grant-list --wires <dir-of-saved-wires>',", 1)
open('src/refusal-voice.js', 'w').write(s)
EOF
caught "M5 a repair names an unoffered command"

# M6: the map entry is EMPTY - only the coverage gate C1b sees this one,
# because an empty repair still prints a `fix:` line to the operator.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "ledger_missing: 'no journal exists at that path yet - the daemon creates it on its first append; check the path: signerd status --grants <grants> --ledger <ledger>',"
assert needle in s
s = s.replace(needle, "ledger_missing: '',", 1)
open('src/refusal-voice.js', 'w').write(s)
EOF
caught "M6 an empty repair (coverage gate C1b)"

# M7: a DUPLICATE key in the repair map (a later entry silently wins) -
# the coverage gate C2 must catch it.
python3 - <<'EOF'
s = open('src/refusal-voice.js').read()
needle = "  ledger_corrupt: 'the journal is structurally broken"
assert needle in s
i = s.index(needle)
s = s[:i] + "  ledger_corrupt: 'MUTATION - a duplicate key silently wins',\n" + s[i:]
open('src/refusal-voice.js', 'w').write(s)
EOF
caught "M7 a duplicate key in the repair map"

restore

echo "restore check (must be clean):"
if [ -n "$(git status --porcelain src/refusal-voice.js src/ledger.js bin/signerd.js | grep -v '^ M')" ]; then
  echo "  UNEXPECTED: files changed beyond the original modifications"
fi
diff <(cat "$WORK/refusal-voice.js") src/refusal-voice.js >/dev/null \
  && diff <(cat "$WORK/ledger.js") src/ledger.js >/dev/null \
  && diff <(cat "$WORK/signerd.js") bin/signerd.js >/dev/null \
  && echo "  byte-identical: all three files match the pre-ladder tree" \
  || { echo "  TREE NOT RESTORED"; exit 1; }

if [ "$MUTATION_VACUUM" = "1" ]; then
  echo "LADDER FAILED: at least one mutation was VACUOUS"
  exit 1
fi
echo "ladder complete: 7/7 CAUGHT"
