#!/usr/bin/env bash
# MUTATION LADDER for the missing-flag voice (2026-11-19).
#
# WHAT IT PROVES: every mutation below is CAUGHT by
# test/missing-flag-voice.test.js, and the tree comes back byte-identical.
#
# THE TWO RULES THIS LADDER ENFORCES ON ITSELF (both burned a run before):
#   R1 a mutation whose sed pattern does not apply is a NO-OP that would be
#      counted as VACUUM ("the test still passed"). Every step therefore
#      prints the mutated line and FAILS if the mutation did not apply;
#   R2 the byte-identical restore check compares against a PRE-LADDER
#      SNAPSHOT of the tree, never against git HEAD (a dirty tree or a
#      mid-ladder commit makes HEAD the wrong reference).
#
# Usage: bash tools/mutation-ladder-missing-flag-voice.sh
# Exit 0 = every mutation caught and the tree restored byte-identically.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
CLI="bin/signerd.js"
TEST="test/missing-flag-voice.test.js"
SNAPSHOT="$(mktemp -d /tmp/mf-ladder-snapshot-XXXXXX)"

cleanup() {
  rm -rf "$SNAPSHOT"
}
trap cleanup EXIT

# R2: the pre-ladder snapshot, taken BEFORE any mutation.
tar --exclude='./node_modules' --exclude='./.git' --exclude='./target' -cf - . | tar -xf - -C "$SNAPSHOT"

pass=0
fail=0
declare -a STEPS=()

restore_tree() {
  # Restore ONLY the files a step touched, from the snapshot.
  cp "$SNAPSHOT/$CLI" "$ROOT/$CLI"
  cp "$SNAPSHOT/$TEST" "$ROOT/$TEST"
}

run_gate() {
  node --test "$TEST" > /tmp/mf-ladder-gate.log 2>&1
}

# A step mutates the CLI, expects the gate to FAIL, and restores.
# grep_after: a pattern that must be PRESENT after the mutation (proof it
# applied); prefix with "!" to require ABSENCE (deletion mutations).
step() {
  local id="$1" description="$2" pattern="$3" replacement="$4" file="$5" grep_after="$6"
  cp "$SNAPSHOT/$file" "$ROOT/$file"
  # R1: apply, then PROVE the mutation applied.
  python3 - "$ROOT/$file" "$pattern" "$replacement" <<'PY'
import re, sys
path, pattern, replacement = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding='utf8').read()
new, n = re.subn(pattern, replacement, text, count=1)
if n != 1:
    print(f"MUTATION DID NOT APPLY: {pattern}", file=sys.stderr)
    sys.exit(3)
open(path, 'w', encoding='utf8').write(new)
PY
  if [ $? -ne 0 ]; then
    echo "FAIL $id — the mutation did not apply (VACUUM, not a caught mutation)"
    fail=$((fail + 1))
    restore_tree
    return
  fi
  if [ "${grep_after:0:1}" = "!" ]; then
    if grep -q -- "${grep_after:1}" "$ROOT/$file"; then
      echo "FAIL $id — the deleted line is still in the tree (VACUUM)"
      fail=$((fail + 1))
      restore_tree
      return
    fi
  elif ! grep -q -- "$grep_after" "$ROOT/$file"; then
    echo "FAIL $id — the mutated line is not in the tree (VACUUM)"
    fail=$((fail + 1))
    restore_tree
    return
  fi
  echo "--- mutation applied: $id ($description)"
  if run_gate; then
    echo "FAIL $id — VACUUM: the gate still passed with the mutation in place"
    fail=$((fail + 1))
  else
    echo "CAUGHT $id"
    pass=$((pass + 1))
  fi
  restore_tree
}

# M1: the code is gone — the refusal falls back to bare prose.
step M1 "the missing_flag code is dropped" \
  'missing_flag: --\$\{flag\}' \
  'missing --${flag}' \
  "$CLI" 'missing --\${flag}'

# M2: the fix line that names the flag is dropped (deletion — the marker
# must be ABSENT).
step M2 "the fix that names the absent flag is dropped" \
  '    `  fix: give --\$\{flag\} a value[^`]*` \+\n' \
  '' \
  "$CLI" '!give --\${flag} a value'

# M3: the takes list is dropped — the operator no longer learns the surface.
step M3 "the takes list is dropped" \
  '    \? `  fix: signerd \$\{ACTIVE_COMMAND\} takes:[^\n]*\n' \
  "    ? ''\n" \
  "$CLI" '!ACTIVE_COMMAND} takes'

# M4: the takes list is hardcoded to a WRONG surface (a copy that drifted).
step M4 "the takes list names a surface that is not the real one" \
  'supported\.map\(\(f\) => `--\$\{f\}`\)\.join\('"'"' '"'"'\)' \
  "supported.map(() => '--keystore').join(' ')" \
  "$CLI" "map(() => '--keystore')"

# M5: the exit code becomes 0 — a usage question would look like success.
step M5 "the refusal exits 0" \
  '  process\.exit\(2\);\n\}\n\nfunction requireArg' \
  '  process.exit(0);
}

function requireArg' \
  "$CLI" 'process.exit(0);'

# M6: the refusal writes to stdout instead of stderr — the machine channel
# would carry a usage question as if it were a verdict frame.
step M6 "the refusal goes to stdout" \
  '  process\.stderr\.write\(`missing_flag: --\$\{flag\}' \
  '  process.stdout.write(`missing_flag: --${flag}' \
  "$CLI" 'process.stdout.write(`missing_flag'

# M7: the refusal names the WRONG flag (the code is right, the subject is
# not) — the operator is told to give a flag the command does not take.
step M7 "the refusal names the wrong flag" \
  'missing_flag: --\$\{flag\}' \
  'missing_flag: --keystore' \
  "$CLI" 'missing_flag: --keystore'

# M8: a host path leaks into the fix line (rule 3 of the refusal voice —
# the guard the measurement pins as no-host-path).
step M8 "the fix carries a host path" \
  'a value — this command cannot run without it' \
  'a value in /home/aurora/.config/signerd is missing' \
  "$CLI" '/home/aurora/.config/signerd'

echo
echo "LADDER: $pass caught, $fail not caught"

# R2: the byte-identical restore check against the PRE-LADDER SNAPSHOT.
if diff -r --exclude=node_modules --exclude=.git --exclude=target "$SNAPSHOT" "$ROOT" > /tmp/mf-ladder-diff.log 2>&1; then
  echo "RESTORE: the tree is byte-identical to the pre-ladder snapshot"
  restore_ok=0
else
  echo "RESTORE: THE TREE DIFFERS from the pre-ladder snapshot:"
  head -30 /tmp/mf-ladder-diff.log
  restore_ok=1
fi

if [ "$fail" -ne 0 ] || [ "$restore_ok" -ne 0 ]; then
  exit 1
fi
exit 0
