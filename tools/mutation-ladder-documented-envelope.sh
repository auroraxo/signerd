#!/usr/bin/env bash
# MUTATION LADDER for the documented-envelope gate (2026-11-19).
#
# WHAT IT PROVES: every mutation below is CAUGHT by
# test/documented-envelope.test.js, and the tree comes back byte-identical.
#
# THE TWO RULES THIS LADDER ENFORCES ON ITSELF (both burned a run before —
# see tools/mutation-ladder-missing-flag-voice.sh):
#   R1 a mutation whose pattern does not apply is a NO-OP that would be
#      counted as VACUUM ("the test still passed"). Every step therefore
#      FAILS if the mutation did not apply;
#   R2 the byte-identical restore check compares against a PRE-LADDER
#      SNAPSHOT of the tree, never against git HEAD.
#
# The mutated surface is README.md (the claim page) and the instrument
# (tools/measure-documented-envelope.js) — the gate must catch a RE-BROKEN
# claim, a BLINDED detector, and a detector that reports nothing at all.
#
# Usage: bash tools/mutation-ladder-documented-envelope.sh
# Exit 0 = every mutation caught and the tree restored byte-identically.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
README="README.md"
TOOL="tools/measure-documented-envelope.js"
TEST="test/documented-envelope.test.js"
SNAPSHOT="$(mktemp -d /tmp/docenv-ladder-snapshot-XXXXXX)"

cleanup() {
  # The tree must come back as the ladder found it EVEN when a step aborts:
  # a mutation left applied is a mutated tree, not a ladder result. Restore
  # BEFORE the snapshot goes — the reverse order deletes the evidence first.
  if [[ -f "$SNAPSHOT/README.md" ]]; then
    cp "$SNAPSHOT/README.md" "$ROOT/README.md" 2>/dev/null || true
    cp "$SNAPSHOT/tools/measure-documented-envelope.js" "$ROOT/tools/measure-documented-envelope.js" 2>/dev/null || true
    cp "$SNAPSHOT/test/documented-envelope.test.js" "$ROOT/test/documented-envelope.test.js" 2>/dev/null || true
  fi
  rm -rf "$SNAPSHOT"
}
trap cleanup EXIT

# R2: the pre-ladder snapshot, taken BEFORE any mutation.
tar --exclude='./node_modules' --exclude='./.git' --exclude='./target' -cf - . | tar -xf - -C "$SNAPSHOT"

pass=0
fail=0
declare -a STEPS=()

restore_tree() {
  cp "$SNAPSHOT/$README" "$ROOT/$README"
  cp "$SNAPSHOT/$TOOL" "$ROOT/$TOOL"
  cp "$SNAPSHOT/$TEST" "$ROOT/$TEST"
}

run_gate() {
  node --test "$TEST" > /tmp/docenv-ladder-gate.log 2>&1
}

# A step mutates `file`, expects the gate to FAIL, and restores.
# grep_after: a pattern that must be PRESENT after the mutation (proof it
# applied); prefix with "!" to require ABSENCE (deletion mutations).
step() {
  local id="$1" description="$2" pattern="$3" replacement="$4" file="$5" grep_after="$6"
  cp "$SNAPSHOT/$file" "$ROOT/$file"
  # A step that cannot apply its mutation must still leave the tree as it
  # found it: the trap restores the whole snapshot on ANY exit.
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
  # R1: prove the mutation applied (or is absent) BEFORE judging the gate.
  if [[ "$grep_after" == !* ]]; then
    if grep -qE "${grep_after#!}" "$ROOT/$file"; then
      echo "M$n $id: VACUUM-RISK — pattern still present after deletion" >&2
      exit 3
    fi
  else
    if ! grep -qE "$grep_after" "$ROOT/$file"; then
      echo "M$n $id: VACUUM-RISK — mutated text not found in $file" >&2
      exit 3
    fi
  fi
  if run_gate; then
    echo "M$n $id: VACUUM (gate passed on the mutant)" >&2
    fail=$((fail+1)); STEPS+=("M$n $id VACUUM")
  else
    echo "M$n $id: CAUGHT" >&2
    pass=$((pass+1)); STEPS+=("M$n $id CAUGHT")
  fi
  restore_tree
}

n=0

# M1 RE-BREAK THE CLAIM: the Memo over-claim returns to the table.
n=$((n+1))
step "rebreak_memo_claim" \
  "the memo cell is claimed again but the policy refuses memo" \
  '\| A receipt body from a message grant \(openreceipts/v1\) \|' \
  '| Memo, ComputeBudget, a receipt body from a message grant (openreceipts/v1) |' \
  "$README" \
  'Memo, ComputeBudget, a receipt body'

# M2 RE-BREAK THE EXAMPLE: the unminted `alt` example returns.
n=$((n+1))
step "rebreak_alt_example" \
  "the README quotes {refused: \"alt\"} again — a code the source never mints" \
  'machine-readable reason \(`\{refused: "version_or_alt", \.\.\.\}`\)' \
  'machine-readable reason (`{refused: "alt", ...}`)' \
  "$README" \
  'refused: "alt"'

# M3 BLIND THE DETECTOR: the sign-claim judge flips so an over-claim reads
# as held (the fixture controls D-face judge directions must still catch it —
# the gate fails through D2b on the REAL README).
n=$((n+1))
step "blind_sign_judge" \
  "a detector that holds every Sign claim cannot certify this README" \
  "const holds = face\.expect === 'allowed'" \
  "const holds = true" \
  "$TOOL" \
  "!const holds = face\.expect"

# M4 BLIND THE EXAMPLE CHECK: the minted-code face stops reporting defects.
n=$((n+1))
step "blind_example_face" \
  "a detector that never reports an unminted example must fail D2" \
  "defect: unmintedExamples\.length > 0," \
  "defect: false," \
  "$TOOL" \
  "!defect: unmintedExamples"

# M5 DETECTOR REPORTS NOTHING: verdict hardcoded truthful (the VACUUM class
# the suite's own verdict assertion D2b exists to catch).
n=$((n+1))
step "hardcode_truthful_verdict" \
  "a detector whose verdict is hardcoded cannot fail" \
  "const verdict = defects\.length === 0 \? 'documented-envelope-truthful' : 'documented-envelope-overclaim';" \
  "const verdict = 'documented-envelope-truthful';" \
  "$TOOL" \
  "!const verdict = defects"

# M6 COVERAGE FACE OFF: an unreadable Sign cell would no longer fail closed.
n=$((n+1))
step "coverage_face_off" \
  "the fail-closed coverage face stops reporting uncovered cells" \
  "defect: uncoveredCells\.length > 0," \
  "defect: false," \
  "$TOOL" \
  "!defect: uncoveredCells"

echo "---- ladder result ----"
for s in "${STEPS[@]}"; do echo "$s"; done
if [[ $fail -ne 0 ]]; then
  echo "LADDER FAILED: $fail of $((pass+fail)) mutations VACUUM" >&2
  exit 1
fi
echo "LADDER OK: $pass/$((pass+fail)) caught"

# R2: byte-identical restore, against the PRE-LADDER snapshot.
if diff -r --exclude='.git' --exclude='node_modules' --exclude='target' "$SNAPSHOT" "$ROOT" > /tmp/docenv-ladder-restore.diff 2>&1; then
  echo "RESTORE: byte-identical"
else
  echo "RESTORE FAILED — tree differs from the pre-ladder snapshot:" >&2
  cat /tmp/docenv-ladder-restore.diff >&2
  exit 1
fi
