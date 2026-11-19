#!/usr/bin/env bash
# MUTATION LADDER for the duplicate-key voice (2026-11-19).
#
# WHAT IT PROVES: every mutation below is CAUGHT by
# test/duplicate-key-voice.test.js, and the tree comes back byte-identical.
#
# THE TWO RULES THIS LADDER ENFORCES ON ITSELF (both burned a run before):
#   R1 a mutation whose sed pattern does not apply is a NO-OP that would be
#      counted as VACUUM ("the test still passed"). Every step therefore
#      prints the mutated line and FAILS if the mutation did not apply;
#   R2 the byte-identical restore check compares against a PRE-LADDER
#      SNAPSHOT of the tree, never against git HEAD (a dirty tree or a
#      mid-run commit makes HEAD the wrong reference).
#
# Usage: bash tools/mutation-ladder-duplicate-key.sh
# Exit 0 = every mutation caught and the tree restored byte-identically.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
GRANTFILE="src/grantfile.js"
VOICE="src/refusal-voice.js"
TEST="test/duplicate-key-voice.test.js"
SNAPSHOT="$(mktemp -d /tmp/dk-ladder-snapshot-XXXXXX)"

cleanup() {
  rm -rf "$SNAPSHOT"
}
trap cleanup EXIT

# R2: the pre-ladder snapshot, taken BEFORE any mutation.
tar --exclude='./node_modules' --exclude='./.git' --exclude='./target' -cf - . | tar -xf - -C "$SNAPSHOT"

pass=0
fail=0

restore_tree() {
  cp "$SNAPSHOT/$GRANTFILE" "$ROOT/$GRANTFILE"
  cp "$SNAPSHOT/$VOICE" "$ROOT/$VOICE"
  cp "$SNAPSHOT/$TEST" "$ROOT/$TEST"
}

run_gate() {
  node --test "$TEST" > /tmp/dk-ladder-gate.log 2>&1
}

# A step mutates a file, expects the gate to FAIL, and restores.
# grep_after: a pattern that must be PRESENT after the mutation (proof it
# applied); prefix with "!" to require ABSENCE (deletion mutations).
step() {
  local id="$1" description="$2" pattern="$3" replacement="$4" file="$5" grep_after="$6"
  cp "$SNAPSHOT/$file" "$ROOT/$file"
  # R1: apply, then PROVE the mutation applied.
  if ! python3 - "$ROOT/$file" "$pattern" "$replacement" <<'PY'
import re, sys
path, pattern, replacement = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding='utf8').read()
new, n = re.subn(pattern, replacement, text, count=1)
if n != 1:
    print(f"MUTATION DID NOT APPLY: {pattern}", file=sys.stderr)
    sys.exit(3)
open(path, 'w', encoding='utf8').write(new)
PY
  then
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

# M1: the whole scanner call is dropped - the loader goes back to
# last-wins (the pre-fix behaviour this ladder exists to keep dead).
# The grep proof is the CALL SITE: after the mutation the loader must not
# mention the scanner at all (deletion mutation -> the marker must be
# ABSENT from the call site block).
step M1 "the duplicate scan is never called" \
  '  const dup = duplicateDocumentKey\(raw\);\n  if \(dup !== null\) \{\n    throw fail\(.grant_duplicate_key.,\n      `the document names "\$\{dup\}" twice - JSON would silently keep the LAST spelling, ` \+\n      .which is not the file you read: remove the stale block and keep one.\);\n  \}' \
  '' \
  "$GRANTFILE" '!const dup = duplicateDocumentKey(raw);'

# M2: the scanner is called but its verdict is ignored - the refusal never
# happens, yet the code still looks present.
step M2 "the scanner result is ignored" \
  '  if \(dup !== null\) \{' \
  '  if (false) {' \
  "$GRANTFILE" 'if (false) {'

# M3: the refusal code is renamed - the reason the operator sees changes,
# so the map lookup (and D1/D4/D5) no longer matches.
step M3 "the refusal code is renamed" \
  "throw fail\('grant_duplicate_key'," \
  "throw fail('grant_file_invalid'," \
  "$GRANTFILE" "throw fail('grant_file_invalid',"

# M4: the detail no longer names the duplicated key (the operator cannot
# tell WHICH member is written twice).
step M4 "the detail drops the duplicated key" \
  '`the document names "\$\{dup\}" twice' \
  '`the document names a key twice' \
  "$GRANTFILE" 'the document names a key twice'

# M5: the detail loses the "twice" wording (D3: the operator must learn
# that a spelling would be dropped, not just that the file is invalid).
step M5 "the detail loses the twice wording" \
  '`the document names "\$\{dup\}" twice - JSON would silently keep the LAST spelling, ` \+' \
  '`the document names "\${dup}" - something is wrong here, ` +' \
  "$GRANTFILE" 'something is wrong here'

# M6: the repair is dropped from the ONE map - the refusal reaches the
# operator without a fix (D7).
step M6 "the repair is missing from the map" \
  '  grant_duplicate_key: .*?\n' \
  '' \
  "$VOICE" '!grant_duplicate_key:'

# M7: the repair names a command this CLI does NOT offer (rule F3 of the
# refusal voice: a repair may only name a real command). The mutation
# replaces the WHOLE repair, not a part of it - a partial replacement
# leaves another real command name in the string and the rule cannot see
# the dead end.
step M7 "the repair names a command that does not exist" \
  '  grant_duplicate_key: .*?\n' \
  "  grant_duplicate_key: 'the grant file names a key twice — open it and delete the stale duplicate block: signerd repair-file --grants <grants>',\n" \
  "$VOICE" 'signerd repair-file'

# M8: the scanner compares GLOBALLY instead of per object - every grant in
# the file repeats every field name, so a global comparison refuses every
# legal file (the false-positive direction: the product would brick).
step M8 "the scanner compares names globally, not per object" \
  '      if \(current\.has\(name\)\) return name; // THE DUPLICATE\n      current\.add\(name\);' \
  '      if (seen.has(name)) return name; // THE DUPLICATE
      seen.add(name);
      current.add(name);' \
  "$GRANTFILE" 'if (seen.has(name)) return name;'

# M9: the scanner forgets to push a scope for a nested object - a grant's
# own fields are then compared against the GRANT names, so a file whose
# grant is named like a field breaks.
step M9 "the scanner does not scope nested objects" \
  '    if \(ch === .\{.\) \{\n      stack\.push\(new Set\(\)\);' \
  '    if (ch === '"'"'{'"'"') {
      stack.push(current === undefined ? new Set() : current);' \
  "$GRANTFILE" 'stack.push(current === undefined ? new Set() : current);'

echo
echo "LADDER: $pass caught, $fail not caught"

# R2: the byte-identical restore check against the PRE-LADDER SNAPSHOT.
if diff -r --exclude=node_modules --exclude=.git --exclude=target "$SNAPSHOT" "$ROOT" > /tmp/dk-ladder-diff.log 2>&1; then
  echo "RESTORE: the tree is byte-identical to the pre-ladder snapshot"
  restore_ok=0
else
  echo "RESTORE: THE TREE DIFFERS from the pre-ladder snapshot:"
  head -30 /tmp/dk-ladder-diff.log
  restore_ok=1
fi

if [ "$fail" -ne 0 ] || [ "$restore_ok" -ne 0 ]; then
  exit 1
fi
exit 0
