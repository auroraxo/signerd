#!/usr/bin/env bash
# Mutation ladder for the grant bootstrap judgement fix (src/grantadd.js).
#
# Each mutation re-introduces ONE of the defects the fix closes (or breaks a
# guard), runs the ladder test file, and requires the ladder to CATCH it
# (test failures > 0). CONTROL must stay green. After every mutation the tree
# is restored byte-identically (verified by sha256 of the whole source file).
#
# Usage: tools/mutation-ladder-grant-bootstrap-judge.sh
set -uo pipefail

cd "$(dirname "$0")/.."
SRC="src/grantadd.js"
LADDER="test/grant-bootstrap-judge.test.js"

CONTROL_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
FAILED=0

restore() {
  [ -f "$CONTROL_SHA.backup" ] || return 0
  cp "$CONTROL_SHA.backup" "$SRC"
  local now
  now=$(sha256sum "$SRC" | cut -d' ' -f1)
  if [ "$now" != "$CONTROL_SHA" ]; then
    echo "VACUUM FAIL: $SRC not restored (expected $CONTROL_SHA, got $now)"
    exit 2
  fi
}
trap restore EXIT

cp "$SRC" "$CONTROL_SHA.backup"

run_ladder() {
  local out fails
  out=$(node --test "$LADDER" 2>&1)
  # node --test prints either TAP ("# fail N") or spec ("ℹ fail N") summaries.
  fails=$(printf '%s\n' "$out" | grep -E "^(ℹ|#) fail [0-9]+" | tail -1 | grep -oE '[0-9]+$')
  printf '%s\n' "${fails:-}"
}

expect_caught() {
  local name="$1" mutation="$2"
  cp "$CONTROL_SHA.backup" "$SRC"
  apply_mutation "$mutation" || { echo "ESCAPED: $name (mutation did not apply)"; FAILED=1; return; }
  local fails
  fails=$(run_ladder)
  if [ "${fails:-0}" -gt 0 ] 2>/dev/null; then
    echo "CAUGHT: $name (fail=$fails)"
  else
    echo "ESCAPED: $name (ladder stayed green — mutation not caught)"
    FAILED=1
  fi
}

apply_mutation() {
  case "$1" in
    parse-instead-of-load)
      # B1+B2: judge the file with a bare JSON.parse (version/seal/name only),
      # exactly the pre-fix hand-rolled check.
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "  const loaded = loadGrantFile(resolved);\n"
assert a in s, "judge call not found"
b = """  const loaded = loadGrantFile(resolved);
"""
old = a
new = """  // MUTANT: hand-rolled parse, no product loader (the pre-fix judgement).
  if (doc === null || typeof doc !== 'object' || doc.version !== 1 ||
      typeof doc.grants !== 'object' || doc.grants === null || Array.isArray(doc.grants)) {
    throw fail('grant_file_invalid');
  }
  const loaded = doc;
"""
s = s.replace(old, new, 1)
open(p, "w").write(s)
PY
      ;;
    no-symlink-check)
      # B3: drop the lstat-first refusal; the parse follows the link and the
      # rename replaces it (the pre-fix face).
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = """  const link = lstatOrNull(resolved);
  if (link !== null && link.isSymbolicLink()) throw fail('grant_file_symlink', resolved);

  // Seal presence needs the raw document"""
assert a in s, "symlink block not found"
s = s.replace(a, """  // MUTANT: no symlink refusal (the pre-fix face).
  // Seal presence needs the raw document""", 1)
open(p, "w").write(s)
PY
      ;;
    name-check-before-judge)
      # B4: answer grant_exists before the loader has judged the file, so a
      # broken file that already holds the name yields a success verdict.
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "  const loaded = loadGrantFile(resolved);\n  const existing = Object.getOwnPropertyNames(loaded.grants);\n  if (existing.includes(name)) throw fail('grant_exists', name);\n"
assert a in s, "judge+name block not found"
b = """  const loaded = loadGrantFile(resolved);
  const existing = Object.getOwnPropertyNames(loaded.grants);
"""
new = """  // MUTANT: name check before the judgement (the pre-fix order).
  if (Object.getOwnPropertyNames(doc.grants).includes(name)) throw fail('grant_exists', name);
  const loaded = loadGrantFile(resolved);
  const existing = Object.getOwnPropertyNames(loaded.grants);
  if (existing.includes(name)) throw fail('grant_exists', name);
"""
s = s.replace(a, new, 1)
open(p, "w").write(s)
PY
      ;;
    no-seal-check)
      # G3 guard: allow the rewrite to proceed over a sealed file.
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "  if (sealed) throw fail('grant_file_sealed', resolved);\n"
assert a in s, "seal check not found"
s = s.replace(a, "  // MUTANT: sealed file rewritten anyway.\n", 1)
open(p, "w").write(s)
PY
      ;;
    always-refuse)
      # Guards G1/G2: the fix must not break the documented bootstrap.
      python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = "  if (!fs.existsSync(resolved)) {\n    return writeGrantFile({ file: resolved, name, grant });\n  }\n"
assert a in s, "create path not found"
s = s.replace(a, a + "  throw fail('grant_file_invalid', 'MUTANT: always refuse');\n", 1)
open(p, "w").write(s)
PY
      ;;
    *)
      echo "unknown mutation: $1"
      return 1
      ;;
  esac
}

# CONTROL: the ladder must be green on the untouched tree.
control_fails=$(run_ladder)
if [ "${control_fails:-1}" != "0" ]; then
  echo "CONTROL FAILED: ladder is red before any mutation (fail=$control_fails)"
  exit 2
fi
echo "CONTROL: green"

expect_caught "parse-instead-of-load" parse-instead-of-load
expect_caught "no-symlink-check" no-symlink-check
expect_caught "name-check-before-judge" name-check-before-judge
expect_caught "no-seal-check" no-seal-check
expect_caught "always-refuse" always-refuse

restore
if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: at least one mutation escaped"
  exit 1
fi
echo "RESULT: all mutations caught, tree restored"
