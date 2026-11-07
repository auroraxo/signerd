#!/usr/bin/env bash
# The mutation ladder for OUTPUT PREFLIGHT (2026-11-07).
#
# Breaks each property of the fix in a plausible way. The pinned test file
# (test/out-preflight.test.js) must catch every mutation, and the tree must
# be restored byte-identically afterwards.
#
# Usage: bash tools/mutation-ladder-out-preflight.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/out-preflight.test.js}"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 300 node --test "$TEST" 2>&1 | grep -E "^ℹ (pass|fail)" | tr '\n' ' '
}

fails_of() { printf '%s' "$1" | sed -n 's/.*fail \([0-9]*\).*/\1/p'; }

check() {
  local label="$1" expect="$2" file="$3" before="$4"
  local after out fails
  out=$(run_tests)
  fails=$(fails_of "$out")
  printf '  %-48s %s\n' "$label" "$out"
  if [ "$expect" = "expect-red" ] && [ "${fails:-0}" = "0" ]; then
    echo "  !! MUTATION SURVIVED: $label"; FAIL=1
  fi
  if [ "$expect" = "expect-green" ] && [ "${fails:-0}" != "0" ]; then
    echo "  !! control is red: $label"; FAIL=1
  fi
  cp "$SNAP/$(basename "$file")" "$file"
  after=$(sha "$file")
  if [ "$after" != "$before" ]; then
    echo "  !! NOT restored byte-identically: $file"; FAIL=1
  fi
}

mutate() {
  local file="$1" script="$2"
  local before
  before=$(sha "$file")
  cp "$file" "$SNAP/$(basename "$file")"
  python3 "$script" || { echo "  !! mutation script failed"; FAIL=1; cp "$SNAP/$(basename "$file")" "$file"; return 1; }
  printf '%s' "$before"
}

# M1: preflight check is disabled in `signerd sign` (the original defect).
cat > "$SNAP/m1.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    requireWritableOut(args.out);"
new="    // requireWritableOut(args.out); // mutation: disabled in sign"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M2: preflight check is disabled in `signerd sign-message`.
cat > "$SNAP/m2.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    // Preflight BEFORE the socket round trip (P3): an unwritable --out must\n    // not sign, journal, or charge rolling-window budget.\n    requireWritableOut(args.out);"
new="    // mutation: disabled in sign-message"
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M3: preflight check is disabled in the example client.
cat > "$SNAP/m3.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="  if (typeof args.out === 'string') {\n    const check = checkOutWritable(args.out);"
new="  if (false && typeof args.out === 'string') { // mutation"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M4: directory check is dropped — an existing directory is not refused.
cat > "$SNAP/m4.py" <<'PY'
p='src/out-preflight.js'
s=open(p).read()
old="      if (stat.isDirectory()) {\n        return {\n          ok: false,\n          code: 'out_is_directory',\n          path: outPath,\n          message: `the output path ${outPath} is an existing directory`,\n        };\n      }"
new="      // mutation: directory check dropped"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M5: preflight check in `build-tx` is disabled.
cat > "$SNAP/m5.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="      requireWritableOut(args.out);"
new="      // requireWritableOut(args.out); // mutation: disabled in build-tx"
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M6: preflight check in `seal-grants` is disabled.
cat > "$SNAP/m6.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    requireWritableOut(out);"
new="    // requireWritableOut(out); // mutation: disabled in seal-grants"
assert old in s, 'M6 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: preflight disabled in sign (the original defect)"
B=$(mutate bin/signerd.js "$SNAP/m1.py"); check "M1 sign out-preflight disabled" expect-red bin/signerd.js "$B"

echo "== M2: preflight disabled in sign-message"
B=$(mutate bin/signerd.js "$SNAP/m2.py"); check "M2 sign-message out-preflight disabled" expect-red bin/signerd.js "$B"

echo "== M3: preflight disabled in example client"
B=$(mutate examples/user-zero-client.js "$SNAP/m3.py"); check "M3 client out-preflight disabled" expect-red examples/user-zero-client.js "$B"

echo "== M4: directory check dropped from preflight"
B=$(mutate src/out-preflight.js "$SNAP/m4.py"); check "M4 directory check dropped" expect-red src/out-preflight.js "$B"

echo "== M5: preflight disabled in build-tx"
B=$(mutate bin/signerd.js "$SNAP/m5.py"); check "M5 build-tx out-preflight disabled" expect-red bin/signerd.js "$B"

echo "== M6: preflight disabled in seal-grants"
B=$(mutate bin/signerd.js "$SNAP/m6.py"); check "M6 seal-grants out-preflight disabled" expect-red bin/signerd.js "$B"

echo
echo "== final control (the tree must be green again)"
FINAL=$(run_tests)
echo "  $FINAL"
if [ "$(fails_of "$FINAL")" != "0" ]; then echo "  !! final control red"; FAIL=1; fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "MUTATION LADDER PASS: every mutation was caught and the tree was restored byte-identically"
else
  echo "MUTATION LADDER FAIL"
fi
exit "$FAIL"
