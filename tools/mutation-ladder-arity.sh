#!/usr/bin/env bash
# The mutation ladder for the FLAG ARITY surface (2026-11-07).
#
# Each mutation breaks ONE property of the arity fix in a plausible way. The
# expectation is that the pinned test file catches every one of them and that
# the tree is restored BYTE-IDENTICALLY afterwards (sha256 before/after).
#
# The tree is restored from a byte-copy, not from git: the fix under test is
# not committed yet, and `git checkout --` would silently throw it away.
#
# Usage: bash tools/mutation-ladder-arity.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/flag-arity-surface.test.js}"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 300 node --test "$TEST" 2>&1 | grep -E "^ℹ (pass|fail)" | tr '\n' ' '
}

fails_of() { printf '%s' "$1" | sed -n 's/.*fail \([0-9]*\).*/\1/p'; }

# check <label> <expect-red|expect-green> <file> <pre-mutation-sha>
check() {
  local label="$1" expect="$2" file="$3" before="$4"
  local after out fails
  out=$(run_tests)
  fails=$(fails_of "$out")
  printf '  %-44s %s\n' "$label" "$out"
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

# mutate <file> <python-body-file>  -> echoes the pre-mutation sha
mutate() {
  local file="$1" script="$2"
  local before
  before=$(sha "$file")
  cp "$file" "$SNAP/$(basename "$file")"
  python3 "$script" || { echo "  !! mutation script failed"; FAIL=1; cp "$SNAP/$(basename "$file")" "$file"; return 1; }
  printf '%s' "$before"
}

# M1: duplicates are parsed but never reported - the map keeps the last value
#     exactly as before (the original defect, restored).
cat > "$SNAP/m1.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="    if (seen.has(key)) {\n      raw.push({ code: 'duplicate_flag', flag: key, first: seen.get(key), second: hasValue ? next : true });"
new="    if (seen.has(key)) {\n      // mutation: duplicates are not reported"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M2: a value-taking flag without a value is no longer an arity problem
#     (the seal-flag fail-open comes back).
cat > "$SNAP/m2.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="      if (switches.has(p.flag)) continue; // a switch without a value is right\n      out.push(p);"
new="      continue; // mutation: a value flag without a value is fine"
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M3: a switch given a value is no longer an arity problem (`--dry true`
#     becomes a real sign again).
cat > "$SNAP/m3.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="      if (!switches.has(p.flag)) continue; // not a switch: its value is right\n      out.push(p);"
new="      continue; // mutation: a switch given a value is fine"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M4: --dry is no longer declared a switch, so `--dry true` reads as a value
#     flag carrying its value (the refusal disappears from the other side).
cat > "$SNAP/m4.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="  sign: ['dry'],"
new="  sign: [],"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M5: the refusal is computed but never acted on (advisory, not a rule).
cat > "$SNAP/m5.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="  const arity = problems || [];\n  if (arity.length > 0) {"
new="  const arity = [] || problems || []; // mutation: never refuse\n  if (arity.length > 0) {"
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M6: the duplicate refusal no longer names the two values - the operator is
#     told WHICH flag but not WHICH files, which is the half-measure the
#     rule forbids ("name the repair, not just the verdict").
cat > "$SNAP/m6.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="        `  fix: give --${p.flag} once   # it was given twice: ` +\n        `${JSON.stringify(p.first)} and ${JSON.stringify(p.second)}\\n` +"
new="        `  fix: give --${p.flag} once\\n` +"
assert old in s, 'M6 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M7: the arity problems are resolved against the WRONG command's shape -
#     the switch set is dropped, so every flag reads as a value flag.
#
# The anchor moved in 3d71957 (the flag-surface fix: the switch set is now
# passed in, so the CLI's own SWITCH_FLAGS table is no longer read here).
# The property under test is unchanged: a switch without a value is right.
cat > "$SNAP/m7.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="  const switches = new Set(switchList || []);"
new="  const switches = new Set([]); // mutation: no flag is a switch"
assert old in s, 'M7 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: duplicates parsed but never reported (last wins, as before)"
B=$(mutate src/cli-flags.js "$SNAP/m1.py"); check "M1 duplicate not reported" expect-red src/cli-flags.js "$B"

echo "== M2: a value flag with no value is no longer refused"
B=$(mutate src/cli-flags.js "$SNAP/m2.py"); check "M2 value flag with no value" expect-red src/cli-flags.js "$B"

echo "== M3: a switch given a value is no longer refused"
B=$(mutate src/cli-flags.js "$SNAP/m3.py"); check "M3 switch given a value" expect-red src/cli-flags.js "$B"

echo "== M4: --dry is no longer declared a switch"
B=$(mutate src/cli-flags.js "$SNAP/m4.py"); check "M4 --dry not a switch" expect-red src/cli-flags.js "$B"

echo "== M5: the refusal is computed but never acted on"
B=$(mutate bin/signerd.js "$SNAP/m5.py"); check "M5 refusal advisory only" expect-red bin/signerd.js "$B"

echo "== M6: the duplicate refusal does not name the two values"
B=$(mutate bin/signerd.js "$SNAP/m6.py"); check "M6 duplicate reason unnamed" expect-red bin/signerd.js "$B"

echo "== M7: the switch set is dropped (every flag reads as a value flag)"
B=$(mutate src/cli-flags.js "$SNAP/m7.py"); check "M7 switch set dropped" expect-red src/cli-flags.js "$B"

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
