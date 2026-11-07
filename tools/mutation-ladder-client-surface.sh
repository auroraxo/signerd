#!/usr/bin/env bash
# The mutation ladder for the USER-ZERO CLIENT'S FLAG SURFACE (2026-11-07).
#
# Each mutation breaks ONE property of the fix in a plausible way. The
# expectation is that the pinned test file catches every one of them and that
# the tree is restored BYTE-IDENTICALLY afterwards (sha256 before/after).
#
# The tree is restored from a byte-copy, not from git: the fix under test is
# not committed yet, and `git checkout --` would silently throw it away.
#
# Usage: bash tools/mutation-ladder-client-surface.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/user-zero-client-surface.test.js}"
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
  printf '  %-46s %s\n' "$label" "$out"
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

# M1: the client stops refusing an unknown flag (the original defect).
cat > "$SNAP/m1.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="  const surface = checkFlagsFor(CLIENT_FLAGS, args, args._);\n  if (!surface.ok) refuse(surface);"
new="  const surface = checkFlagsFor(CLIENT_FLAGS, args, args._);\n  // mutation: unknown flags are not refused"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M2: a flag given twice is no longer refused - last wins again, and the
#     operator never hears about it.
cat > "$SNAP/m2.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="  const problems = arityProblemsFor(CLIENT_FLAGS, CLIENT_SWITCH_FLAGS, raw);\n  if (problems.length > 0) refuse(problems[0]);"
new="  const problems = [];\n  // mutation: duplicates are not refused"
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M3: --dry is no longer forwarded to the daemon - the client asks for a
#     REAL signature while claiming to be a preview.
cat > "$SNAP/m3.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="    socketPath, grant, wire, dry: args.dry === true ? true : undefined,"
new="    socketPath, grant, wire, // mutation: --dry is not forwarded"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M4: the dry branch is removed from the output - the verdict is reported as
#     a normal success, and the client writes --out in a dry run.
cat > "$SNAP/m4.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="  if (response.ok && response.dry === true) {"
new="  if (false && response.ok && response.dry === true) { // mutation"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M5: a value flag given without a value is no longer refused (it reads as
#     absent, exactly like the pre-fix parser).
cat > "$SNAP/m5.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="    if (p.code === 'missing_value') {\n      if (switches.has(p.flag)) continue; // a switch without a value is right\n      out.push(p);\n      continue;\n    }"
new="    if (p.code === 'missing_value') {\n      continue; // mutation: a value flag without a value is fine\n    }"
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M6: the client's --dry is no longer declared a switch, so `--dry true`
#     reads as a value flag and the refusal disappears from the other side.
cat > "$SNAP/m6.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="const CLIENT_SWITCH_FLAGS = ['hold', 'dry'];"
new="const CLIENT_SWITCH_FLAGS = ['hold']; // mutation: --dry is not a switch"
assert old in s, 'M6 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M7: the duplicate refusal no longer names the two values - the operator is
#     told WHICH flag but not WHICH amounts, which is the half-measure the
#     rule forbids ("name the repair, not just the verdict").
cat > "$SNAP/m7.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="      `  fix: give --${problem.flag} once   # it was given twice: ` +\n      `${JSON.stringify(problem.first)} and ${JSON.stringify(problem.second)}\\n` +"
new="      `  fix: give --${problem.flag} once\\n` +"
assert old in s, 'M7 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M8: the switch list is dropped (every flag reads as a value flag), so
#     `--hold yes` and `--dry true` are accepted again.
cat > "$SNAP/m8.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="function arityProblemsFor(supportedList, switchList, raw) {"
new="function arityProblemsFor(supportedList, switchList, raw) {\n  switchList = []; // mutation: no flag is a switch"
assert old in s, 'M8 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: the client stops refusing an unknown flag"
B=$(mutate examples/user-zero-client.js "$SNAP/m1.py"); check "M1 unknown flag accepted" expect-red examples/user-zero-client.js "$B"

echo "== M2: a flag given twice is no longer refused"
B=$(mutate examples/user-zero-client.js "$SNAP/m2.py"); check "M2 duplicate flag accepted" expect-red examples/user-zero-client.js "$B"

echo "== M3: --dry is not forwarded to the daemon"
B=$(mutate examples/user-zero-client.js "$SNAP/m3.py"); check "M3 --dry not forwarded" expect-red examples/user-zero-client.js "$B"

echo "== M4: the dry branch is removed from the output"
B=$(mutate examples/user-zero-client.js "$SNAP/m4.py"); check "M4 dry branch removed" expect-red examples/user-zero-client.js "$B"

echo "== M5: a value flag with no value is no longer refused"
B=$(mutate src/cli-flags.js "$SNAP/m5.py"); check "M5 value flag with no value" expect-red src/cli-flags.js "$B"

echo "== M6: --dry is no longer declared a switch"
B=$(mutate src/cli-flags.js "$SNAP/m6.py"); check "M6 --dry not a switch" expect-red src/cli-flags.js "$B"

echo "== M7: the duplicate refusal does not name the two values"
B=$(mutate examples/user-zero-client.js "$SNAP/m7.py"); check "M7 duplicate reason unnamed" expect-red examples/user-zero-client.js "$B"

echo "== M8: the switch list is dropped"
B=$(mutate src/cli-flags.js "$SNAP/m8.py"); check "M8 switch list dropped" expect-red src/cli-flags.js "$B"

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
