#!/usr/bin/env bash
# The mutation ladder for LEASE HELPER PREREQUISITE (2026-11-08).
#
# Breaks each property of the fix in a plausible way. The pinned test file
# (test/lease-prereq-surface.test.js) must catch every mutation, and the
# tree must be restored byte-identically afterwards.
#
# Mutations:
#   M1 drop the repair message from the no-compiler refusal
#   M2 revert to the doubled code (detailOf stops stripping the prefix)
#   M3 revert to the Node-internal "spawnSync cc ENOENT"
#   M4 drop the read-only install directory detection
#   M5 drop the CC knob mention in the fix line
#
# Usage: bash tools/mutation-ladder-lease-prereq.sh
set -u
cd "$(dirname "$0")/.."
TEST="test/lease-prereq-surface.test.js"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 300 node --test "$TEST" 2>&1 | grep -E "^. (pass|fail)" | tr '\n' ' '
}

fails_of() { printf '%s' "$1" | sed -n 's/.*fail \([0-9]*\).*/\1/p'; }

check() {
  local label="$1" expect="$2" file="$3" before="$4"
  local after out fails
  out=$(run_tests)
  fails=$(fails_of "$out")
  printf '  %-52s %s\n' "$label" "$out"
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
  local file="$1"
  cp "$file" "$SNAP/$(basename "$file")"
  python3 - || {
    echo "  !! mutation script failed"; FAIL=1
    cp "$SNAP/$(basename "$file")" "$file"
    return 1
  }
}

echo "Control run (unmodified tree):"
cp bin/signerd.js "$SNAP/signerd.js"; cp src/lease.js "$SNAP/lease.js"
check "control (unmodified)" "expect-green" "bin/signerd.js" "$(sha bin/signerd.js)"

echo "Mutation ladder:"

# M1: drop the repair message from the no-compiler refusal
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
assert 'fix: install a C compiler' in c, 'anchor missing'
open('bin/signerd.js', 'w').write(c.replace('fix: install a C compiler', 'no fix here'))
PY
check "M1 drop compiler repair line" "expect-red" "bin/signerd.js" "$BEFORE"

# M2: re-introduce the doubled code
BEFORE=$(sha src/lease.js)
mutate src/lease.js <<'PY'
c = open('src/lease.js').read()
assert 'return message.slice(code.length + 2);' in c, 'anchor missing'
open('src/lease.js', 'w').write(c.replace('return message.slice(code.length + 2);', 'return message;'))
PY
check "M2 doubled code survives" "expect-red" "src/lease.js" "$BEFORE"

# M3: revert to the Node-internal "spawnSync cc ENOENT"
BEFORE=$(sha src/lease.js)
mutate src/lease.js <<'PY'
c = open('src/lease.js').read()
old = 'the C compiler "${cc}" was not found'
assert old in c, 'anchor missing'
new = 'spawnSync ${cc} ENOENT'
open('src/lease.js', 'w').write(c.replace(old, new))
PY
check "M3 revert to spawnSync cc ENOENT" "expect-red" "src/lease.js" "$BEFORE"

# M4: drop the read-only install directory detection
BEFORE=$(sha src/lease.js)
mutate src/lease.js <<'PY'
c = open('src/lease.js').read()
old = 'if (/permission denied|cannot open output file|read-only file system/i.test(stderr))'
assert old in c, 'anchor missing'
open('src/lease.js', 'w').write(c.replace(old, 'if (false)'))
PY
check "M4 drop read-only dir detection" "expect-red" "src/lease.js" "$BEFORE"

# M5: drop the CC knob from the fix line
BEFORE=$(sha bin/signerd.js)
mutate bin/signerd.js <<'PY'
c = open('bin/signerd.js').read()
assert 'CC=/path/to/cc' in c, 'anchor missing'
open('bin/signerd.js', 'w').write(c.replace('CC=/path/to/cc', 'configure your system'))
PY
check "M5 drop CC knob from fix" "expect-red" "bin/signerd.js" "$BEFORE"

echo
if [ "$FAIL" = "0" ]; then
  echo "All 5 mutations caught. Tree restored byte-identically."
  exit 0
else
  echo "Mutation ladder FAILED."
  exit 1
fi
