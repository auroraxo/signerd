#!/usr/bin/env bash
# The mutation ladder for THE GRANT CAP DOMAIN (2026-11-09).
#
# Breaks each property of the fix in turn. The pinned test file
# (test/grant-cap-domain.test.js) must catch every mutation, and the
# tree must be restored byte-identically afterwards.
#
# Mutations:
#   M1 grantadd drops the 5000-lamport floor on windowMaxLamports (accepts 0 again)
#   M2 grantvalues accepts 0 message count again (dead cap on message grants)
#   M3 loader drops the 5000-lamport floor on windowMaxLamports (accepts 0 at load)
#   M4 bin/signerd.js drops the fix: line from the refusal voice
#   M5 ledger.js accepts 0 windowMaxLamports at runtime
#
# Usage: bash tools/mutation-ladder-grant-caps.sh
set -u
cd "$(dirname "$0")/.."
TEST="test/grant-cap-domain.test.js"
FAIL=0
SNAP="$(mktemp -d)"

restore() {
  for f in src/grantadd.js src/grantfile.js src/grantvalues.js src/ledger.js bin/signerd.js; do
    [ -f "$SNAP/$(basename "$f")" ] && cp "$SNAP/$(basename "$f")" "$f" 2>/dev/null || true
  done
  rm -rf "$SNAP"
}
trap 'restore' EXIT INT TERM

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
  printf '  %-56s %s\n' "$label" "$out"
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
for f in src/grantadd.js src/grantfile.js src/grantvalues.js src/ledger.js bin/signerd.js; do
  cp "$f" "$SNAP/"
done
B_ADD=$(sha src/grantadd.js)
B_FILE=$(sha src/grantfile.js)
B_VAL=$(sha src/grantvalues.js)
B_LED=$(sha src/ledger.js)
B_BIN=$(sha bin/signerd.js)
check "C0: unmodified tree is green" "expect-green" "src/grantadd.js" "$B_ADD"

echo "Mutation ladder:"

# M1: grantadd drops the 5000-lamport floor
mutate "src/grantadd.js" <<'PY'
p = 'src/grantadd.js'
s = open(p).read()
s = s.replace("!isWindowMaxLamports(args.windowMaxLamports)", "!isU64(args.windowMaxLamports)")
open(p, 'w').write(s)
PY
check "M1: grantadd drops 5000-lamport floor (accepts 0)" "expect-red" "src/grantadd.js" "$B_ADD"

# M2: grantvalues accepts 0 message count again
mutate "src/grantvalues.js" <<'PY'
p = 'src/grantvalues.js'
s = open(p).read()
s = s.replace("count > 0 && count <= MAX_SAFE", "count >= 0 && count <= MAX_SAFE")
open(p, 'w').write(s)
PY
check "M2: grantvalues accepts 0 message count again" "expect-red" "src/grantvalues.js" "$B_VAL"

# M3: loader drops the 5000-lamport floor
mutate "src/grantfile.js" <<'PY'
p = 'src/grantfile.js'
s = open(p).read()
s = s.replace("!isWindowMaxLamports(grant.windowMaxLamports)", "!isU64(grant.windowMaxLamports)")
open(p, 'w').write(s)
PY
check "M3: loader drops 5000-lamport floor (loads 0)" "expect-red" "src/grantfile.js" "$B_FILE"

# M4: drop the repair text from the refusal
mutate "bin/signerd.js" <<'PY'
p = 'bin/signerd.js'
s = open(p).read()
s = s.replace(
  "windowMaxLamports: 'an integer between 5000 (the base fee every approval costs) and 18446744073709551615 (the u64 window cap)',",
  "windowMaxLamports: 'an integer',"
)
open(p, 'w').write(s)
PY
check "M4: refusal printer drops 5000-lamport repair text" "expect-red" "bin/signerd.js" "$B_BIN"

# M5: loader accepts 0 messages
mutate "src/grantvalues.js" <<'PY'
p = 'src/grantvalues.js'
s = open(p).read()
s = s.replace("return n >= MIN_WINDOW_LAMPORTS && n <= MAX_U64;", "return n >= 0n && n <= MAX_U64;")
open(p, 'w').write(s)
PY
check "M5: isWindowMaxLamports accepts 0 lamports" "expect-red" "src/grantvalues.js" "$B_VAL"

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "ALL MUTATIONS CAUGHT: the test is a witness to every property of the fix."
  exit 0
else
  echo "MUTATION LADDER FAILED: at least one mutation survived or was not restored."
  exit 1
fi
