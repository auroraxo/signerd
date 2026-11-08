#!/usr/bin/env bash
# The mutation ladder for THE GRANT VALUE CONTRACT (2026-11-08).
#
# Breaks each property of the fix in turn. The pinned test file
# (test/grant-value-contract.test.js) must catch every mutation, and the
# tree must be restored byte-identically afterwards.
#
# Mutations:
#   M1 drop canonical-expiry validation from grantadd (accept Feb 31 again)
#   M2 drop canonical-key validation from grantadd (accept 43 ones again)
#   M3 drop u64 cap validation from grantadd (accept u64+1 again)
#   M4 drop the loader's expiry check (load accepts Feb 31 again)
#   M5 drop the fix: line from the grant-value refusal voice
#
# Usage: bash tools/mutation-ladder-grant-values.sh
set -u
cd "$(dirname "$0")/.."
TEST="test/grant-value-contract.test.js"
FAIL=0
SNAP="$(mktemp -d)"
# Restore every mutated file on ANY exit, including SIGINT/SIGTERM: a ladder
# killed halfway must not leave a mutation in the tree.
restore() {
  for f in src/grantadd.js src/grantfile.js bin/signerd.js; do
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
  printf '  %-54s %s\n' "$label" "$out"
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
cp src/grantadd.js "$SNAP/"
cp src/grantfile.js "$SNAP/"
cp bin/signerd.js "$SNAP/"
B_ADD=$(sha src/grantadd.js)
B_FILE=$(sha src/grantfile.js)
B_BIN=$(sha bin/signerd.js)
check "C0: unmodified tree is green" "expect-green" "src/grantadd.js" "$B_ADD"

echo "Mutation ladder:"

# M1: grantadd accepts calendar shape without canonical instant (the Feb 31 bug)
mutate "src/grantadd.js" <<'PY'
p = 'src/grantadd.js'
s = open(p).read()
s = s.replace(
  "!isCanonicalExpiry(args.expiresAt)",
  "!/^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(?:\\.\\d{1,3})?Z$/.test(args.expiresAt)"
)
open(p, 'w').write(s)
PY
check "M1: grantadd drops canonical expiry (accepts Feb 31)" "expect-red" "src/grantadd.js" "$B_ADD"

# M2: grantadd accepts base58 charset without 32-byte canonical key
mutate "src/grantadd.js" <<'PY'
p = 'src/grantadd.js'
s = open(p).read()
s = s.replace(
  "!isCanonicalPublicKey(args.destination)",
  "!/^[1-9A-HJ-NP-Za-km-z]+$/.test(args.destination)"
)
open(p, 'w').write(s)
PY
check "M2: grantadd drops canonical key check (accepts 43 ones)" "expect-red" "src/grantadd.js" "$B_ADD"

# M3: grantadd accepts arbitrary digits for maxLamports (overflow u64)
mutate "src/grantadd.js" <<'PY'
p = 'src/grantadd.js'
s = open(p).read()
s = s.replace(
  "!isU64(args.maxLamports)",
  "!/^(0|[1-9][0-9]*)$/.test(args.maxLamports)"
)
open(p, 'w').write(s)
PY
check "M3: grantadd drops u64 bound on maxLamports" "expect-red" "src/grantadd.js" "$B_ADD"

# M4: loader accepts non-canonical expiry
mutate "src/grantfile.js" <<'PY'
p = 'src/grantfile.js'
s = open(p).read()
s = s.replace(
  "!isCanonicalExpiry(grant.expiresAt)",
  "!/^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(?:\\.\\d{1,3})?Z$/.test(grant.expiresAt)"
)
open(p, 'w').write(s)
PY
check "M4: loader drops canonical expiry check" "expect-red" "src/grantfile.js" "$B_FILE"

# M5: drop the fix: line from the refusal printer
mutate "bin/signerd.js" <<'PY'
p = 'bin/signerd.js'
s = open(p).read()
s = s.replace(
  "`${err.code}: ${field}\\n` +\n      `  fix: set the field to ${fix}\\n`",
  "`${err.code}: ${field}\\n`"
)
open(p, 'w').write(s)
PY
check "M5: bin/signerd.js drops the fix: line from the refusal" "expect-red" "bin/signerd.js" "$B_BIN"

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "ALL MUTATIONS CAUGHT: the test is a witness to every property of the fix."
  exit 0
else
  echo "MUTATION LADDER FAILED: at least one mutation survived or was not restored."
  exit 1
fi
