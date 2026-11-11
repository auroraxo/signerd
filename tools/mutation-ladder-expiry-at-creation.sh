#!/usr/bin/env bash
# The mutation ladder for THE EXPIRY DOMAIN AT CREATION (2026-11-11).
#
# Breaks each property of the fix in turn. The pinned test file
# (test/expiry-at-creation.test.js) must catch every mutation, and the
# tree must be restored byte-identically afterwards.
#
# Mutations:
#   M1 isFutureExpiry returns true unconditionally (accepts past expiries again)
#   M2 isFutureExpiry uses >= instead of > (accepts an expiry equal to now)
#   M3 assertFreshGrant is removed from writeGrantFile (create path admits dead grants)
#   M4 assertFreshGrant is removed from extendGrantFile (--append admits dead grants)
#   M5 bin/signerd.js drops the grant_expired_at_creation branch (raw/generic voice)
#   M6 validateTxGrantArgs drops the isFutureExpiry check (library admits dead tx grants)
#
# Usage: bash tools/mutation-ladder-expiry-at-creation.sh
set -u
cd "$(dirname "$0")/.."
TEST="test/expiry-at-creation.test.js"
FAIL=0
SNAP="$(mktemp -d)"

restore() {
  for f in src/grantvalues.js src/grantadd.js bin/signerd.js; do
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
  printf '  %-60s %s\n' "$label" "$out"
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

echo "Control run (unmodified tree):"
for f in src/grantvalues.js src/grantadd.js bin/signerd.js; do
  cp "$f" "$SNAP/"
done
B_VAL=$(sha src/grantvalues.js)
B_ADD=$(sha src/grantadd.js)
B_BIN=$(sha bin/signerd.js)
check "C0: unmodified tree is green" "expect-green" "src/grantvalues.js" "$B_VAL"

echo "Mutation ladder:"

# M1: isFutureExpiry returns true unconditionally
python3 -c "
p = 'src/grantvalues.js'
s = open(p).read()
assert 'return expiry > now;' in s, 'M1 anchor missing'
open(p, 'w').write(s.replace('return expiry > now;', 'return true;'))
"
check "M1: isFutureExpiry unconditionally returns true" "expect-red" "src/grantvalues.js" "$B_VAL"

# M2: isFutureExpiry uses >= instead of > (now is admitted)
python3 -c "
p = 'src/grantvalues.js'
s = open(p).read()
assert 'return expiry > now;' in s, 'M2 anchor missing'
open(p, 'w').write(s.replace('return expiry > now;', 'return expiry >= now;'))
"
check "M2: isFutureExpiry uses >= instead of >" "expect-red" "src/grantvalues.js" "$B_VAL"

# M3: assertFreshGrant dropped from writeGrantFile
python3 -c "
p = 'src/grantadd.js'
s = open(p).read()
assert 'function writeGrantFile' in s and 'assertFreshGrant(grant);' in s, 'M3 anchor missing'
# Replace only the first occurrence after writeGrantFile
parts = s.split('function writeGrantFile')
sub = parts[1].replace('assertFreshGrant(grant);', '/* M3 */', 1)
open(p, 'w').write(parts[0] + 'function writeGrantFile' + sub)
"
check "M3: assertFreshGrant dropped from writeGrantFile" "expect-red" "src/grantadd.js" "$B_ADD"

# M4: assertFreshGrant dropped from extendGrantFile
python3 -c "
p = 'src/grantadd.js'
s = open(p).read()
assert 'function extendGrantFile' in s, 'M4 anchor missing'
parts = s.split('function extendGrantFile')
sub = parts[1].replace('assertFreshGrant(grant);', '/* M4 */', 1)
open(p, 'w').write(parts[0] + 'function extendGrantFile' + sub)
"
check "M4: assertFreshGrant dropped from extendGrantFile" "expect-red" "src/grantadd.js" "$B_ADD"

# M5: bin/signerd.js drops the grant_expired_at_creation branch
python3 -c "
p = 'bin/signerd.js'
s = open(p).read()
assert 'grant_expired_at_creation' in s, 'M5 anchor missing'
sub = s.replace(\"if (err && err.code === 'grant_expired_at_creation')\", \"if (false && err && err.code === 'grant_expired_at_creation')\")
open(p, 'w').write(sub)
"
check "M5: bin drops grant_expired_at_creation branch" "expect-red" "bin/signerd.js" "$B_BIN"

# M6: validateTxGrantArgs drops the isFutureExpiry check
python3 -c "
p = 'src/grantadd.js'
s = open(p).read()
assert \"!isFutureExpiry(args.expiresAt)\" in s, 'M6 anchor missing'
sub = s.replace(\"if (!isFutureExpiry(args.expiresAt)) throw fail('grant_expired_at_creation', args.expiresAt);\", '/* M6 */', 1)
open(p, 'w').write(sub)
"
check "M6: validateTxGrantArgs drops isFutureExpiry" "expect-red" "src/grantadd.js" "$B_ADD"

# M7: assertFreshGrant dropped from addGrantToFile (the bootstrap face)
python3 -c "
p = 'src/grantadd.js'
s = open(p).read()
assert 'function addGrantToFile' in s, 'M7 anchor missing'
parts = s.split('function addGrantToFile')
sub = parts[1].replace('assertFreshGrant(grant);', '/* M7 */', 1)
open(p, 'w').write(parts[0] + 'function addGrantToFile' + sub)
"
check "M7: assertFreshGrant dropped from addGrantToFile" "expect-red" "src/grantadd.js" "$B_ADD"

# M8: validateMessageGrantArgs drops the isFutureExpiry check
python3 -c "
p = 'src/grantadd.js'
s = open(p).read()
assert \"!isFutureExpiry(args.expiresAt)) throw fail('grant_expired_at_creation', args.expiresAt);\" in s, 'M8 anchor missing'
sub = s.replace(\"if (!isFutureExpiry(args.expiresAt)) throw fail('grant_expired_at_creation', args.expiresAt);\", '/* M8 */')
open(p, 'w').write(sub)
"
check "M8: validateMessageGrantArgs drops isFutureExpiry" "expect-red" "src/grantadd.js" "$B_ADD"

# M9: the CLI voice loses the value (the refusal stops naming the instant)
python3 -c "
p = 'bin/signerd.js'
s = open(p).read()
anchor = '\`\${err.code}: expiresAt \${value} is not in the future\\\n\`'
assert '\${err.code}: expiresAt \${value} is not in the future' in s, 'M9 anchor missing'
sub = s.replace('\${err.code}: expiresAt \${value} is not in the future', '\${err.code}: expiresAt is not in the future', 1)
open(p, 'w').write(sub)
"
check "M9: the CLI voice stops naming the value" "expect-red" "bin/signerd.js" "$B_BIN"

echo "Ladder complete, exit=$FAIL"
exit $FAIL
