#!/usr/bin/env bash
# MUTATION LADDER for the one-flag message bootstrap's cap
# (test/bootstrap-cap-lag.test.js).
#
# Each mutation removes ONE part of the fix and MUST turn the test red. A
# mutation that leaves it green means the test does not pin what it claims to
# pin. The tree is restored byte-identically at the end and the control runs
# green again.
#
# Usage: tools/mutation-ladder-bootstrap-cap-lag.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
TEST="test/bootstrap-cap-lag.test.js"
BACKUP="$(mktemp -d)"
trap 'rm -rf "$BACKUP"' EXIT

cp src/grantadd.js "$BACKUP/grantadd.js"
cp bin/signerd.js "$BACKUP/signerd.js"
restore() {
  cp "$BACKUP/grantadd.js" src/grantadd.js
  cp "$BACKUP/signerd.js" bin/signerd.js
}

run_test() { node --test "$TEST" 2>&1; }
verdict() { grep -qE 'ℹ fail 0' <<<"$1" && grep -qE 'ℹ pass [1-9]' <<<"$1"; }

OUT="$(run_test)"
if ! verdict "$OUT"; then
  echo "CONTROL is not green - the ladder measures nothing:"
  grep -E '✖|fail [1-9]' <<<"$OUT" | head -8
  exit 1
fi
echo "CONTROL green"

caught=0; total=0

mutate() {
  local name="$1"; shift
  total=$((total+1))
  restore
  "$@" || { echo "$name: MUTATION FAILED TO APPLY"; restore; exit 1; }
  OUT="$(run_test)"
  if verdict "$OUT"; then
    echo "$name: NOT CAUGHT (test still green)"
    restore; exit 1
  fi
  caught=$((caught+1))
  echo "$name: caught"
  restore
}

# M1: the original defect — the cap goes back to the hardcoded README value.
m1() {
  sed -i 's/maxBytes: bootstrapMaxBytes(bodyObj),/maxBytes: '"'"'700'"'"',/' bin/signerd.js
  grep -q "maxBytes: '700'," bin/signerd.js
}

# M2: the documented 700 floor is dropped (a small body loses its cap).
m2() {
  sed -i 's/Math.min(MAX_MESSAGE_BYTES, Math.max(700, canonical))/Math.min(MAX_MESSAGE_BYTES, canonical)/' src/grantadd.js
  grep -q 'Math.min(MAX_MESSAGE_BYTES, canonical)' src/grantadd.js
}

# M3: the envelope ceiling clamp is dropped (the bootstrap would widen it).
m3() {
  sed -i 's/Math.min(MAX_MESSAGE_BYTES, Math.max(700, canonical))/Math.max(700, canonical)/' src/grantadd.js
  grep -q 'Math.max(700, canonical)' src/grantadd.js
  ! grep -q 'Math.min(MAX_MESSAGE_BYTES' src/grantadd.js
}

# M4: the cap is computed from the wrong body — a stub, not the one given.
m4() {
  sed -i 's/maxBytes: bootstrapMaxBytes(bodyObj),/maxBytes: bootstrapMaxBytes({ schema: bodyObj.schema }),/' bin/signerd.js
  grep -q 'bootstrapMaxBytes({ schema: bodyObj.schema })' bin/signerd.js
}

# M5: the cap is derived from the wrong measure (the raw JSON text instead of
# the canonical bytes the daemon actually signs against).
m5() {
  sed -i 's/String(Math.min(MAX_MESSAGE_BYTES, Math.max(700, canonical)))/String(Math.min(MAX_MESSAGE_BYTES, Math.max(700, canonical - 400)))/' src/grantadd.js
  grep -q 'canonical - 400' src/grantadd.js
}

mutate M1 m1
mutate M2 m2
mutate M3 m3
mutate M4 m4
mutate M5 m5

if ! cmp -s src/grantadd.js "$BACKUP/grantadd.js" || ! cmp -s bin/signerd.js "$BACKUP/signerd.js"; then
  echo "TREE NOT RESTORED"; exit 1
fi
OUT="$(run_test)"
verdict "$OUT" || { echo "CONTROL after restore is not green"; exit 1; }
echo "LADDER: $caught/$total caught, control green after restore, tree byte-identical"
