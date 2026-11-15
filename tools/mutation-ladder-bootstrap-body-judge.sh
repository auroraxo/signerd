#!/usr/bin/env bash
# MUTATION LADDER for the bootstrap BODY judge
# (test/bootstrap-body-judge.test.js).
#
# Each mutation removes ONE part of the fix and MUST turn the test red. A
# mutation that leaves it green means the test does not pin what it claims to
# pin. The tree is restored byte-identically at the end and the control runs
# green again.
#
# Usage: tools/mutation-ladder-bootstrap-body-judge.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
TEST="test/bootstrap-body-judge.test.js"
BACKUP="$(mktemp -d)"
trap 'rm -rf "$BACKUP"' EXIT

cp src/policy-message.js "$BACKUP/policy-message.js"
cp bin/signerd.js "$BACKUP/signerd.js"
restore() {
  cp "$BACKUP/policy-message.js" src/policy-message.js
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

# M1: the original defect - the judge call is dropped from the CLI entirely.
m1() {
  perl -0pi -e 's/      const verdict = judgeBootstrapBody\(bodyObj, messageGrant, new Date\(\)\);\n      if \(verdict\.allowed !== true\) \{/      if (false) {/' bin/signerd.js
  ! grep -q 'judgeBootstrapBody(bodyObj' bin/signerd.js
}

# M2: the judge reports but never refuses (the bootstrap keeps writing).
m2() {
  perl -0pi -e 's/if \(verdict\.allowed !== true\) \{/if (verdict.allowed !== true \&\& false) {/' bin/signerd.js
  grep -q 'verdict.allowed !== true && false' bin/signerd.js
}

# M3: a refusal is NOT a refusal - exit code 0 tells the caller it worked.
m3() {
  perl -0pi -e 's/        process\.exit\(2\);\n      \}\n      \/\/ Report on stderr/        process.exit(0);\n      }\n      \/\/ Report on stderr/' bin/signerd.js
  grep -q 'process.exit(0);' bin/signerd.js
}

# M4: the judge blesses everything (the defect the measurement names).
m4() {
  perl -0pi -e 's/  if \(verdict\.allowed === true\) return \{ allowed: true, messageBytes: bytes\.length \};\n  return \{ allowed: false, refused: verdict\.refused \};/  return { allowed: true, messageBytes: bytes.length };/' src/policy-message.js
  ! grep -q 'refused: verdict.refused' src/policy-message.js
}

# M5: the judge hides the envelope's own reason - the refusal names nothing
# the operator (or the ladder) can act on.
m5() {
  perl -0pi -e 's/const reason = verdict\.refused \|\| .envelope.;/const reason = "refused";/' bin/signerd.js
  grep -q 'const reason = "refused";' bin/signerd.js
}

# M6: the ceiling exception is dropped - a body beyond the envelope's ceiling
# (which still gets its scope by design) is refused, breaking the cap guard.
m6() {
  perl -0pi -e 's/  if \(bytes\.length > MAX_MESSAGE_BYTES\) \{\n    return \{ allowed: true, beyondEnvelopeCeiling: true, messageBytes: bytes\.length \};\n  \}\n//' src/policy-message.js
  ! grep -q 'beyondEnvelopeCeiling' src/policy-message.js
}

mutate M1 m1
mutate M2 m2
mutate M3 m3
mutate M4 m4
mutate M5 m5
mutate M6 m6

if ! cmp -s src/policy-message.js "$BACKUP/policy-message.js" || ! cmp -s bin/signerd.js "$BACKUP/signerd.js"; then
  echo "TREE NOT RESTORED"; exit 1
fi
OUT="$(run_test)"
verdict "$OUT" || { echo "CONTROL after restore is not green"; exit 1; }
echo "LADDER: $caught/$total caught, control green after restore, tree byte-identical"
