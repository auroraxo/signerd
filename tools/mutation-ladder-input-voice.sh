#!/usr/bin/env bash
# MUTATION LADDER for the operator-input refusal voice (src/input-file.js +
# the three CLI call sites in bin/signerd.js).
#
# Each mutation removes ONE part of the fix and MUST turn
# test/input-voice.test.js red. A mutation that leaves the suite green means
# the test does not pin what it claims to pin. The tree is restored
# byte-identically at the end and the control runs green again.
#
# Usage: tools/mutation-ladder-input-voice.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
TEST="test/input-voice.test.js"
BACKUP="$(mktemp -d)"
trap 'rm -rf "$BACKUP"' EXIT

cp bin/signerd.js "$BACKUP/signerd.js"
cp src/input-file.js "$BACKUP/input-file.js"

restore() { cp "$BACKUP/signerd.js" bin/signerd.js; cp "$BACKUP/input-file.js" src/input-file.js; }

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
    echo "$name: NOT CAUGHT (suite still green)"
    restore; exit 1
  fi
  caught=$((caught+1))
  echo "$name: caught"
  restore
}

REFUSE_CALL='passphraseReadRefusal(flag, file, { reason: classifyReadError(err), detail: err.code });'

# M1: the passphrase lstat stops classifying errors (throws the raw errno).
m1() {
  python3 - "$REFUSE_CALL" <<'PY'
import sys
needle = sys.argv[1]
src = open('bin/signerd.js').read()
assert src.count(needle) == 2, f"expected 2 call sites, found {src.count(needle)}"
src = src.replace(needle, 'throw err;', 1)
open('bin/signerd.js', 'w').write(src)
PY
}

# M2: the unreadable FINAL read loses its classification (mode 000 face).
m2() {
  python3 - "$REFUSE_CALL" <<'PY'
import sys
needle = sys.argv[1]
src = open('bin/signerd.js').read()
assert src.count(needle) == 2
idx = src.rindex(needle)
src = src[:idx] + 'throw err;' + src[idx + len(needle):]
open('bin/signerd.js', 'w').write(src)
PY
}

# M3: the tx probe stops reading THROUGH links (G4 guard must notice).
m3() {
  sed -i 's/const txProbe = readOperatorFile(txPath, { follow: true });/const txProbe = readOperatorFile(txPath);/' bin/signerd.js
  grep -q 'readOperatorFile(txPath);' bin/signerd.js
}

# M4: the tx refusal guard is disabled (the raw face returns).
m4() {
  sed -i 's/if (!txProbe.ok) {/if (false) {/' bin/signerd.js
  grep -q 'if (false) {' bin/signerd.js
}

# M5: the body probe bypasses classification (pre-fix readFileSync).
m5() {
  sed -i 's/const bodyProbe = readOperatorFile(bodyPath, { follow: true });/const bodyProbe = { ok: true, bytes: fs.readFileSync(bodyPath) };/' bin/signerd.js
  grep -q 'fs.readFileSync(bodyPath)' bin/signerd.js
}

# M6: the refusal stops naming the reason (generic message).
m6() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "`${code}: cannot read ${pathValue} (${probe.reason})\\n` +"
assert needle in src, 'refusal line not found'
src = src.replace(needle, "`cannot read ${pathValue}\\n` +", 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M7: the refusal loses the repair line (house rule: every refusal names a fix).
m7() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "    `  fix: ${fix}\\n`);"
assert needle in src, 'fix line not found'
src = src.replace(needle, "    `\\n`);", 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M8: the usage refusal exits 1 instead of 2 (breaks the exit-code contract).
m8() {
  python3 <<'PY'
src = open('bin/signerd.js').read()
needle = "  process.stderr.write(\n    `${code}: cannot read ${pathValue} (${probe.reason})\\n` +\n    `  fix: ${fix}\\n`);\n  process.exit(2);"
assert needle in src, "operatorFileRefusal body not found"
src = src.replace(needle, needle.replace("process.exit(2);", "process.exit(1);"), 1)
open('bin/signerd.js', 'w').write(src)
PY
}

mutate M1 m1
mutate M2 m2
mutate M3 m3
mutate M4 m4
mutate M5 m5
mutate M6 m6
mutate M7 m7
mutate M8 m8

if ! cmp -s bin/signerd.js "$BACKUP/signerd.js" || ! cmp -s src/input-file.js "$BACKUP/input-file.js"; then
  echo "TREE NOT RESTORED"; exit 1
fi
OUT="$(run_test)"
verdict "$OUT" || { echo "CONTROL after restore is not green"; exit 1; }
echo "LADDER: $caught/$total caught, control green after restore, tree byte-identical"
