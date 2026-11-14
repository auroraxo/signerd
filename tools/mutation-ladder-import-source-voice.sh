#!/usr/bin/env bash
# MUTATION LADDER for the `import --from` source voice.
#
# Each mutation removes ONE part of the fix and MUST turn
# test/import-source-voice.test.js red. A mutation that leaves the suite
# green means the test does not pin what it claims to pin. The tree is
# restored byte-identically at the end and the control runs green again.
#
# Usage: tools/mutation-ladder-import-source-voice.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
TEST="test/import-source-voice.test.js"
BACKUP="$(mktemp -d)"
trap 'rm -rf "$BACKUP"' EXIT

cp bin/signerd.js "$BACKUP/signerd.js"
restore() { cp "$BACKUP/signerd.js" bin/signerd.js; }

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

# M1: the source probe is removed entirely (the library's errno escapes).
m1() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
start = src.index('    const sourceProbe = readOperatorFile(from, { follow: true });')
end = src.index('    // The preflight read the plaintext key into memory', start)
src = src[:start] + src[end:]
src = src.replace('    sourceProbe.bytes.fill(0);\n', '', 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M2: the probe stops reading THROUGH links (the guard must notice).
m2() {
  sed -i 's/const sourceProbe = readOperatorFile(from, { follow: true });/const sourceProbe = readOperatorFile(from);/' bin/signerd.js
  grep -q 'readOperatorFile(from);' bin/signerd.js
}

# M3: the refusal guard is disabled (the raw face returns).
m3() {
  sed -i 's/    if (!sourceProbe.ok) {/    if (false) {/' bin/signerd.js
  grep -q 'if (false) {' bin/signerd.js
}

# M4: the refusal stops naming the reason (generic message).
m4() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "`${code}: cannot read ${pathValue} (${probe.reason})\\n` +"
assert needle in src, 'refusal line not found'
src = src.replace(needle, "`cannot read ${pathValue}\\n` +", 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M5: the refusal loses the repair line (house rule: every refusal names a fix).
m5() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "    `  fix: ${fix}\\n`);"
assert needle in src, 'fix line not found'
src = src.replace(needle, "    `\\n`);", 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M6: the usage refusal exits 1 instead of 2 (breaks the exit-code contract).
m6() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "  process.stderr.write(\n    `${code}: cannot read ${pathValue} (${probe.reason})\\n` +\n    `  fix: ${fix}\\n`);\n  process.exit(2);"
assert needle in src, 'operatorFileRefusal body not found'
src = src.replace(needle, needle.replace('process.exit(2);', 'process.exit(1);'), 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

# M7: the face name loses its reason suffix (the face must name ITSELF).
m7() {
  python3 <<'PYEOF'
src = open('bin/signerd.js').read()
needle = "        `import_source_${sourceProbe.reason}`, from, sourceProbe,"
assert needle in src, 'import source refusal call not found'
src = src.replace(needle, "        'import_source_unreadable', from, sourceProbe,", 1)
open('bin/signerd.js', 'w').write(src)
PYEOF
}

mutate M1 m1
mutate M2 m2
mutate M3 m3
mutate M4 m4
mutate M5 m5
mutate M6 m6
mutate M7 m7

if ! cmp -s bin/signerd.js "$BACKUP/signerd.js"; then
  echo "TREE NOT RESTORED"; exit 1
fi
OUT="$(run_test)"
verdict "$OUT" || { echo "CONTROL after restore is not green"; exit 1; }
echo "LADDER: $caught/$total caught, control green after restore, tree byte-identical"
