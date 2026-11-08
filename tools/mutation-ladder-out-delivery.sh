#!/usr/bin/env bash
# The mutation ladder for OUTPUT DELIVERY (2026-11-07).
#
# Breaks each property of the delivery fix in a plausible way. The pinned test
# file (test/out-delivery.test.js) must catch every mutation, and the tree must
# be restored byte-identically afterwards.
#
# The properties, and the plausible break of each:
#   M1 symlink resolution disabled -> a dangling symlink signs then loses it
#   M2 the non-regular-file check dropped -> a FIFO signs then blocks forever
#   M3 preflight disabled in `sign` -> the original v0.2.5 defect returns
#   M4 delivery degrades to plain writeFileSync -> O_TRUNC destroys the prior
#      file and the mode sticks to the old one
#   M5 the write failure path swallowed (exit 0) -> the signature is reported
#      as delivered when it was not
#   M6 the signed wire stripped from stdout on failure -> paid for, gone
#   M7 preflight disabled in the example client -> user-zero path loses it
#   M8 preflight disabled in sign-message -> the receipt is lost
#
# Usage: bash tools/mutation-ladder-out-delivery.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/out-delivery.test.js}"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 600 node --test "$TEST" 2>&1 | grep -E "^ℹ (pass|fail)" | tr '\n' ' '
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
  local file="$1" script="$2"
  local before
  before=$(sha "$file")
  cp "$file" "$SNAP/$(basename "$file")"
  python3 "$script" || { echo "  !! mutation script failed"; FAIL=1; cp "$SNAP/$(basename "$file")" "$file"; return 1; }
  printf '%s' "$before"
}

# M1: symlink resolution disabled — the original "check the path you were
# given, write the path the link points at" defect returns.
cat > "$SNAP/m1.py" <<'PY'
p='src/out-preflight.js'
s=open(p).read()
old="    if (!stat.isSymbolicLink()) {"
new="    if (true) { // mutation: never follow, never notice symlinks"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M2: the non-regular-file check dropped — a FIFO becomes an acceptable
# --out, so the daemon is paid and then the open blocks forever.
cat > "$SNAP/m2.py" <<'PY'
p='src/out-preflight.js'
s=open(p).read()
old="    if (!stat.isFile()) {"
new="    if (false && !stat.isFile()) { // mutation: non-regular targets allowed"
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M3: preflight disabled in `sign` (the v0.2.5 defect).
cat > "$SNAP/m3.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    requireWritableOut(args.out);\n    let wire;"
new="    // requireWritableOut(args.out); // mutation\n    let wire;"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M4: delivery degrades to a plain writeFileSync — O_TRUNC destroys a
# pre-existing file when the write then fails, and the old mode sticks.
cat > "$SNAP/m4.py" <<'PY'
p='src/out-preflight.js'
s=open(p).read()
old="    fs.renameSync(tmp, target);"
new="    fs.unlinkSync(tmp); fs.writeFileSync(target, bytes, { mode: 0o644 }); // mutation: non-atomic, O_TRUNC, loose mode"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M5: a delivery failure is reported as success (exit 0) — the operator is
# told the file was written when it was not.
#
# The anchor moved with the verified-recovery fix (2026-11-08): the exit-3
# path now asks src/recovery.js for the exit code, so the mutation has to
# break THAT decision — the recovery reported as a success. The property
# under test is unchanged: a delivery failure must never be reported as a
# delivered signature.
cat > "$SNAP/m5.py" <<'PY'
p='src/recovery.js'
s=open(p).read()
old="      exitCode: 3,\n      stderr: outLine + `${fixLine}\\n`,"
new="      exitCode: 0, // mutation: failure reported as success\n      stderr: outLine + `${fixLine}\\n`,"
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M6: the signed wire stripped from stdout on failure — paid for, gone.
cat > "$SNAP/m6.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="      const signed = Buffer.from(response.signed, 'base64');\n      const delivery = writeOutAtomic(args.out, signed);"
new="      const signed = Buffer.from(response.signed, 'base64');\n      delete response.signed; // mutation: strip the artifact before any failure path\n      const delivery = writeOutAtomic(args.out, signed);"
assert old in s, 'M6 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M7: preflight disabled in the example client (user-zero path).
cat > "$SNAP/m7.py" <<'PY'
p='examples/user-zero-client.js'
s=open(p).read()
old="  if (typeof args.out === 'string') {\n    const check = checkOutWritable(args.out);"
new="  if (false && typeof args.out === 'string') { // mutation\n    const check = checkOutWritable(args.out);"
assert old in s, 'M7 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M8: preflight disabled in sign-message (the receipt path).
cat > "$SNAP/m8.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    // Preflight BEFORE the socket round trip (P3): an unwritable --out must\n    // not sign, journal, or charge rolling-window budget.\n    requireWritableOut(args.out);"
new="    // mutation: preflight disabled in sign-message"
assert old in s, 'M8 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: symlink resolution disabled"
B=$(mutate src/out-preflight.js "$SNAP/m1.py"); check "M1 symlink resolution disabled" expect-red src/out-preflight.js "$B"

echo "== M2: non-regular-file check dropped"
B=$(mutate src/out-preflight.js "$SNAP/m2.py"); check "M2 non-regular-file check dropped" expect-red src/out-preflight.js "$B"

echo "== M3: preflight disabled in sign"
B=$(mutate bin/signerd.js "$SNAP/m3.py"); check "M3 preflight disabled in sign" expect-red bin/signerd.js "$B"

echo "== M4: delivery degraded to a plain (truncating) write"
B=$(mutate src/out-preflight.js "$SNAP/m4.py"); check "M4 non-atomic truncating write" expect-red src/out-preflight.js "$B"

echo "== M5: delivery failure reported as success"
B=$(mutate src/recovery.js "$SNAP/m5.py"); check "M5 failure reported as exit 0" expect-red src/recovery.js "$B"

echo "== M6: signed wire stripped from stdout on failure"
B=$(mutate bin/signerd.js "$SNAP/m6.py"); check "M6 signature stripped on failure" expect-red bin/signerd.js "$B"

echo "== M7: preflight disabled in the example client"
B=$(mutate examples/user-zero-client.js "$SNAP/m7.py"); check "M7 client preflight disabled" expect-red examples/user-zero-client.js "$B"

echo "== M8: preflight disabled in sign-message"
B=$(mutate bin/signerd.js "$SNAP/m8.py"); check "M8 sign-message preflight disabled" expect-red bin/signerd.js "$B"

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
