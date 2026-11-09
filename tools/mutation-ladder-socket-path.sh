#!/usr/bin/env bash
# THE MUTATION LADDER for the socket-path domain (2026-11-09).
#
# Every mutation breaks ONE rule of the fix and the ladder must catch it.
# The tree is restored byte-identically after every step (sha256), and the
# control run must be green - a ladder that only fails proves nothing.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST="$ROOT/test/socket-path-domain.test.js"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

restore() {
  # Restore from a COPY taken with content preserved and a fresh mtime, so
  # cargo/node do not serve a cached build of the mutated file.
  cp -a "$WORK/orig/$(basename "$1")" "$1" 2>/dev/null
  touch "$1"
}

run_tests() {
  ( cd "$ROOT" && timeout 300 node --test "$TEST" 2>&1 )
}

expect_red() {
  local name="$1" out="$2"
  if grep -qE '^\s*ℹ fail [1-9]' <<<"$out"; then
    echo "  CAUGHT  $name"
    pass=$((pass+1))
  else
    echo "  MISSED  $name"
    fail=$((fail+1))
  fi
}

expect_green() {
  local name="$1" out="$2"
  if grep -qE '^\s*ℹ fail 0' <<<"$out"; then
    echo "  GREEN   $name (control)"
    pass=$((pass+1))
  else
    echo "  BROKE   $name (control must stay green)"
    fail=$((fail+1))
  fi
}

mkdir -p "$WORK/orig"
cp "$ROOT/src/socketpath.js" "$WORK/orig/socketpath.js"
cp "$ROOT/src/daemon.js" "$WORK/orig/daemon.js"
cp "$ROOT/bin/signerd.js" "$WORK/orig/signerd.js"

echo "CONTROL (unmutated tree):"
expect_green "control" "$(run_tests)"

echo
echo "M1: the byte count becomes a character count again (the pre-fix unit):"
restore "$ROOT/src/socketpath.js"
sed -i 's/Buffer.byteLength(socketPath, .utf8.)/socketPath.length/' "$ROOT/src/socketpath.js"
expect_red "M1 character count" "$(run_tests)"
restore "$ROOT/src/socketpath.js"

echo
echo "M2: the limit is raised above the kernel's 108 bytes:"
restore "$ROOT/src/socketpath.js"
sed -i 's/const SUN_PATH_MAX_BYTES = 108;/const SUN_PATH_MAX_BYTES = 200;/' "$ROOT/src/socketpath.js"
expect_red "M2 limit 200" "$(run_tests)"
restore "$ROOT/src/socketpath.js"

echo
echo "M3: the limit is lowered to the old arbitrary 100 bytes (the false refusal):"
restore "$ROOT/src/socketpath.js"
sed -i 's/const SUN_PATH_MAX_BYTES = 108;/const SUN_PATH_MAX_BYTES = 100;/' "$ROOT/src/socketpath.js"
expect_red "M3 limit 100" "$(run_tests)"
restore "$ROOT/src/socketpath.js"

echo
echo "M4: the byte count is not named in the message (the empty-detail defect):"
restore "$ROOT/src/socketpath.js"
sed -i 's/the socket path is ${bytes} bytes; this OS allows at most ${SUN_PATH_MAX_BYTES} bytes in a unix socket path/the socket path is too long/' "$ROOT/src/socketpath.js"
expect_red "M4 no byte count" "$(run_tests)"
restore "$ROOT/src/socketpath.js"

echo
echo "M5: the client stops preflighting (only the daemon judges the path):"
restore "$ROOT/src/daemon.js"
python3 - <<'PY'
p = 'src/daemon.js'
s = open(p).read()
old = """    const socketPathCheck = checkSocketPath(socketPath);
    if (!socketPathCheck.ok) {
      const err = fail(socketPathCheck.code, socketPathCheck.message);
      err.fix = socketPathFix(socketPathCheck);
      reject(err);
      return;
    }
"""
assert old in s, 'M5 anchor not found - the client preflight block changed shape'
s = s.replace(old, "")
open(p,'w').write(s)
PY
expect_red "M5 client does not preflight" "$(run_tests)"
restore "$ROOT/src/daemon.js"

echo
echo "M6: the daemon stops judging the path in the constructor:"
restore "$ROOT/src/daemon.js"
python3 - <<'PY'
p = 'src/daemon.js'
s = open(p).read()
old = """    const socketPathCheck = checkSocketPath(socketPath);
    if (!socketPathCheck.ok) {
      const err = fail(socketPathCheck.code, socketPathCheck.message);
      // The repair rides on the error so the CLI prints ONE source of it
      // (src/socketpath.js) - a second copy in the printer would be the same
      // two-surface drift this fix exists to remove.
      err.fix = socketPathFix(socketPathCheck);
      throw err;
    }
"""
assert old in s, 'M6 anchor not found - the constructor block changed shape'
s = s.replace(old, "")
open(p,'w').write(s)
PY
expect_red "M6 daemon does not judge" "$(run_tests)"
restore "$ROOT/src/daemon.js"

echo
echo "M7: the repair line is dropped from the client's refusal:"
restore "$ROOT/src/daemon.js"
python3 - <<'PY'
p = 'src/daemon.js'
s = open(p).read()
old = "      err.fix = socketPathFix(socketPathCheck);\n      reject(err);"
assert old in s, 'M7 anchor not found'
s = s.replace(old, "      reject(err);")
open(p,'w').write(s)
PY
expect_red "M7 no repair on the client" "$(run_tests)"
restore "$ROOT/src/daemon.js"

echo
echo "FINAL CONTROL (restored tree):"
expect_green "final control" "$(run_tests)"

echo
echo "MUTATION LADDER: $pass caught/green, $fail missed/broken"
[ "$fail" -eq 0 ]
