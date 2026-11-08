#!/usr/bin/env bash
# The mutation ladder for the RECOVERY CHANNEL (2026-11-08).
#
# Breaks each property of the verified-recovery fix in a plausible way. The
# pinned test file (test/recovery-channel.test.js) must catch every mutation,
# and the tree must be restored byte-identically afterwards.
#
# The properties, and the plausible break of each:
#   M1 the synchronous verified write degrades back to the async write that
#      shipped in v0.2.9 (process.stdout.write + process.exit) -> CASE A:
#      exit 3 with 0 bytes on stdout
#   M2 the partial-write check dropped (a partial write counts as delivered)
#      -> CASE E: exit 3 with 1024 of 1402 bytes
#   M3 the retention check dropped (a channel that keeps nothing is trusted)
#      -> CASE D: exit 3 while /dev/null discards the artefact
#   M4 the failure reported as exit 3 anyway (the lie this fix exists to
#      remove) -> CASE A/B/D all claim recovery they do not have
#   M5 the `recovery_failed` statement silenced (the CLI goes quiet) ->
#      the operator is told nothing when a paid-for signature is lost
#   M6 the exit-3 path in sign-message left unverified (the fix applied to
#      only one of the two commands) -> the receipt document is lost silently
#
# Usage: bash tools/mutation-ladder-recovery-channel.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/recovery-channel.test.js}"
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

# M1: the verified synchronous write degrades back to the async write that
# shipped in v0.2.9 — the exact defect this fix removes.
cat > "$SNAP/m1.py" <<'PY'
p='src/stdout.js'
s=open(p).read()
old="function writeStdoutSync(text) {\n  return writeFdSync(1, text);\n}"
new="function writeStdoutSync(text) { // mutation: async write, unchecked (v0.2.9)\n  process.stdout.write(String(text));\n  return { ok: true, bytes: Buffer.byteLength(String(text)) };\n}"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M2: the partial-write check dropped — 1024 of 1402 bytes counts as a
# delivery, so a truncated artefact is presented as the artefact.
cat > "$SNAP/m2.py" <<'PY'
p='src/stdout.js'
s=open(p).read()
old="  if (lastError) {\n    return { ok: false, bytes: written, code: lastError.code, errno: lastError.code, message: lastError.message };\n  }\n  return { ok: true, bytes: written };"
new="  if (lastError && written === 0) { // mutation: a partial write counts as delivered\n    return { ok: false, bytes: written, code: lastError.code, errno: lastError.code, message: lastError.message };\n  }\n  return { ok: true, bytes: written };"
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M3: the retention check dropped — a channel that keeps nothing is trusted
# because the write itself succeeded.
cat > "$SNAP/m3.py" <<'PY'
p='src/stdout.js'
s=open(p).read()
old="  const discard = target === '/dev/null' || target === '/dev/zero';\n  return { retains: !discard, target, checked: true };"
new="  return { retains: true, target, checked: true }; // mutation: retention never checked"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M4: the failure reported as exit 3 anyway — the lie the fix exists to remove.
cat > "$SNAP/m4.py" <<'PY'
p='src/recovery.js'
s=open(p).read()
old="  return {\n    exitCode: EXIT_UNRECOVERABLE,\n    stderr: outLine + recoveryFailedText(put),\n    delivered: false,\n  };"
new="  return {\n    exitCode: 3, // mutation: claim recovery the channel never carried\n    stderr: outLine + recoveryFailedText(put),\n    delivered: false,\n  };"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M5: the recovery_failed statement silenced — the CLI says nothing when a
# paid-for signature is lost (the measured v0.2.9 behaviour: 0-byte stderr).
cat > "$SNAP/m5.py" <<'PY'
p='src/recovery.js'
s=open(p).read()
old="  return {\n    exitCode: EXIT_UNRECOVERABLE,\n    stderr: outLine + recoveryFailedText(put),\n    delivered: false,\n  };"
new="  return {\n    exitCode: EXIT_UNRECOVERABLE,\n    stderr: outLine, // mutation: recovery_failed silenced\n    delivered: false,\n  };"
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

# M6: the sign-message path left unverified — the fix applied to only one of
# the two commands that promise exit 3.
cat > "$SNAP/m6.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
anchor="        const recovery = deliverRecovery({\n          payload: JSON.stringify(response) + '\\n',\n          outPath: delivery.path,\n          outError: delivery,\n          subject: 'the receipt',\n          fixLine: outWriteFix(delivery),\n        });"
assert anchor in s, 'M6 anchor missing'
new="        process.stdout.write(JSON.stringify(response) + '\\n'); // mutation: receipt path unverified\n        process.exit(3);"
s=s.replace(anchor,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: the verified write degrades to the async write"
B=$(mutate src/stdout.js "$SNAP/m1.py"); check "M1 async unchecked write (v0.2.9 defect)" expect-red src/stdout.js "$B"

echo "== M2: the partial-write check dropped"
B=$(mutate src/stdout.js "$SNAP/m2.py"); check "M2 partial write counts as delivered" expect-red src/stdout.js "$B"

echo "== M3: the retention check dropped"
B=$(mutate src/stdout.js "$SNAP/m3.py"); check "M3 retention never checked" expect-red src/stdout.js "$B"

echo "== M4: the failure reported as exit 3 anyway"
B=$(mutate src/recovery.js "$SNAP/m4.py"); check "M4 failure claimed as exit 3" expect-red src/recovery.js "$B"

echo "== M5: the recovery_failed statement silenced"
B=$(mutate src/recovery.js "$SNAP/m5.py"); check "M5 recovery_failed silenced" expect-red src/recovery.js "$B"

echo "== M6: the sign-message path left unverified"
B=$(mutate bin/signerd.js "$SNAP/m6.py"); check "M6 receipt recovery unverified" expect-red bin/signerd.js "$B"

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
