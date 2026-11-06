#!/usr/bin/env bash
# The mutation ladder for the dry-run surface (2026-11-06).
#
# Each mutation breaks ONE property of the fix in a plausible way. The
# expectation is that the pinned test file catches every one of them and that
# the tree is restored BYTE-IDENTICALLY afterwards (sha256 before/after).
#
# The tree is restored from a byte-copy, not from git: the fix under test is
# not committed yet, and `git checkout --` would silently throw it away.
#
# Usage: bash tools/mutation-ladder-dry.sh [test-file]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-test/dry-run-surface.test.js}"
FAIL=0
SNAP="$(mktemp -d)"
trap 'rm -rf "$SNAP"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

run_tests() {
  timeout 300 node --test "$TEST" 2>&1 | grep -E "^ℹ (pass|fail)" | tr '\n' ' '
}

fails_of() { printf '%s' "$1" | sed -n 's/.*fail \([0-9]*\).*/\1/p'; }

# check <label> <expect-red|expect-green> <file> <pre-mutation-sha>
check() {
  local label="$1" expect="$2" file="$3" before="$4"
  local after out fails
  out=$(run_tests)
  fails=$(fails_of "$out")
  printf '  %-44s %s\n' "$label" "$out"
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

# mutate <file> <python-body-file>  -> echoes the pre-mutation sha
mutate() {
  local file="$1" script="$2"
  local before
  before=$(sha "$file")
  cp "$file" "$SNAP/$(basename "$file")"
  python3 "$script" || { echo "  !! mutation script failed"; FAIL=1; cp "$SNAP/$(basename "$file")" "$file"; return 1; }
  printf '%s' "$before"
}

cat > "$SNAP/m1.py" <<'PY'
p='src/daemon.js'
s=open(p).read()
old="    if (parsed.dry === true) {\n      const preview = previewApproved({"
new="    if (false && parsed.dry === true) {\n      const preview = previewApproved({"
assert old in s, 'M1 anchor missing'
s=s.replace(old,new,1)
old2="      if (parsed.dry === true) {\n        const preview = previewMessageApproved({"
new2="      if (false && parsed.dry === true) {\n        const preview = previewMessageApproved({"
assert old2 in s, 'M1b anchor missing'
s=s.replace(old2,new2,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m2.py" <<'PY'
p='src/daemon.js'
s=open(p).read()
old="""  if (dryField !== undefined && (typeof dryField.value !== 'boolean')) {
    throw fail('request_invalid');
  }
  const dry = dryField !== undefined ? dryField.value : false;"""
new="""  const dry = dryField !== undefined ? Boolean(dryField.value) : false;"""
assert old in s, 'M2 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m3.py" <<'PY'
p='src/cli-flags.js'
s=open(p).read()
old="  sign: ['socket', 'grant', 'tx', 'out', 'dry'],"
new="  sign: ['socket', 'grant', 'tx', 'out'],"
assert old in s, 'M3 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m4.py" <<'PY'
p='bin/signerd.js'
s=open(p).read()
old="    if (response.ok && !response.dry && typeof args.out === 'string') {"
new="    if (response.ok && typeof args.out === 'string') {"
assert old in s, 'M4 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m5.py" <<'PY'
p='src/ledger.js'
s=open(p).read()
old="""  preview({ wire, amountLamports, grant, now = new Date() }) {
    const decision = this.#decideSpend({ wire, amountLamports, grant, now });
    if (decision.allowed !== true) return decision;"""
new="""  preview({ wire, amountLamports, grant, now = new Date() }) {
    const decision = this.#decideSpend({ wire, amountLamports, grant, now });
    if (decision.allowed !== true) return decision;
    this.approve({ wire, amountLamports, grant, now });"""
assert old in s, 'M5 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m6.py" <<'PY'
p='src/signer.js'
s=open(p).read()
old="  const verdict = previewGate(wire, grant, now, ledger);\n  if (!verdict.allowed) return verdict;"
new="  return { allowed: true, dry: true, amountLamports: '0', feeLamports: '0', totalLamports: '0', windowSpentLamports: '0', windowRemainingLamports: '0', budgetConsumed: false };"
assert old in s, 'M6 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

cat > "$SNAP/m7.py" <<'PY'
p='src/ledger.js'
s=open(p).read()
old="""  previewMessage({ messageBytes, grant, now = new Date() }) {
    const decision = this.#decideMessage({ messageBytes, grant, now });
    if (decision.allowed !== true) return decision;"""
new="""  previewMessage({ messageBytes, grant, now = new Date() }) {
    const decision = this.#decideMessage({ messageBytes, grant, now });
    if (decision.allowed !== true) return decision;
    this.approveMessage({ messageBytes, grant, now });"""
assert old in s, 'M7 anchor missing'
s=s.replace(old,new,1)
open(p,'w').write(s)
PY

echo "== control (the unmutated tree must be green)"
CONTROL=$(run_tests)
echo "  $CONTROL"
if [ "$(fails_of "$CONTROL")" != "0" ]; then echo "  !! control red"; FAIL=1; fi

echo
echo "== M1: the daemon ignores the dry flag (falls through to the real sign)"
B=$(mutate src/daemon.js "$SNAP/m1.py"); check "M1 daemon ignores dry" expect-red src/daemon.js "$B"

echo "== M2: the daemon accepts a non-boolean dry value (fail-open typing)"
B=$(mutate src/daemon.js "$SNAP/m2.py"); check "M2 permissive dry typing" expect-red src/daemon.js "$B"

echo "== M3: the CLI no longer knows --dry (flag surface regresses)"
B=$(mutate src/cli-flags.js "$SNAP/m3.py"); check "M3 --dry not in the flag surface" expect-red src/cli-flags.js "$B"

echo "== M4: the CLI writes --out even on a dry run"
B=$(mutate bin/signerd.js "$SNAP/m4.py"); check "M4 --out written on a dry run" expect-red bin/signerd.js "$B"

echo "== M5: the ledger preview journals anyway (preview = approve)"
B=$(mutate src/ledger.js "$SNAP/m5.py"); check "M5 preview journals the spend" expect-red src/ledger.js "$B"

echo "== M6: the dry path skips the policy decision (allowed without checking)"
B=$(mutate src/signer.js "$SNAP/m6.py"); check "M6 dry skips the policy decision" expect-red src/signer.js "$B"

echo "== M7: the message preview journals anyway"
B=$(mutate src/ledger.js "$SNAP/m7.py"); check "M7 message preview journals" expect-red src/ledger.js "$B"

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
