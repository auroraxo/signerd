#!/usr/bin/env bash
# Mutation ladder for the canonical-base64 pubkey rule (11.11. PULS).
#
# Each mutation reverts ONE pillar of the fix in a copy of the tree; the
# pin test (test/pubkey-canonical.test.js) must FAIL on every mutation
# ("CAUGHT") and PASS on the untouched tree ("CONTROL"). Anchor + compile +
# vacuum gates: a mutation that does not compile, does not change the file,
# or escapes without failing counts as NOT caught.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTFILE="test/pubkey-canonical.test.js"
WORK="$(mktemp -d /tmp/pubkey-ladder-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
summary() { echo "LADDER: $pass caught, $fail escaped"; [ "$fail" -eq 0 ] || exit 1; }

# run_case NAME MUTATE_FN — copies the tree, applies the mutation, runs the
# pin test in the copy.
run_case() {
  local name="$1"
  local dir="$WORK/$name"
  mkdir -p "$WORK"
  cp -a "$ROOT" "$dir"
  # node_modules via symlink to keep the copy cheap but complete
  rm -rf "$dir/node_modules"; ln -s "$ROOT/node_modules" "$dir/node_modules"
  ( cd "$dir" && "$2" ) || { echo "$name: ANCHOR-FAIL (mutation did not apply)"; fail=$((fail+1)); return; }
  if ( cd "$dir" && node --test "$TESTFILE" ) >"$WORK/$name.out" 2>&1; then
    echo "$name: ESCAPED (pin test green on mutated tree) — VACUUM"; fail=$((fail+1))
  else
    # VACUUM GATE: a real catch is a parsed nonzero fail count. A compile
    # error, a missing anchor, or an unparseable run does NOT count.
    local fails
    fails=$(grep -oE 'ℹ fail [0-9]+' "$WORK/$name.out" | head -1 | awk '{print $3}')
    if [ -z "${fails:-}" ] || [ "$fails" -eq 0 ]; then
      echo "$name: ESCAPED (no nonzero parsed fail count) — VACUUM"; fail=$((fail+1))
    else
      echo "$name: CAUGHT ($fails failing)"; pass=$((pass+1))
    fi
  fi
}

# M1: the loader drops the round trip (shape only, like the pre-fix rule)
m1() {
  python3 - <<'EOF'
import re
p='src/grantfile.js'
s=open(p).read()
old="""    if (!isCanonicalBase64PublicKey(grant.pubkey)) {
      throw fail('grant_field_invalid', `${name}.pubkey`);
    }"""
new="""    if (!/^[A-Za-z0-9+\\/]{43}=$/.test(grant.pubkey) ||
        Buffer.from(grant.pubkey, 'base64').length !== 32) {
      throw fail('grant_field_invalid', `${name}.pubkey`);
    }"""
assert old in s, "anchor M1 missing"
open(p,'w').write(s.replace(old,new))
EOF
}

# M2: the creation path drops the round trip
m2() {
  python3 - <<'EOF'
p='src/grantadd.js'
s=open(p).read()
import re
old="""  if (!isCanonicalBase64PublicKey(args.pubkey)) {
    throw fail('grant_field_invalid', 'pubkey');
  }"""
new="""  if (typeof args.pubkey !== 'string' || !/^[A-Za-z0-9+\\/]{43}=$/.test(args.pubkey)) {
    throw fail('grant_field_invalid', 'pubkey');
  }"""
assert old in s, "anchor M2 missing"
open(p,'w').write(s.replace(old,new))
EOF
}

# M3: policy drops the round trip (shape regex only)
m3() {
  python3 - <<'EOF'
p='src/policy-message.js'
s=open(p).read()
old="      pubkey === null || !isCanonicalBase64PublicKey(pubkey) ||"
new="      pubkey === null || !/^[A-Za-z0-9+\\/]{43}=$/.test(pubkey) ||"
assert old in s, "anchor M3 missing"
open(p,'w').write(s.replace(old,new))
EOF
}

# M4: the round trip itself decodes without re-encoding (accepts every
# spelling the shape regex allows — a HALF-fix the ladder must catch)
m4() {
  python3 - <<'EOF'
p='src/grantvalues.js'
s=open(p).read()
old="  return decoded.toString('base64') === value;\n}"
new="  return true;\n}"
assert old in s, "anchor M4 missing"
open(p,'w').write(s.replace(old,new))
EOF
}

# M5: the grant_key_mismatch voice block is removed (a genuinely wrong key
# reverts to a bare refusal without repair — G2 must catch it)
m5() {
  python3 - <<'EOF'
p='bin/signerd.js'
s=open(p).read()
start=s.index("  // The daemon refused to start because a grant pins a public key this")
end=s.index("  // Name the repair, not just the verdict (same rule as the passphrase")
open(p,'w').write(s[:start]+s[end:])
EOF
}

# M6: the bootstrap encoding goes URL-safe (base64url — a spelling the
# loader's canonical rule must reject). Catches: D5, the bootstrap that the
# documented message quickstart runs.
m6() {
  python3 - <<'EOF'
p='bin/signerd.js'
s=open(p).read()
old="const pubkeyB64 = Buffer.from(bs58.decode(readKeystorePublicKey({ file: keystorePath }))).toString('base64');"
new="const pubkeyB64 = Buffer.from(bs58.decode(readKeystorePublicKey({ file: keystorePath }))).toString('base64url');"
assert old in s, "anchor M6 missing"
open(p,'w').write(s.replace(old,new))
EOF
}

run_case m1-loader-shape-only m1
run_case m2-create-shape-only m2
run_case m3-policy-shape-only m3
run_case m4-roundtrip-removed m4
run_case m5-fix-line-vanishes m5
run_case m6-shape-gate-removed m6

# CONTROL: untouched tree must be green
if node --test "$TESTFILE" >/dev/null 2>&1; then echo "CONTROL: green"; else echo "CONTROL: RED — pin test broken on the real tree"; fail=$((fail+1)); fi
summary
