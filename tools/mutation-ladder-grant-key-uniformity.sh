#!/bin/bash
# MUTATION LADDER for the ONE-KEY-PER-GRANT-FILE fix (2026-11-17).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour (or a drift the fix's own contract forbids).
# A rung counts as CAUGHT only when the gate (test/grant-key-uniformity.test.js)
# goes RED on the mutated tree AND the control (an UNTOUCHED copy of the fixed
# tree) stays green — otherwise a red result could be vacuous (broken fixture,
# not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the tree must be byte-identical to the fixed tree
# after restore. The fix lives in THREE files (bin/signerd.js,
# src/grantfile.js, src/grantadd.js), so all three are snapshotted.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/grant-key-uniformity.test.js"
WORK="$(mktemp -d /tmp/mutation-keyuniformity.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="$REPO/bin/signerd.js"
GF="$REPO/src/grantfile.js"
GA="$REPO/src/grantadd.js"
FIXED_HASH="$(sha256sum "$CLI" "$GF" "$GA" | sha256sum | awk '{print $1}')"

# --- helpers ---------------------------------------------------------------

snapshot() { # $1=dir: byte-copy of all three fixed files for restore
  cp "$CLI" "$1.signerd.js"
  cp "$GF" "$1.grantfile.js"
  cp "$GA" "$1.grantadd.js"
}

restore() { # $1=dir
  cp "$1.signerd.js" "$CLI"
  cp "$1.grantfile.js" "$GF"
  cp "$1.grantadd.js" "$GA"
}

runs_gate() { # -> exit 0 when the gate passes, 1 when it fails
  (cd "$REPO" && node --test "$GATE" >/tmp/mutation-ladder-keyuniformity.log 2>&1)
}

count_matches() { # $1=regex, $2=file
  grep -c -E "$1" "$2"
}

# --- rung driver -----------------------------------------------------------

CAUGHT=0
ESCAPED=0

run_rung() { # $1=mutation-id, $2=pattern, $3=file, $4=sed-expression, $5=expected-count (default 1)
  local id="$1" pattern="$2" file="$3" expr="$4" want="${5:-1}"
  local back="$WORK/back-$id"
  snapshot "$back"
  local n
  n="$(count_matches "$pattern" "$file")"
  if [ "$n" -ne "$want" ]; then
    echo "VACUUM  $id: pattern matched $n places (expected $want) — mutation NOT applied"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  sed -i "$expr" "$file"
  if cmp -s "$back.signerd.js" "$CLI" && cmp -s "$back.grantfile.js" "$GF" \
     && cmp -s "$back.grantadd.js" "$GA"; then
    echo "VACUUM  $id: sed changed nothing"
    restore "$back"
    ESCAPED=$((ESCAPED + 1))
    return
  fi
  if runs_gate; then
    echo "ESCAPED $id: gate still GREEN after the mutation"
    ESCAPED=$((ESCAPED + 1))
  else
    echo "CAUGHT  $id: gate RED on the mutated tree"
    CAUGHT=$((CAUGHT + 1))
  fi
  restore "$back"
}

# --- control ---------------------------------------------------------------
# The untouched fixed tree must stay GREEN, or every red above is vacuous.

if runs_gate; then
  echo "CONTROL green (gate passes on the untouched fixed tree)"
else
  echo "CONTROL RED — the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------

# M1: the pre-fix behaviour — the write path never checks the keys at all.
# Both call sites go, which is exactly what the tree looked like before the
# fix (zero checks): the count guard pins that it really is both, and only
# both.
run_rung "M1-no-uniformity-check" \
  'assertUniformGrantKeys\(grants\);' \
  "$GA" \
  's|assertUniformGrantKeys(grants);|/* removed */|' \
  2

# M2: the rule compares the SPELLING instead of the key — a marker of which
# encoding a key arrived in is baked into the bytes. The same key in base58
# (tx) and base64 (message) then reads as TWO keys: the over-tightening
# drift, and the K4 guard must catch it.
run_rung "M2-spelling-not-key" \
  'return raw\.length === 32 \? raw : null;' \
  "$GF" \
  's|return raw.length === 32 ? raw : null;|return raw.length === 32 ? Buffer.concat([Buffer.from("b64:"), raw]) : null;|'

# M3: the message grant's base64 spelling is read as the literal string bytes
# instead of the 32-byte key it decodes to — again a cross-encoding drift
# (the message grant would never match a tx grant's key). K4 must catch it.
run_rung "M3-message-key-read-wrong" \
  'return raw\.length === 32 \? raw : null;' \
  "$GF" \
  's|return raw.length === 32 ? raw : null;|return Buffer.from(String(descriptor.value));|'

# M4: the refusal is computed but never thrown, so the write path carries on
# and reports ok:true for a file the daemon refuses — the exact pre-fix
# shape, with a decoration on top. Both throws in the guard are neutered.
run_rung "M4-refusal-not-thrown" \
  'throw fail\('"'"'grant_file_key_mismatch'"'"',' \
  "$GF" \
  's|throw fail('"'"'grant_file_key_mismatch'"'"',|fail('"'"'grant_file_key_mismatch'"'"',|' \
  2

# M5: the CLI's repair line for the new refusal disappears — the refusal
# would still name itself but would name no repair.
run_rung "M5-repair-line-dropped" \
  "err\.code === 'grant_file_key_mismatch'" \
  "$CLI" \
  "s|err.code === 'grant_file_key_mismatch'|false \&\& err.code === 'grant_file_key_mismatch'|"

# M6: the removal path also enforces the rule — that would make an
# ALREADY-poisoned file unrepairable (the operator would be stuck). The K5
# guard must catch it.
run_rung "M6-removal-blocked" \
  'function removeGrantFromFile\(\{ file, name, sealPassphrase \}\) \{' \
  "$GA" \
  's|function removeGrantFromFile({ file, name, sealPassphrase }) {|function removeGrantFromFile({ file, name, sealPassphrase }) { if (true) throw fail('"'"'grant_file_key_mismatch'"'"', '"'"'blocked'"'"');|'

# --- verdict ---------------------------------------------------------------
echo "----"
echo "caught=$CAUGHT escaped=$ESCAPED"
if [ "$ESCAPED" -ne 0 ]; then
  echo "LADDER FAILED: $ESCAPED mutation(s) escaped or were vacuous"
  exit 1
fi
if [ "$CAUGHT" -lt 6 ]; then
  echo "LADDER FAILED: only $CAUGHT caught (minimum 6)"
  exit 1
fi
echo "LADDER PASS: $CAUGHT/$CAUGHT caught, control green, tree byte-identical"
RESTORE_HASH="$(sha256sum "$CLI" "$GF" "$GA" | sha256sum | awk '{print $1}')"
if [ "$RESTORE_HASH" = "$FIXED_HASH" ]; then
  echo "TREE BYTE-IDENTICAL after restore"
else
  echo "TREE DIRTY after restore ($RESTORE_HASH vs $FIXED_HASH)"
  exit 1
fi
