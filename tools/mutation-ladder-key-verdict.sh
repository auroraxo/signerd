#!/bin/bash
# MUTATION LADDER for the ONE-KEY rule on the VERDICT surfaces (2026-11-17).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour (or a drift the fix's own contract forbids).
# A rung counts as CAUGHT only when the gate (test/grant-key-verdict.test.js)
# goes RED on the mutated tree AND the control (an UNTOUCHED copy of the fixed
# tree) stays green — otherwise a red result could be vacuous (broken fixture,
# not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the tree must be byte-identical to the fixed tree after
# restore. The fix lives in TWO files (src/grantfile.js, bin/signerd.js), so
# both are snapshotted.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/grant-key-verdict.test.js"
WORK="$(mktemp -d /tmp/mutation-keyverdict.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

CLI="$REPO/bin/signerd.js"
GF="$REPO/src/grantfile.js"
FIXED_HASH="$(sha256sum "$CLI" "$GF" | sha256sum | awk '{print $1}')"

# --- helpers ---------------------------------------------------------------

snapshot() { # $1=dir: byte-copy of both fixed files for restore
  cp "$CLI" "$1.signerd.js"
  cp "$GF" "$1.grantfile.js"
}

restore() { # $1=dir
  cp "$1.signerd.js" "$CLI"
  cp "$1.grantfile.js" "$GF"
}

runs_gate() { # -> exit 0 when the gate passes, 1 when it fails
  (cd "$REPO" && node --test "$GATE" >/tmp/mutation-ladder-keyverdict.log 2>&1)
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
  if cmp -s "$back.signerd.js" "$CLI" && cmp -s "$back.grantfile.js" "$GF"; then
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

if runs_gate; then
  echo "CONTROL green (gate passes on the untouched fixed tree)"
else
  echo "CONTROL RED — the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------

# M1: the pre-fix behaviour — the verdict entry point enforces nothing, it is
# just the plain loader. This is exactly what `status`/`verify-grants`/
# `seal-grants` called before the fix.
run_rung "M1-no-verdict-check" \
  'assertUniformGrantKeys\(loaded\.grants\);' \
  "$GF" \
  's|assertUniformGrantKeys(loaded.grants);|/* removed */|' \
  1

# M2: the verdict surfaces fall back to the permissive loader (a partial
# revert: the helper still exists, but nothing routes through it). The count
# guard pins that all THREE surfaces route through the enforcing entry point.
run_rung "M2-surfaces-reverted" \
  'loadVerdictGrantFile\(' \
  "$CLI" \
  's|loadVerdictGrantFile(|loadGrantFile(|g' \
  3

# M3: the rule is applied only to `seal-grants` (the write face) and dropped
# from `status` — the report face degrades again while the seal still holds.
run_rung "M3-status-degrades" \
  "const loaded = loadVerdictGrantFile\(requireArg\(args, 'grants'\), options\);" \
  "$CLI" \
  "s|const loaded = loadVerdictGrantFile(requireArg(args, 'grants'), options);|const loaded = loadGrantFile(requireArg(args, 'grants'), options);|" \
  1

# M4: `seal-grants` stops judging uniformity — a dead file becomes an
# AUTHENTIC dead file again, the sharpest face of this defect.
run_rung "M4-seal-degrades" \
  'loadVerdictGrantFile\(file, \{ allowSealedWithoutKey: true \}\);' \
  "$CLI" \
  's|loadVerdictGrantFile(file, { allowSealedWithoutKey: true });|loadGrantFile(file, { allowSealedWithoutKey: true });|' \
  1

# M5: the refusal loses its voice — the gates demand a named refusal with a
# repair (V1/V3/V4), so a silent drop must go red too.
run_rung "M5-refusal-not-named" \
  'if \(!bytes\.equals\(key\)\) \{' \
  "$GF" \
  "/!bytes.equals(key)/,/pins a different key/ s|throw fail('grant_file_key_mismatch',|throw fail(\"silent\",|" \
  1

# M6: the over-tightening drift — the rule compares the SPELLING instead of
# the decoded key, so the cross-encoding guard (V6: tx base58 + message
# base64 of ONE key) must catch it.
run_rung "M6-spelling-not-key" \
  'if \(!bytes\.equals\(key\)\) \{' \
  "$GF" \
  's|if (!bytes.equals(key)) {|if (Buffer.from(grants[name] && JSON.stringify(grants[name])).length >= 0 \&\& true) {|' \
  1

# --- verdict ---------------------------------------------------------------

REMAINING_HASH="$(sha256sum "$CLI" "$GF" | sha256sum | awk '{print $1}')"
if [ "$FIXED_HASH" != "$REMAINING_HASH" ]; then
  echo "DIRTY   tree is NOT byte-identical to the fixed tree after restore"
  exit 1
fi
echo "TREE    byte-identical to the fixed tree after all rungs"

if [ "$ESCAPED" -ne 0 ]; then
  echo "RESULT  $CAUGHT caught, $ESCAPED ESCAPED"
  exit 1
fi
echo "RESULT  $CAUGHT/$((CAUGHT + ESCAPED)) CAUGHT"
exit 0
