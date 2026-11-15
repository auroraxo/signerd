#!/bin/bash
# MUTATION LADDER for the seal-grants SUMMARY fix (2026-11-15).
#
# Every rung takes the FIXED tree and re-introduces exactly one defect from
# the pre-fix behaviour (or a new drift the fix's own contract forbids).
# A rung counts as CAUGHT only when the gate (test/seal-grants-summary.test.js)
# goes RED on the mutated tree AND the control (an UNTOUCHED copy of the fixed
# tree) stays green — otherwise a red result could be vacuous (broken fixture,
# not the mutation).
#
# Rules (house standard): each mutation must match EXACTLY ONE place (a
# vacuum guard), and the tree must be byte-identical to the fixed tree
# after restore. The fix lives in TWO files (bin/signerd.js and
# src/grantfile.js), so both are snapshotted.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GATE="test/seal-grants-summary.test.js"
WORK="$(mktemp -d /tmp/mutation-sealsummary.XXXXXX)"
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
  (cd "$REPO" && node --test "$GATE" >/tmp/mutation-ladder-gate.log 2>&1)
}

count_matches() { # $1=regex, $2=file
  grep -c -E "$1" "$2"
}

# --- rung driver -----------------------------------------------------------

CAUGHT=0
ESCAPED=0

run_rung() { # $1=mutation-id, $2=pattern, $3=file, $4=sed-expression
  local id="$1" pattern="$2" file="$3" expr="$4"
  local back="$WORK/back-$id"
  snapshot "$back"
  local n
  n="$(count_matches "$pattern" "$file")"
  if [ "$n" -ne 1 ]; then
    echo "VACUUM  $id: pattern matched $n places (expected 1) — mutation NOT applied"
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
# The untouched fixed tree must stay GREEN, or every red above is vacuous.

if runs_gate; then
  echo "CONTROL green (gate passes on the untouched fixed tree)"
else
  echo "CONTROL RED — the gate does not pass on the fixed tree; ladder is invalid"
  exit 1
fi

# --- rungs -----------------------------------------------------------------
# M1: the pre-fix summary — a hand-picked field subset for every grant.
run_rung "M1-handpicked-subset" \
  'grantSummary\(name, loaded\.grants\[name\]\)' \
  "$CLI" \
  's|const summary = loaded.names.map((name) => grantSummary(name, loaded.grants\[name\]));|const summary = loaded.names.map((name) => { const g = loaded.grants[name]; return { name, signer: g.signer, destination: g.destination, maxLamports: g.maxLamports, expiresAt: g.expiresAt }; });|'

# M2: message grants report name+expiresAt only (the pre-fix message face).
run_rung "M2-message-scope-dropped" \
  'const fields = isMessage \? MESSAGE_FIELDS : REQUIRED_FIELDS;' \
  "$GF" \
  's|const fields = isMessage ? MESSAGE_FIELDS : REQUIRED_FIELDS;|const fields = isMessage ? ["expiresAt"] : REQUIRED_FIELDS;|'

# M3: the window budget is dropped from every summary (the pre-fix tx face).
run_rung "M3-window-fields-dropped" \
  'for \(const field of fields\) \{' \
  "$GF" \
  's|for (const field of fields) {|for (const field of fields.filter((f) => !f.startsWith("window")))|'

# M4: the summary drifts from the sealed document (S3's own contract: the
# printed value must equal the file's value).
run_rung "M4-summary-drift" \
  'summary\[field\] = descriptor.value;' \
  "$GF" \
  's|summary\[field\] = descriptor.value;|summary\[field\] = "drifted";|'

# --- verdict ---------------------------------------------------------------
echo "----"
echo "caught=$CAUGHT escaped=$ESCAPED"
if [ "$ESCAPED" -ne 0 ]; then
  echo "LADDER FAILED: $ESCAPED mutation(s) escaped or were vacuous"
  exit 1
fi
if [ "$CAUGHT" -lt 4 ]; then
  echo "LADDER FAILED: only $CAUGHT caught (minimum 4)"
  exit 1
fi
echo "LADDER PASS: $CAUGHT/$CAUGHT caught, control green, tree byte-identical"
RESTORE_HASH="$(sha256sum "$CLI" "$GF" | sha256sum | awk '{print $1}')"
if [ "$RESTORE_HASH" = "$FIXED_HASH" ]; then
  echo "TREE BYTE-IDENTICAL after restore"
else
  echo "TREE DIRTY after restore ($RESTORE_HASH vs $FIXED_HASH)"
  exit 1
fi
