#!/usr/bin/env bash
# Mutation ladder for the socket-voice surface
# (test/socket-voice.test.js).
# Each mutation removes ONE face of the fix; the ladder must catch it
# (>= 1 failing case in the ladder file), and the CONTROL must leave the
# tree byte-identical. Vacuum gate: a run with 0 parsed failures is a
# HARNESS failure, not a pass. (File copies are the backup: `git stash push`
# on an already-clean file is a no-op and the pop then hits "No stash
# entries found".)
set -u
cd "$(dirname "$0")/.."

SRC=src/socketstatus.js
DAEMON=src/daemon.js
CLI=bin/signerd.js
FLAGS=src/cli-flags.js
LADDER=test/socket-voice.test.js

fail_count() {
  node --test "$LADDER" 2>&1 | grep -E '^ℹ fail' | grep -oE '[0-9]+'
}

mutate_and_run() {
  local name="$1"; shift
  local target="$1"; shift
  cp "$target" "$target.ladder-bak" || exit 3
  eval "$@" || { mv "$target.ladder-bak" "$target"; echo "MUTATION-FAILED $name (edit errored)"; exit 3; }
  if ! diff -q "$target" "$target.ladder-bak" >/dev/null; then
    local fails
    fails=$(fail_count)
    local parsed="yes"
    case "$fails" in
      ''|*[!0-9]*) fails="unparseable"; parsed="no" ;;
    esac
    mv "$target.ladder-bak" "$target"
    if [ "$parsed" != "yes" ]; then
      echo "VACUUM  $name (fail count unparseable)"
    elif [ "$fails" -ge 1 ]; then
      echo "CAUGHT  $name ($fails failing)"
    else
      echo "ESCAPED $name"
    fi
  else
    mv "$target.ladder-bak" "$target"
    echo "VACUUM  $name (mutation changed nothing)"
  fi
}

BEFORE_STATUS=$(git hash-object "$SRC")
BEFORE_DAEMON=$(git hash-object "$DAEMON")
BEFORE_CLI=$(git hash-object "$CLI")
BEFORE_FLAGS=$(git hash-object "$FLAGS")

echo "== control: unmutated tree must be green =="
ctrl=$(fail_count)
if [ "${ctrl:-x}" = "0" ]; then echo "CONTROL green (0 failing)"; else echo "CONTROL NOT GREEN (${ctrl:-unparseable}) - aborting"; exit 1; fi

mutate_and_run "M1 the socket refusal loses its named code (the raw errno is the answer again)" \
  "$SRC" "sed -i \"s/code: 'socket_missing',/code: 'ENOENT',/g\" $SRC"

mutate_and_run "M2 the stale state collapses into the missing one (dead and never-started read the same)" \
  "$SRC" "sed -i \"s/code: 'socket_stale',/code: 'socket_missing',/g\" $SRC"

mutate_and_run "M3 the refusal loses its repair (the operator sees a state and no action)" \
  "$SRC" "node -e \"
const fs=require('fs');let s=fs.readFileSync('$SRC','utf8');
const start=s.indexOf('function socketStateRefusal');
if (start===-1) process.exit(1);
const end=s.indexOf('function socketConnectRefusal', start);
if (end===-1) process.exit(1);
const block=s.slice(start,end);
const stripped=block.split('\\n').filter(function(l){return l.trim().indexOf('fix:')!==0;}).join('\\n');
s=s.slice(0,start)+stripped+s.slice(end);
fs.writeFileSync('$SRC',s);\""

mutate_and_run "M4 the repair names a command the CLI does not have (the unrunnable repair returns)" \
  "$SRC" "sed -i 's/signerd status --socket \${where}/signerd diagnose --socket \${where}/g' $SRC"

mutate_and_run "M5 the status command loses the --socket flag (the named repair cannot be run)" \
  "$FLAGS" "sed -i \"s/    'grants', 'ledger', 'socket', 'grant-seal-passphrase-file', 'journal-seal-passphrase-file',/    'grants', 'ledger', 'grant-seal-passphrase-file', 'journal-seal-passphrase-file',/\" $FLAGS"

mutate_and_run "M6 the unknown state is guessed as dead (the probe verdict is collapsed)" \
  "$SRC" "sed -i \"s/code: 'socket_state_unknown',/code: 'socket_stale',/\" $SRC"

mutate_and_run "M7 the transport refusal stops classifying (the errno reaches the operator)" \
  "$DAEMON" "sed -i \"s/const refusal = socketConnectRefusal(err, socketPath);/const refusal = { code: err.code || 'error', detail: err.message, fix: '' };/\" $DAEMON"

AFTER_STATUS=$(git hash-object "$SRC")
AFTER_DAEMON=$(git hash-object "$DAEMON")
AFTER_CLI=$(git hash-object "$CLI")
AFTER_FLAGS=$(git hash-object "$FLAGS")
if [ "$BEFORE_STATUS" = "$AFTER_STATUS" ] && [ "$BEFORE_DAEMON" = "$AFTER_DAEMON" ] \
  && [ "$BEFORE_CLI" = "$AFTER_CLI" ] && [ "$BEFORE_FLAGS" = "$AFTER_FLAGS" ]; then
  echo "TREE byte-identical after ladder"
else
  echo "TREE CHANGED - ladder left a mutation behind"
  git checkout -q -- "$SRC" "$DAEMON" "$CLI" "$FLAGS"
  exit 1
fi
