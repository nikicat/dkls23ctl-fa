#!/usr/bin/env bash
# Run several dkls23ctl commands in parallel and collect their stdout.
#
# Usage: run_many.sh <timeout-seconds> <cmd1> <cmd2> ...
# Each <cmd> is a full shell command line. Prints "<index>: <stdout>" per
# command and exits non-zero if any command fails.
set -u

TIMEOUT="$1"; shift

declare -a PIDS OUTS
i=0
for cmd in "$@"; do
    out=$(mktemp)
    OUTS[$i]="$out"
    ( timeout "$TIMEOUT" bash -c "$cmd" >"$out" 2>"$out.err" ) &
    PIDS[$i]=$!
    i=$((i+1))
done

rc=0
for ((j=0; j<i; j++)); do
    if ! wait "${PIDS[$j]}"; then
        rc=1
        echo "command $j FAILED:" >&2
        sed 's/^/    /' "${OUTS[$j]}.err" | tail -5 >&2
    fi
    echo "$j: $(cat "${OUTS[$j]}")"
done
exit $rc
