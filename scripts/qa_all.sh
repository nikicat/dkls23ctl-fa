#!/usr/bin/env bash
# Full QA suite for dkls23ctl. Runs every supported scenario against the
# built CLI with real iroh/mDNS networking on localhost.
#
# Usage: scripts/qa_all.sh [path-to-binary]
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="${1:-$REPO/target/debug/dkls23ctl}"
RUN_MANY="$REPO/scripts/run_many.sh"
TIMEOUT=120

WORK=$(mktemp -d /tmp/dkls23ctl-qa.XXXXXX)
cd "$WORK"
echo "work dir: $WORK"

PASS=0
FAIL=0

check() { # check <name> <condition...>
    local name="$1"; shift
    if "$@"; then
        echo "PASS: $name"
        PASS=$((PASS+1))
    else
        echo "FAIL: $name"
        FAIL=$((FAIL+1))
    fi
}

same_nonempty() { # all args equal and non-empty
    local first="$1"
    [ -n "$first" ] || return 1
    for v in "$@"; do [ "$v" = "$first" ] || return 1; done
}

extract() { # extract <index> <run_many output>
    echo "$2" | sed -n "s/^$1: //p"
}

#############################################
echo "=== scenario 1: singleton keygen / sign / verify ==="
PK=$("$BIN" keygen -t1 --peer-id solo --key-id k-solo 2>/dev/null)
check "singleton keygen prints pubkey" test -n "$PK"
check "pubkey matches" test "$("$BIN" pubkey --key-id k-solo 2>/dev/null)" = "$PK"
SIG=$("$BIN" sign --key-id k-solo --peer-id solo --msg hello 2>/dev/null)
check "singleton sign" test -n "$SIG"
check "verify ok" test "$("$BIN" verify --key-id k-solo --msg hello --signature "$SIG" 2>/dev/null)" = "OK"
"$BIN" verify --key-id k-solo --msg other --signature "$SIG" >/dev/null 2>&1
check "verify rejects wrong msg" test $? -ne 0

#############################################
echo "=== scenario 2: 2-of-3 keygen, sign with 2, verify ==="
OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN keygen -t2 -n3 --peer-id p1 --key-id k23" \
    "$BIN keygen -t2 -n3 --peer-id p2 --key-id k23" \
    "$BIN keygen -t2 -n3 --peer-id p3 --key-id k23")
RC=$?
PK1=$(extract 0 "$OUT"); PK2=$(extract 1 "$OUT"); PK3=$(extract 2 "$OUT")
check "keygen 2of3 succeeds" test $RC -eq 0
check "all peers same pubkey" same_nonempty "$PK1" "$PK2" "$PK3"

OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN sign --key-id k23 --peer-id p1 --msg 'pay 42'" \
    "$BIN sign --key-id k23 --peer-id p3 --msg 'pay 42'")
RC=$?
S1=$(extract 0 "$OUT"); S2=$(extract 1 "$OUT")
check "sign with 2 of 3 succeeds" test $RC -eq 0
check "signers agree" same_nonempty "$S1" "$S2"
check "signature verifies" test "$("$BIN" verify --key-id k23 --msg 'pay 42' --signature "$S1" 2>/dev/null)" = "OK"

#############################################
echo "=== scenario 3: reshare 2-of-3 -> 3-of-4 (add a peer) ==="
OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN reshare --peer-id p1 --key-id k23 -t3 -n4" \
    "$BIN reshare --peer-id p2 --key-id k23 -t3 -n4" \
    "$BIN reshare --peer-id p3 --key-id k23 -t3 -n4" \
    "$BIN reshare --peer-id p4 --key-id k23 -t3 -n4")
RC=$?
R1=$(extract 0 "$OUT"); R4=$(extract 3 "$OUT")
check "reshare to 3of4 succeeds" test $RC -eq 0
check "pubkey unchanged" same_nonempty "$R1" "$R4" "$PK1"

OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN sign --key-id k23 --peer-id p2 --msg again" \
    "$BIN sign --key-id k23 --peer-id p3 --msg again" \
    "$BIN sign --key-id k23 --peer-id p4 --msg again")
RC=$?
S1=$(extract 0 "$OUT")
check "sign with new 3of4 quorum" test $RC -eq 0
check "new signature verifies" test "$("$BIN" verify --key-id k23 --msg again --signature "$S1" 2>/dev/null)" = "OK"

#############################################
echo "=== scenario 4: reshare singleton -> 2-of-2 (import) ==="
PKS=$("$BIN" keygen -t1 --peer-id imp1 --key-id k-imp 2>/dev/null)
OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN reshare --peer-id imp1 --key-id k-imp -t2 -n2" \
    "$BIN reshare --peer-id imp2 --key-id k-imp -t2 -n2")
RC=$?
I1=$(extract 0 "$OUT"); I2=$(extract 1 "$OUT")
check "import succeeds" test $RC -eq 0
check "pubkey preserved by import" same_nonempty "$I1" "$I2" "$PKS"

OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN sign --key-id k-imp --peer-id imp1 --msg imported" \
    "$BIN sign --key-id k-imp --peer-id imp2 --msg imported")
RC=$?
S1=$(extract 0 "$OUT")
check "sign with imported key" test $RC -eq 0
check "imported-key signature verifies" \
    test "$("$BIN" verify --key-id k-imp --msg imported --signature "$S1" 2>/dev/null)" = "OK"

#############################################
echo "=== scenario 5: reshare 2-of-2 -> singleton (export) ==="
OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN reshare --peer-id imp1 --key-id k-imp -t1 -n1" \
    "$BIN reshare --peer-id imp2 --key-id k-imp -t1 -n1")
RC=$?
E1=$(extract 0 "$OUT"); E2=$(extract 1 "$OUT")
check "export succeeds" test $RC -eq 0
check "pubkey preserved by export" same_nonempty "$E1" "$E2" "$PKS"
check "imp1 now holds singleton" test -f .secrets/k-imp/imp1.json
check "imp2 share deleted" bash -c '! test -f .secrets/k-imp/imp2.json'

SIG=$("$BIN" sign --key-id k-imp --peer-id imp1 --msg exported 2>/dev/null)
check "singleton sign after export" test -n "$SIG"
check "exported-key signature verifies" \
    test "$("$BIN" verify --key-id k-imp --msg exported --signature "$SIG" 2>/dev/null)" = "OK"

#############################################
echo "=== scenario 6: reshare 3-of-4 -> 2-of-2 (shrink quorum) ==="
OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN reshare --peer-id p1 --key-id k23 -t2 -n2" \
    "$BIN reshare --peer-id p2 --key-id k23 -t2 -n2" \
    "$BIN reshare --peer-id p3 --key-id k23 -t2 -n2")
RC=$?
Q1=$(extract 0 "$OUT")
check "shrink to 2of2 succeeds" test $RC -eq 0
check "pubkey unchanged after shrink" same_nonempty "$Q1" "$PK1"
check "p3 dropped from quorum" bash -c '! test -f .secrets/k23/p3.json'

OUT=$("$RUN_MANY" $TIMEOUT \
    "$BIN sign --key-id k23 --peer-id p1 --msg shrunk" \
    "$BIN sign --key-id k23 --peer-id p2 --msg shrunk")
RC=$?
S1=$(extract 0 "$OUT")
check "sign with shrunk quorum" test $RC -eq 0
check "shrunk-quorum signature verifies" \
    test "$("$BIN" verify --key-id k23 --msg shrunk --signature "$S1" 2>/dev/null)" = "OK"

#############################################
echo
echo "==========================================="
echo "QA result: $PASS passed, $FAIL failed"
echo "==========================================="
[ $FAIL -eq 0 ]
