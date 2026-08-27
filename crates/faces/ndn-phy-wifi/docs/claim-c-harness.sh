#!/bin/bash
# claim-C v3 run: $1=arm $2=RESERVE $3=rep. Deaf-A. HYGIENE (each bug found the hard way):
#  - `pkill -x campaign_p5` (EXACT NAME, not -f): -f matches the harness's own shell cmdline and
#     self-kills the chain before it runs — the "identical stale results" bug.
#  - `sudo rm` the root-owned log (non-root can't delete it in sticky /tmp) so a no-run can't read stale.
#  - env BEFORE `timeout` (env after execs the env as a program).
A=minidronesys@141.225.165.246; C=minidronesys@141.225.163.122; B=minidronesys@141.225.165.128
COMMON="NDN_SCHED_SLOT=8:20000 NDN_SCHED_CLAIM=1 NDN_SCHED_LEASE=8 NDN_RADIO_TX_RATE=4 NDN_SCHED_CLOCK=cv NDN_SCHED_RESERVE=$2"
run() { local host="$1" env="$2" args="$3" secs="$4" log="$5"
  ssh "$host" "sudo pkill -9 -x campaign_p5 2>/dev/null; sudo rm -f $log; sleep 1; sudo bash -c '$env timeout $((secs+8)) /tmp/campaign_p5 $args > $log 2>&1'; sudo pkill -9 -x campaign_p5 2>/dev/null"
}
run "$B" "NDN_PID=881a $COMMON" "obs 149 50"  50 /tmp/o.log &
run "$C" "NDN_PID=8812 RATE=20 $COMMON" "lat 149 45" 45 /tmp/l.log &
sleep 8
CN=$(ssh $C "grep -o 'nonce=[0-9a-f]*' /tmp/l.log | head -1 | cut -d= -f2")
run "$A" "NDN_PID=a81a $COMMON NDN_SCHED_MASTER=1 NDN_SCHED_DEAF_SRC=$CN" "bulk 149 35" 35 /tmp/b.log
wait
echo "##### arm=$1 rep=$3 (RESERVE=$2) deaf-to=$CN"
echo -n "-- C: "; ssh $C "grep -E '^sent|nonce\\(end\\)' /tmp/l.log | tr '\n' ' '"; echo
echo -n "-- A: "; ssh $A "grep -E '^sent|elections' /tmp/b.log | tr '\n' ' '"; echo
echo "-- B:"; ssh $B "grep -E 'heard' /tmp/o.log"
