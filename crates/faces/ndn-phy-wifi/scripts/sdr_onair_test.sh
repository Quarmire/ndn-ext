#!/bin/bash
# Definitive on-air test: does the RTL8812EU emit RF at 5805 MHz when we inject?
# Captures USRP power (1) baseline with nothing transmitting, then (2) while the
# Realtek injects continuously for ~6s. A burst_frac / peak rise in (2) over (1)
# means the chip radiates (→ calibration/quality problem); no change means the
# analog TX path is dead or the MAC isn't keying TX.
#
# Prereq: USRP enumerated (uhd_usrp_probe works), dongle on the Mac.
set -e
cd "$(dirname "$0")/../../.."   # repo root
export PATH="/opt/homebrew/bin:$PATH"
SDR="crates/ndn-face-monitor-wifi/scripts/sdr_power.sh"

echo "### 1. BASELINE (nothing transmitting) ###"
"$SDR" baseline 5805e6 2 65

echo "### 2. capturing WHILE injecting (6s) ###"
# Start the SDR capture in the background, then drive a 6s injection burst.
( "$SDR" injecting 5805e6 6 65 ) &
SDR_PID=$!
sleep 1   # let the SDR settle/tune before frames start
cargo run -q --example usb_probe -p ndn-face-monitor-wifi --features libusb-backend -- --inject --secs 6 2>&1 | grep -E "bring-up|injected" || true
wait $SDR_PID

echo "### compare: a peak/burst_frac rise under (2) = the chip radiates ###"
