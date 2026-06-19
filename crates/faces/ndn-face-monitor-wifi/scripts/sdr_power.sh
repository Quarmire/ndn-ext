#!/bin/bash
# Capture IQ from the USRP at a center freq and report the power statistics.
# Usage: sdr_power.sh <label> [freq_hz] [secs] [gain]
# Default freq 5805e6 (ch161), 2s, gain 60.
set -e
LABEL="${1:-cap}"
FREQ="${2:-5805e6}"
SECS="${3:-2}"
GAIN="${4:-60}"
RATE=10e6
RX="/opt/homebrew/Cellar/uhd/4.10.0.0_1/lib/uhd/examples/rx_samples_to_file"
OUT="/tmp/sdr_${LABEL}.dat"

"$RX" -f "$FREQ" -r "$RATE" --gain "$GAIN" --duration "$SECS" \
      --type float --file "$OUT" --args "" >/tmp/sdr_${LABEL}.log 2>&1 || { tail -5 /tmp/sdr_${LABEL}.log; exit 1; }

/usr/bin/python3 - "$OUT" "$LABEL" <<'PY'
import sys, numpy as np
data = np.fromfile(sys.argv[1], dtype=np.complex64)
if len(data) == 0:
    print("no samples"); sys.exit(1)
p = np.abs(data)**2
pdb = 10*np.log10(p + 1e-20)
# noise floor = 10th percentile; peak = 99.99th
floor = np.percentile(pdb, 10)
peak  = np.percentile(pdb, 99.99)
mean  = 10*np.log10(p.mean() + 1e-20)
# burst detection: fraction of samples > floor+10 dB
frac = float((pdb > floor + 10).mean())
print(f"[{sys.argv[2]}] n={len(data)} floor={floor:.1f} mean={mean:.1f} peak={peak:.1f} dBFS  burst_frac={frac*100:.3f}%")
PY
