#!/bin/bash
# Capture IQ from the USRP and report the strongest spectral peaks (offset from
# the tuned center, in MHz) — distinguishes an RF LO tone (at DC/center) from a
# BB-modulated subcarrier (offset) or spread modulation.
# Usage: sdr_fft.sh <label> [freq_hz] [secs] [gain]
set -e
LABEL="${1:-fft}"; FREQ="${2:-5500e6}"; SECS="${3:-2}"; GAIN="${4:-50}"
RATE=10e6
RX="/opt/homebrew/Cellar/uhd/4.10.0.0_1/lib/uhd/examples/rx_samples_to_file"
OUT="/tmp/sdr_${LABEL}.dat"
"$RX" -f "$FREQ" -r "$RATE" --gain "$GAIN" --duration "$SECS" \
      --type float --file "$OUT" --args "" >/tmp/sdr_${LABEL}.log 2>&1 || { tail -5 /tmp/sdr_${LABEL}.log; exit 1; }
/usr/bin/python3 - "$OUT" "$LABEL" "$RATE" <<'PY'
import sys, numpy as np
d = np.fromfile(sys.argv[1], dtype=np.complex64)
rate = float(sys.argv[3])
n = 1<<16
d = d[:(len(d)//n)*n].reshape(-1, n)
# average power spectrum (FFT-shifted so center = DC = tuned freq)
psd = np.mean(np.abs(np.fft.fftshift(np.fft.fft(d*np.hanning(n), axis=1), axes=1))**2, axis=0)
psd_db = 10*np.log10(psd/psd.max() + 1e-20)
freqs = np.fft.fftshift(np.fft.fftfreq(n, 1/rate))/1e6  # MHz offset from center
floor = np.percentile(psd_db, 50)
# top peaks at least 6 dB above the median floor, thinned
idx = np.where(psd_db > floor + 6)[0]
peaks = []
for i in sorted(idx, key=lambda j: -psd_db[j]):
    if all(abs(freqs[i]-f) > 0.2 for f,_ in peaks):
        peaks.append((freqs[i], psd_db[i]))
    if len(peaks) >= 6: break
peaks.sort()
print(f"[{sys.argv[2]}] floor={floor:.1f} dB; peaks (MHz offset, dB):",
      ", ".join(f"{f:+.2f}@{p:.0f}" for f,p in peaks) or "none")
PY
