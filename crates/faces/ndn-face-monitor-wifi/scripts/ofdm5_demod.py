#!/usr/bin/env python3
"""Offline 802.11a/g OFDM demodulator for the 5 MHz down-clocked signal — a tool
to CONFIRM whether the userspace driver's 5 MHz TX is decodable (Phase 1: front-end
through equalized constellation + pilot EVM). The 5 MHz down-clock keeps the standard
sample COUNTS (160-sample L-STF, 64-FFT, 16-CP), so a standard 802.11a front-end
applies once the capture is resampled to exactly 5 MHz.

If the equalized pilots / data subcarriers form tight clusters (low EVM), the TX is a
valid, decodable OFDM signal and the 5 MHz link failure is purely RX-side.

Usage: ofdm5_demod.py <capture.dat float-complex64> [capture_rate_hz=10e6]
"""
import sys, numpy as np

# 802.11a L-LTF, frequency domain, subcarriers -26..+26 (DC = 0).
LTF = np.array([1,1,-1,-1,1,1,-1,1,-1,1,1,1,1,1,1,-1,-1,1,1,-1,1,-1,1,1,1,1,
                0,
                1,-1,-1,1,1,-1,1,-1,1,-1,-1,-1,-1,-1,1,1,-1,-1,1,-1,1,-1,1,1,1,1], dtype=float)
PILOTS = [-21,-7,7,21]
DATA_SC = [k for k in range(-26,27) if k!=0 and k not in PILOTS]

def ltf_freq64():
    f = np.zeros(64, dtype=complex)
    for i,sc in enumerate(range(-26,27)):
        f[sc % 64] = LTF[i]
    return f

def main():
    cap = np.fromfile(sys.argv[1], dtype=np.complex64)
    rate = float(sys.argv[2]) if len(sys.argv)>2 else 10e6
    # --- band-isolate to ±2.5 MHz and resample to exactly 5 MHz ---
    N=len(cap); F=np.fft.fft(cap); f=np.fft.fftfreq(N,1/rate)
    F[np.abs(f)>2.5e6]=0; cap=np.fft.ifft(F)
    dec=int(round(rate/5e6))
    x=cap[::dec].astype(complex)            # now ~5 MHz sample rate
    Rs=5e6
    print(f"resampled to {Rs/1e6} MHz: {len(x)} samples")

    # --- L-STF packet detection: lag-16 autocorrelation (Schmidl-Cox-style) ---
    L=16
    c = x[:-L]*np.conj(x[L:])
    P = np.convolve(c, np.ones(L), 'valid')          # sliding sum (numerator)
    R = np.convolve(np.abs(x[L:])**2, np.ones(L),'valid')  # energy (denominator)
    M = np.abs(P[:len(R)])**2 / (R**2 + 1e-12)
    # find a strong, sustained plateau (M near 1 over the L-STF)
    cand = np.where(M > 0.6)[0]
    if len(cand) < 50:
        print(f"NO packet detected (max metric {M.max():.2f}) — signal too weak/dirty?"); return
    start = cand[0]
    print(f"L-STF detected at sample {start} (metric {M[start]:.2f}); {len(cand)} samples above 0.6")

    # --- coarse CFO from the L-STF lag-16 autocorrelation phase ---
    cfo_coarse = np.angle(np.sum(P[start:start+128])) / (2*np.pi*L/Rs)
    x = x * np.exp(-1j*2*np.pi*cfo_coarse*np.arange(len(x))/Rs)
    print(f"coarse CFO = {cfo_coarse/1e3:+.1f} kHz")

    # --- L-LTF: nominally 160 samples after the L-STF start; refine timing by ---
    # cross-correlating with the known L-LTF time-domain symbol ---
    ltf_t = np.fft.ifft(ltf_freq64())
    search = x[start+120 : start+360]
    xc = np.array([np.abs(np.vdot(search[d:d+64], ltf_t)) for d in range(len(search)-64)])
    ltf_off = start+120+int(np.argmax(xc))
    print(f"L-LTF symbol start ~ sample {ltf_off}")
    # two LTF symbols back-to-back
    L1 = x[ltf_off:ltf_off+64]; L2 = x[ltf_off+64:ltf_off+128]
    # fine CFO from the 64-lag repetition
    cfo_fine = np.angle(np.vdot(L1, L2)) / (2*np.pi*64/Rs)
    x = x * np.exp(-1j*2*np.pi*cfo_fine*np.arange(len(x))/Rs)
    print(f"fine CFO   = {cfo_fine/1e3:+.1f} kHz")
    L1 = x[ltf_off:ltf_off+64]; L2 = x[ltf_off+64:ltf_off+128]

    # --- channel estimate from the two LTF symbols ---
    lf = ltf_freq64()
    H = (np.fft.fft(L1)+np.fft.fft(L2))/2
    H = np.where(lf!=0, H/np.where(lf==0,1,lf), 0)

    # --- equalize the SIGNAL + data symbols; report pilot + data EVM ---
    sym0 = ltf_off+128            # SIGNAL field start (GI+sym)
    pil_err=[]; dat_pts=[]
    for s in range(20):          # first 20 OFDM symbols
        base = sym0 + s*80 + 16  # skip 16-sample GI
        if base+64 > len(x): break
        Y = np.fft.fft(x[base:base+64])
        Eq = np.where(H!=0, Y/np.where(H==0,1,H), 0)
        # common phase correction from pilots (BPSK ±1, with the std polarity ignored)
        pv = np.array([Eq[k%64] for k in PILOTS])
        ph = np.angle(np.sum(pv*np.conj(np.sign(pv.real+1e-9))))
        Eq = Eq*np.exp(-1j*ph)
        for k in PILOTS:
            v=Eq[k%64]; pil_err.append(abs(v-np.sign(v.real+1e-9)))
        for k in DATA_SC:
            dat_pts.append(Eq[k%64])
    pil_err=np.array(pil_err); dat=np.array(dat_pts)
    pil_evm = np.sqrt(np.mean(pil_err**2)) if len(pil_err) else float('nan')
    # data EVM vs nearest QPSK point (rough, assumes ≥QPSK), normalized
    if len(dat):
        d=dat/np.sqrt(np.mean(np.abs(dat)**2))
        qpsk=(np.sign(d.real)+1j*np.sign(d.imag))/np.sqrt(2)
        dat_evm=np.sqrt(np.mean(np.abs(d-qpsk)**2))
    else: dat_evm=float('nan')
    print(f"pilot EVM = {pil_evm:.3f} (tight ⇒ <0.3)   data-vs-QPSK EVM = {dat_evm:.3f}")
    print("VERDICT:", "DECODABLE OFDM — TX is good, 5 MHz failure is RX-side"
          if pil_evm<0.4 else "pilots not locking — TX signal or front-end issue")

if __name__=='__main__':
    main()
