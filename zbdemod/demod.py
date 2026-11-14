"""Streaming IEEE 802.15.4 O-QPSK demodulator.

Signal chain (all per input block, state carried between blocks):

    IQ -> mix by +offset -> low-pass FIR -> (full rate y_f) -> decimate -> y (2 samples/chip)

Detection of the SHR (preamble tail + SFD), one of:

    detector="diff" (default with the coherent decoder)
       half-sine chip matched filter z, chip-differential product
       x[n] = z[n] * conj(z[n + 1 chip]). A carrier offset only rotates x by a
       constant angle, so x can be correlated coherently over the whole SHR
       (one FFT convolution). The phase of the peak gives a coarse CFO.
    detector="disc"
       FM discriminator d[n] = arg(y[n] y*[n-1]) correlated with the ideal SHR;
       the CFO is a DC term, estimated by a least-squares fit. Loses ~3.5 dB
       at low SNR (FM threshold effect of the arg()).

Symbol decoding, one of:

    method="coherent" (default)
       half-sine matched filter on y_f for every chip; whole-symbol SHR
       alignment check (+-2 symbols), fine CFO + carrier phase + timing from the
       known SHR chips (FFT over 4-chip blocks), 16-way coherent symbol
       correlation with decision-directed phase tracking, clock-drift fit
    method="disc"
       chip integrals of the discriminator, 31-chip MSK correlation

    -> PHR length, PSDU, FCS check
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.signal import fftconvolve, firwin, oaconvolve

from . import phy
from .mac import fcs_ok

CPS = phy.CHIPS_PER_SYMBOL
N_SHR_SYM = 2 * phy.PREAMBLE_BYTES + 2  # 8 preamble + 2 SFD symbols

# (detector, method) -> default SHR correlation threshold. The "diff" value
# gives ~2 false detections per second on pure noise (rejected by the FCS).
DEFAULT_THRESHOLDS = {("diff", "coherent"): 0.22, ("disc", "coherent"): 0.30, ("disc", "disc"): 0.45}


@dataclass
class Frame:
    sample: int  # absolute index (at fs) of the start of the PHR
    time: float  # seconds since the start of the stream
    psdu: bytes
    fcs_ok: bool
    cfo_hz: float
    rssi_dbfs: float
    snr_db: float
    chip_errors: float  # mean chip errors per symbol (0..31)
    corr: float  # SHR correlation peak (0..1)
    drift_ppm: float  # estimated symbol clock offset
    channel: int | None = None

    @property
    def lqi(self) -> int:
        """Rough 0..255 link quality figure derived from chip errors."""
        return int(max(0, min(255, round(255 * (1 - self.chip_errors / 10)))))


class Demodulator:
    def __init__(
        self,
        fs: float = 8e6,
        offset_hz: float = 0.0,
        threshold: float | None = None,
        decim: int | None = None,
        lpf_cutoff: float = 1.3e6,
        lpf_taps: int | None = None,
        preamble_symbols_in_template: int | None = None,
        keep_bad_fcs: bool = False,
        channel: int | None = None,
        method: str = "coherent",
        detector: str | None = None,
    ):
        """
        fs        input sample rate (integer multiple of 2 MHz, >= 4 MHz)
        offset_hz SDR LO minus channel frequency; the channel sits at -offset_hz
                  in the input and is mixed back to 0 Hz
        threshold SHR correlation threshold (default per detector/method, see
                  DEFAULT_THRESHOLDS)
        decim     decimation after the channel filter; default brings the
                  processing rate to 4 MHz (2 samples/chip)
        method    "coherent" (default) or "disc" symbol decoder
        detector  "diff" (default for coherent) or "disc" SHR detector;
                  method "disc" requires detector "disc"
        preamble_symbols_in_template
                  preamble symbols before the SFD used for detection/sync
                  (default 6 for "diff", 4 for "disc")
        """
        if method not in ("coherent", "disc"):
            raise ValueError("method must be 'coherent' or 'disc'")
        if detector is None:
            detector = "diff" if method == "coherent" else "disc"
        if detector not in ("diff", "disc"):
            raise ValueError("detector must be 'diff' or 'disc'")
        if method == "disc" and detector != "disc":
            raise ValueError("method 'disc' needs detector 'disc'")
        n_pre = preamble_symbols_in_template
        if n_pre is None:
            n_pre = 6 if detector == "diff" else 4
        if not 1 <= n_pre <= 2 * phy.PREAMBLE_BYTES:
            raise ValueError("preamble symbols in template: 1..8")
        if threshold is None:
            threshold = DEFAULT_THRESHOLDS[(detector, method)]

        sps_in = fs / phy.CHIP_RATE
        if abs(sps_in - round(sps_in)) > 1e-9 or round(sps_in) < 2:
            raise ValueError("fs must be an integer multiple (>=2) of 2 MHz")
        sps_in = int(round(sps_in))
        if decim is None:
            decim = sps_in // 2 if sps_in % 2 == 0 else 1
        if sps_in % decim or sps_in // decim < 2:
            raise ValueError("decim must divide fs/2MHz and leave >= 2 samples/chip")

        self.method = method
        self.detector = detector
        self.n_pre = n_pre
        self.n_tmpl_sym = n_pre + 2
        self.fs_in = float(fs)
        self.decim = int(decim)
        self.fs = self.fs_in / self.decim  # processing rate
        self.sps_in = sps_in
        self.sps = sps_in // self.decim
        self.sym_len = self.sps * CPS
        self.offset_hz = float(offset_hz)
        self.threshold = threshold
        self.keep_bad_fcs = keep_bad_fcs
        self.channel = channel
        self._need_y = detector == "diff"
        self._need_d = detector == "disc"
        self._need_yf = method == "coherent"

        if lpf_taps is None:
            lpf_taps = 12 * sps_in + 1  # ~6 chips long
        self.h = firwin(lpf_taps, lpf_cutoff, fs=self.fs_in).astype(np.float32)
        self._lut_period = self._mixer_period()
        self._lut = np.zeros(0, dtype=np.complex64)
        self._build_coherent_tables()
        self._build_templates()

        # The preamble is periodic, so the template also matches (at ~n_pre/(n_pre+2))
        # when shifted whole symbols early, and partially even earlier. After the
        # first threshold crossing the true (SFD-aligned) peak is therefore
        # searched over a whole SHR length (no other frame fits there).
        self.slack = N_SHR_SYM * self.sym_len

        # Search window must hold a template, the longest frame and slack for the
        # peak search and timing offsets.
        self.max_frame = (1 + phy.MAX_PSDU) * 2 * self.sym_len  # PHR + PSDU
        self.tau_range = max(2, self.sps)  # +-1 chip of timing search
        self.margin = self.max_frame + self.slack + 4 * self.tau_range
        # Samples kept before the search position: the coherent decoder looks
        # back up to 2 symbols before the detected template start.
        self.history = 3 * self.sym_len + 64
        self.reset()

    # ------------------------------------------------------------------ setup
    def _build_coherent_tables(self) -> None:
        # Half-sine chip pulse (matched filter) at the full and processing rates.
        s = self.sps_in
        self._mf = np.sin(np.pi * np.arange(2 * s + 1) / (2 * s)).astype(np.float32)
        s = self.sps
        self._mf_dec = np.sin(np.pi * np.arange(2 * s + 1) / (2 * s)).astype(np.float32)
        # Expected matched-filter output of chip n (unit amplitude, zero phase):
        # a_n on I for even n, j*a_n on Q for odd n.
        w = (2.0 * phy.CHIPS - 1.0).astype(np.complex128)
        w[:, 1::2] *= 1j
        self._chip_pattern = w  # (16, 32)
        self._wc = np.conj(w).T  # (32, 16): X = z @ wc
        # Known chips of the SHR tail used for fine sync.
        shr_syms = np.array([0] * self.n_pre + [phy.SFD & 0x0F, phy.SFD >> 4])
        self._shr_w = w[shr_syms].reshape(-1)  # (32 * (n_pre + 2),)
        self._shr_chips = len(self._shr_w)

    def _ideal_shr(self) -> np.ndarray:
        """Ideal SHR through the receiver chain; index 0 = first chip pulse start."""
        shr = bytes(phy.PREAMBLE_BYTES) + bytes([phy.SFD, 0x00])
        x = phy.modulate_chips(phy.symbols_to_chips(phy.bytes_to_symbols(shr)), self.sps_in)
        gd = (len(self.h) - 1) // 2
        return np.convolve(x, self.h)[gd : gd + len(x)][:: self.decim].astype(np.complex64)

    def _build_templates(self) -> None:
        y = self._ideal_shr()
        S, sps, n_pre = self.sym_len, self.sps, self.n_pre
        first = (N_SHR_SYM - 2 - n_pre) * S  # first template chip (sample index)

        # Discriminator template: d index i covers the phase step y[i-1] -> y[i].
        d = phy.discriminator(y, sps)
        raw = d[first + 1 : N_SHR_SYM * S + 1].astype(np.float64)
        self.tmpl_raw = raw  # ideal discriminator shape (units of FREQ_UNIT_HZ)
        zm = raw - raw.mean()
        self.tmpl_d = (zm / np.linalg.norm(zm)).astype(np.float64)
        self.tmpl_d_len = len(raw)
        # Least squares d ~= g * tmpl_raw + b  ->  [g, b] = P @ d
        self._ls = np.linalg.pinv(np.stack([raw, np.ones_like(raw)], axis=1))

        # Chip-differential template (last chip pairs with the unknown PHR: excluded).
        x = self._chip_diff(y)
        L = self.n_tmpl_sym * S - sps
        T = x[first : first + L].astype(np.complex128)
        T0 = T - T.mean()  # insensitive to a DC term in x (correlated noise, CW)
        T0 /= np.linalg.norm(T0)
        self.tmpl_x_kernel = np.conj(T0[::-1]).astype(np.complex64)
        self.tmpl_x_len = L

    def reset(self, channel: int | None = None) -> None:
        """Forget all stream state (call after retuning)."""
        if channel is not None:
            self.channel = channel
        self._fir_state = np.zeros(len(self.h) - 1, dtype=np.complex64)
        self._mix_phase = 0.0
        self._mix_index = 0
        self._dec_phase = 0
        self._last_y = np.complex64(0)
        self._p = np.zeros(0, dtype=np.float32)  # |y|^2, defines the buffer length
        self._y = np.zeros(0, dtype=np.complex64)  # filtered, processing rate
        self._d = np.zeros(0, dtype=np.float32)  # discriminator
        self._yf = np.zeros(0, dtype=np.complex64)  # filtered, full rate
        self._base = 0  # absolute index of self._p[0]; self._yf[0] is at base*decim
        self._next = 0  # absolute index where the SHR search continues
        self.n_samples = 0
        self.noise_floor = None
        self.stats = {"detections": 0, "ok": 0, "bad_fcs": 0, "bad_phr": 0}

    # -------------------------------------------------------------- streaming
    def process(self, iq: np.ndarray) -> list[Frame]:
        """Feed complex64 baseband samples (at fs); returns decoded frames."""
        iq = np.asarray(iq, dtype=np.complex64)
        if len(iq) == 0:
            return []
        y, yf = self._frontend(iq)
        self.n_samples += len(iq)
        if self._need_yf:
            self._yf = np.concatenate((self._yf, yf))
        if len(y) == 0:
            return []
        p = (y.real * y.real + y.imag * y.imag).astype(np.float32)
        self._update_noise(p)
        self._p = np.concatenate((self._p, p))
        if self._need_y:
            self._y = np.concatenate((self._y, y))
        if self._need_d:
            self._d = np.concatenate((self._d, phy.discriminator(y, self.sps, prev=self._last_y)))
        self._last_y = y[-1]
        return self._search(final=False)

    def flush(self) -> list[Frame]:
        """Decode whatever is left in the buffer (end of a file)."""
        pad = self.margin
        self._p = np.concatenate((self._p, np.zeros(pad, dtype=np.float32)))
        if self._need_y:
            self._y = np.concatenate((self._y, np.zeros(pad, dtype=np.complex64)))
        if self._need_d:
            self._d = np.concatenate((self._d, np.zeros(pad, dtype=np.float32)))
        if self._need_yf:
            self._yf = np.concatenate((self._yf, np.zeros(pad * self.decim, dtype=np.complex64)))
        return self._search(final=True)

    def _mixer_period(self) -> int | None:
        """Period (samples) of exp(j*2*pi*offset*n/fs) if short, else None."""
        if not self.offset_hz:
            return None
        ratio = self.offset_hz / self.fs_in
        for period in range(1, 4097):
            if abs(ratio * period - round(ratio * period)) < 1e-9:
                return period
        return None

    def _mix(self, x: np.ndarray) -> np.ndarray:
        n = len(x)
        P = self._lut_period
        if P is not None:  # periodic oscillator: slice a cached table
            if len(self._lut) < n + P:
                m = np.arange(P * ((n + P) // P + 1))
                self._lut = np.exp(2j * np.pi * self.offset_hz / self.fs_in * m).astype(np.complex64)
            k = self._mix_index
            self._mix_index = (k + n) % P
            return x * self._lut[k : k + n]
        w = 2 * np.pi * self.offset_hz / self.fs_in
        ph = self._mix_phase + w * np.arange(n, dtype=np.float64)
        self._mix_phase = float((self._mix_phase + w * n) % (2 * np.pi))
        return x * np.exp(1j * ph).astype(np.complex64)

    def _frontend(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Mix and low-pass; returns (decimated at self.fs, full rate)."""
        if self.offset_hz:
            x = self._mix(x)
        xx = np.concatenate((self._fir_state, x))
        yf = oaconvolve(xx, self.h, mode="valid").astype(np.complex64, copy=False)
        self._fir_state = xx[len(xx) - (len(self.h) - 1) :]
        y = yf
        if self.decim > 1:
            y = yf[self._dec_phase :: self.decim]
            self._dec_phase = (self._dec_phase - len(x)) % self.decim
        return y, yf

    def _update_noise(self, p: np.ndarray) -> None:
        blk = 1024
        nb = len(p) // blk
        if nb < 4:
            return
        lvl = np.percentile(p[: nb * blk].reshape(nb, blk).mean(axis=1), 10)
        if self.noise_floor is None:
            self.noise_floor = float(lvl)
        else:
            self.noise_floor = 0.8 * self.noise_floor + 0.2 * float(lvl)

    # -------------------------------------------------------------- detection
    def _chip_diff(self, y: np.ndarray) -> np.ndarray:
        """x[i] = z[i] * conj(z[i + sps]), z[i] = chip matched filter for a pulse at i."""
        sps = self.sps
        n = len(y) - 2 * sps
        z = np.zeros(n, dtype=np.complex64)
        for m in range(1, 2 * sps):  # the end taps of the half-sine are zero
            z += self._mf_dec[m] * y[m : m + n]
        return z[:-sps] * np.conj(z[sps:])

    def _template_span(self) -> int:
        """Buffer samples a metric value at position i depends on (i .. i+span-1)."""
        if self.detector == "diff":
            return self.tmpl_x_len + 3 * self.sps
        return self.tmpl_d_len

    def _metric(self, lo: int, npos: int) -> tuple[np.ndarray, np.ndarray | None]:
        """Normalised SHR correlation for template starts lo .. lo+npos-1."""
        if self.detector == "diff":
            L = self.tmpl_x_len
            x = self._chip_diff(self._y[lo : lo + npos + self._template_span() - 1])
            c = oaconvolve(x, self.tmpl_x_kernel, mode="valid")
            e = x.real * x.real + x.imag * x.imag
            c2 = np.concatenate(([0.0], np.cumsum(e, dtype=np.float64)))
            rho = np.abs(c) / np.sqrt(np.maximum(c2[L:] - c2[:-L], 1e-30))
            return rho, c
        L = self.tmpl_d_len
        seg = self._d[lo : lo + npos + L - 1].astype(np.float64)
        corr = fftconvolve(seg, self.tmpl_d[::-1], mode="valid")
        c1 = np.concatenate(([0.0], np.cumsum(seg)))
        c2 = np.concatenate(([0.0], np.cumsum(seg * seg)))
        s1 = c1[L:] - c1[:-L]
        s2 = c2[L:] - c2[:-L]
        return corr / np.sqrt(np.maximum(s2 - s1 * s1 / L, 1e-9)), None

    def _search(self, final: bool) -> list[Frame]:
        n = len(self._p)
        lo = self._next - self._base
        slack = self.slack  # window for the correlation peak search
        hi = n - self._template_span() - slack - (2 * self.tau_range if final else self.margin)
        frames: list[Frame] = []
        if hi <= lo:
            return frames

        rho, aux = self._metric(lo, hi - lo + slack)
        cand = np.flatnonzero(rho[: hi - lo] > self.threshold)
        pos = 0  # relative to lo
        i = 0
        while i < len(cand):
            c = int(cand[i])
            pk = c + int(np.argmax(rho[c : c + slack]))
            self.stats["detections"] += 1
            frame, end = self._detected(lo + pk, float(rho[pk]), None if aux is None else aux[pk])
            if frame is not None:
                frames.append(frame)
            # Only a frame with a valid FCS consumes its span: a bad FCS often
            # means a false/side-lobe detection with a garbage length field,
            # and skipping that span could hide a real frame.
            if frame is not None and frame.fcs_ok:
                pos = end - lo
            else:
                pos = pk + self.sym_len
            i = int(np.searchsorted(cand, pos))

        nxt = lo + max(pos, hi - lo)
        self._next = self._base + nxt
        # Drop everything that can no longer be needed.
        cut = max(0, nxt - self.history)
        if cut:
            self._p = self._p[cut:]
            self._y = self._y[cut:]
            self._d = self._d[cut:]
            self._yf = self._yf[cut * self.decim :]
            self._base += cut
        return frames

    def _detected(self, q: int, corr: float, aux) -> tuple[Frame | None, int]:
        """Turn a detection at template start q into (start of PHR, coarse CFO) and decode."""
        S = self.sym_len
        if self.detector == "diff":
            start = q + self.n_tmpl_sym * S + 1  # same convention as the d index
            cfo_hint = -float(np.angle(aux)) * self.fs / (2 * np.pi * self.sps)
            dc = 0.0
        else:
            L = self.tmpl_d_len
            g, b = self._ls @ self._d[q : q + L].astype(np.float64)
            if self.method == "disc" and g < 0.2:
                return None, 0
            start = q + L
            cfo_hint = b / max(g, 0.3) * phy.FREQ_UNIT_HZ
            dc = b
        return self._decode(start, corr, cfo_hint, dc)

    # ----------------------------------------------------------------- decode
    def _decode(self, start: int, corr: float, cfo_hint: float, dc: float) -> tuple[Frame | None, int]:
        """start: index of the PHR's first chip interval (y index of its pulse + 1)."""
        S = self.sym_len
        if self.method == "coherent":
            res = self._demod_coherent(start, cfo_hint)
        else:
            res = self._demod_disc(start, dc)
        if res is None:
            self.stats["bad_phr"] += 1
            return None, 0
        syms, chip_err, cfo_hz, drift_ppm, shift = res
        start += shift * S
        psdu = phy.symbols_to_bytes(syms[2:])
        ok = fcs_ok(psdu)
        end = start + len(syms) * S
        self.stats["ok" if ok else "bad_fcs"] += 1
        if not ok and not self.keep_bad_fcs:
            return None, end

        p0 = max(0, start - self.n_tmpl_sym * S - 1)
        seg = self._p[p0:end]
        pw = float(seg.mean()) if len(seg) else 0.0
        rssi = 10 * np.log10(max(pw, 1e-12))
        if self.noise_floor:
            snr = 10 * np.log10(max(pw - self.noise_floor, 1e-12) / self.noise_floor)
        else:
            snr = float("nan")
        abs_start = self._base + start
        frame = Frame(
            sample=abs_start * self.decim,
            time=abs_start / self.fs,
            psdu=psdu,
            fcs_ok=ok,
            cfo_hz=float(cfo_hz),
            rssi_dbfs=float(rssi),
            snr_db=float(snr),
            chip_errors=float(chip_err),
            corr=corr,
            drift_ppm=float(drift_ppm),
            channel=self.channel,
        )
        return frame, end

    @staticmethod
    def _peak_offsets(best: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Row-wise argmax of `best` (n, ntau) with parabolic refinement."""
        ti = best.argmax(axis=1)
        rows = np.arange(len(best))
        w = best[rows, ti]
        frac = np.zeros(len(best))
        inner = np.flatnonzero((ti > 0) & (ti < best.shape[1] - 1))
        if len(inner):
            ym = best[inner, ti[inner] - 1]
            y0 = best[inner, ti[inner]]
            yp = best[inner, ti[inner] + 1]
            den = ym - 2 * y0 + yp
            ok = den < -1e-12
            frac[inner[ok]] = 0.5 * (ym[ok] - yp[ok]) / den[ok]
        return ti, np.clip(frac, -0.5, 0.5), w

    @staticmethod
    def _fit_line(tau, wts, s_idx, slope_max: float, outlier: float) -> tuple[float, float]:
        """Weighted, outlier-trimmed fit tau ~= alpha + beta * s (clock drift)."""
        alpha, beta = 0.0, 0.0
        keep = np.ones(len(s_idx), dtype=bool)
        for _ in range(3):
            if keep.sum() >= 3:
                A = np.stack([np.ones(keep.sum()), s_idx[keep]], axis=1)
                wk = wts[keep]
                sol, *_ = np.linalg.lstsq(A * wk[:, None], tau[keep] * wk, rcond=None)
                alpha, beta = float(sol[0]), float(np.clip(sol[1], -slope_max, slope_max))
            keep = np.abs(tau - (alpha + beta * s_idx)) < outlier
        return alpha, beta

    # ------------------------------------------------------- coherent decoder
    @staticmethod
    def _interp(z: np.ndarray, x: np.ndarray) -> np.ndarray:
        """Linear interpolation of complex z at fractional indices x."""
        i0 = np.floor(x).astype(np.intp)
        fr = x - i0
        return z[i0] * (1.0 - fr) + z[i0 + 1] * fr

    def _demod_coherent(self, start: int, f0: float):
        D, s8 = self.decim, self.sps_in
        S8 = CPS * s8  # full-rate samples per symbol
        R8 = s8  # timing search +-1 chip
        nshr = self._shr_chips
        lam = 0.7  # phase reference memory (symbols ~ 1/(1-lam))
        kmax = 2  # whole-symbol alignment search (periodic preamble side lobes)

        t0 = D * (start - 1)  # self._yf index where the PHR chip-0 pulse starts
        lo = max(0, t0 - (nshr + kmax * CPS) * s8 - 2 * R8 - 2)
        hi = min(len(self._yf), t0 + (self.max_frame + kmax * self.sym_len) * D + 3 * R8 + 2 * len(self._mf))
        if t0 - lo < CPS * s8 or hi - t0 < 2 * S8:
            return None
        seg = self._yf[lo:hi]
        k = np.arange(len(seg))
        seg = seg * np.exp(-2j * np.pi * f0 / self.fs_in * k).astype(np.complex64)
        z = np.correlate(seg, self._mf, mode="valid")  # z[t]: chip pulse starting at t
        base0 = t0 - lo  # z index of the PHR chip 0 (as detected)

        # --- alignment, fine CFO, timing and carrier phase from the known SHR chips
        taus = np.arange(-R8, R8 + 1)
        n_idx = np.arange(-nshr, 0)
        blk = 4
        nb = nshr // blk
        nfft = 512
        freqs = np.fft.fftfreq(nfft, d=blk * s8 / self.fs_in)
        far = np.abs(freqs) > 200e3
        best = None
        for shift in range(-kmax, kmax + 1):
            base = base0 + shift * S8
            idx = base + n_idx[None, :] * s8 + taus[:, None]
            if idx.min() < 0 or base + 2 * S8 + R8 + 1 >= len(z):
                continue
            u = z[idx] * np.conj(self._shr_w)[None, :]
            ub = u[:, : nb * blk].reshape(len(taus), nb, blk).sum(axis=2)
            F = np.abs(np.fft.fft(ub, nfft, axis=1)) ** 2
            F[:, far] = 0.0
            ti, ki = np.unravel_index(int(np.argmax(F)), F.shape)
            if best is None or F[ti, ki] > best[0]:
                best = (F[ti, ki], shift, ti, ki, F, u)
        if best is None:
            return None
        _, shift, ti, ki, F, u = best
        base = base0 + shift * S8
        fm, f_0, fp = F[ti, (ki - 1) % nfft], F[ti, ki], F[ti, (ki + 1) % nfft]
        den = fm - 2 * f_0 + fp
        dk = 0.5 * (fm - fp) / den if den < 0 else 0.0
        df = freqs[ki] + dk * (freqs[1] - freqs[0])
        z = z * np.exp(-2j * np.pi * df / self.fs_in * (np.arange(len(z)) + s8))
        cfo = f0 + df

        rot = np.exp(-2j * np.pi * df / self.fs_in * (base + n_idx * s8 + s8))
        mag = np.abs((u * rot[None, :]).sum(axis=1))
        tt, tfrac, _ = self._peak_offsets(mag[None, :])
        tau_shr = float(taus[tt[0]] + tfrac[0])
        zs = self._interp(z, base + n_idx * s8 + tau_shr)
        R0 = (zs * np.conj(self._shr_w)).sum() * (CPS / nshr)
        if abs(R0) == 0:
            return None

        offs = np.arange(CPS) * s8

        def corr_at(starts: np.ndarray):
            zc = self._interp(z, starts[..., None] + offs)
            return zc @ self._wc, zc

        def dd_decide(X: np.ndarray, R: complex):
            syms = np.empty(len(X), dtype=np.intp)
            refs = np.empty(len(X), dtype=np.complex128)
            for i in range(len(X)):
                rn = R / abs(R)
                refs[i] = rn
                kk = int(np.argmax((X[i] * np.conj(rn)).real))
                syms[i] = kk
                R = lam * R + (1 - lam) * X[i, kk]
            return syms, refs

        # --- PHR at the SHR timing
        X, _ = corr_at(base + np.arange(2) * S8 + tau_shr)
        phr_syms, _ = dd_decide(X, R0)
        length = int(phr_syms[0] | (phr_syms[1] << 4)) & 0x7F
        if length < 3:
            return None
        n_sym = 2 + 2 * length
        if base + (n_sym - 1) * S8 + offs[-1] + tau_shr + 2 * R8 + 2 >= len(z):
            return None

        # --- clock drift: per-symbol non-coherent timing peak, line fit anchored on the SHR
        s_idx = np.arange(n_sym, dtype=np.float64)
        grid = base + s_idx[:, None] * S8 + tau_shr + taus[None, :]
        Xg, _ = corr_at(grid)
        bestg = np.abs(Xg).max(axis=2)  # (n_sym, ntau)
        ti, frac, w = self._peak_offsets(bestg)
        tau_rel = taus[ti] + frac
        anchor_s = -(nshr / CPS) / 2.0  # centre of the SHR span, in symbols
        tau_all = np.concatenate(([0.0], tau_rel))
        s_all = np.concatenate(([anchor_s], s_idx))
        w_all = np.concatenate(([nshr / CPS * float(np.median(w))], np.clip(w, 0, None) + 1e-9))
        slope_max = 120e-6 * S8
        alpha, beta = self._fit_line(tau_all, w_all, s_all, slope_max, outlier=2.0)
        alpha = float(np.clip(alpha, -R8 + 1, R8 - 1))

        # --- final coherent decisions with decision-directed phase tracking
        starts = base + s_idx * S8 + tau_shr + alpha + beta * s_idx
        X, zc = corr_at(starts)
        syms, refs = dd_decide(X, R0)
        if int(syms[0] | (syms[1] << 4)) & 0x7F != length:
            return None
        chip_metric = (zc * np.conj(refs)[:, None] * np.conj(self._chip_pattern[syms])).real
        chip_err = float((chip_metric < 0).sum(axis=1).mean())
        return syms, chip_err, cfo, beta / S8 * 1e6, shift

    # --------------------------------------------------- discriminator decoder
    def _chip_values(self, C: np.ndarray, starts: np.ndarray) -> np.ndarray:
        """Chip-interval integrals for symbols starting at (fractional) `starts`.

        C is the cumulative sum of the DC-corrected discriminator; values are
        normalised so an ideal chip is +-1. Returns shape starts.shape + (32,).
        """
        offs = np.arange(CPS + 1) * self.sps
        idx = starts[..., None] + offs
        if np.issubdtype(idx.dtype, np.integer):
            Ci = C[idx]
        else:
            Ci = np.interp(idx, np.arange(len(C)), C)
        return np.diff(Ci, axis=-1) / self.sps

    def _demod_disc(self, start: int, b: float):
        sps, S, R = self.sps, self.sym_len, self.tau_range
        n = len(self._d)
        if start - R < 0 or start + 2 * S + 2 * R + 2 > n:
            return None
        # Cumulative sum over the region that may be touched (up to a maximal frame).
        r0 = start - R
        r1 = min(n, start + self.max_frame + 3 * R + 2)
        C = np.concatenate(([0.0], np.cumsum(self._d[r0:r1].astype(np.float64) - b)))
        base = start - r0
        taus = np.arange(-R, R + 1)
        templ = phy.MSK[:, 1:].T.astype(np.float64)  # (31, 16)

        def coarse(n_sym: int):
            starts = base + np.arange(n_sym)[:, None] * S + taus[None, :]
            v = self._chip_values(C, starts)  # (n_sym, ntau, 32)
            return v[..., 1:] @ templ  # (n_sym, ntau, 16)

        # --- PHR (2 symbols) with a small timing search around the SHR timing
        sc = coarse(2)
        best = sc.max(axis=2)
        tau_phr = int(taus[np.argmax(best.sum(axis=0))])
        phr_syms = sc[:, tau_phr + R, :].argmax(axis=1)
        length = int(phr_syms[0] | (phr_syms[1] << 4)) & 0x7F
        if length < 3:
            return None
        n_sym = 2 + 2 * length
        last_start_max = len(C) - 1 - CPS * sps - 1  # keep interp in range
        if base + (n_sym - 1) * S + R > last_start_max:
            return None

        # --- coarse per-symbol timing, then a weighted linear fit (clock drift)
        best = coarse(n_sym).max(axis=2)
        ti, frac, w = self._peak_offsets(best)
        tau_est = taus[ti] + frac - tau_phr
        s_idx = np.arange(n_sym, dtype=np.float64)
        alpha, beta = self._fit_line(tau_est, np.clip(w, 0, None) + 1e-6, s_idx, 120e-6 * S, 1.5)
        alpha = float(np.clip(alpha + tau_phr, -R + 1, R - 1))

        # --- final decisions at the fitted (fractional) timing
        starts = np.clip(base + s_idx * S + alpha + beta * s_idx, 0, last_start_max)
        v = self._chip_values(C, starts)  # (n_sym, 32)
        syms = (v[:, 1:] @ templ).argmax(axis=1)
        chip_err = float((np.sign(v[:, 1:]) != phy.MSK[syms, 1:]).sum(axis=1).mean())
        if int(syms[0] | (syms[1] << 4)) & 0x7F != length:
            return None
        return syms, chip_err, b * phy.FREQ_UNIT_HZ, beta / S * 1e6, 0
