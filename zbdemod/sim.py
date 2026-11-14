"""Channel simulator: exact continuous-time O-QPSK modulator with CFO, phase,
timing offset, clock drift, IF offset and AWGN. Used by tests and `selftest`."""

from __future__ import annotations

import numpy as np

from . import phy
from .mac import add_fcs


def oqpsk_at_times(chips: np.ndarray, t: np.ndarray) -> np.ndarray:
    """Evaluate the half-sine O-QPSK waveform at times t (in chip periods)."""
    a = 2.0 * np.asarray(chips, dtype=np.float64) - 1.0
    a_pad = np.concatenate(([0.0], a, [0.0]))  # index shift by 1 for n = -1 / n = N
    n1 = np.floor(t).astype(np.int64)
    n0 = n1 - 1
    out = np.zeros(len(t), dtype=np.complex128)
    for n in (n0, n1):
        valid = (n >= 0) & (n < len(a))
        amp = np.where(valid, a_pad[np.clip(n + 1, 0, len(a) + 1)], 0.0)
        val = amp * np.sin(np.pi * (t - n) / 2.0)
        even = (n % 2) == 0
        out += np.where(even, val, 1j * val)
    return out


def random_mpdu(rng: np.random.Generator, length: int) -> bytes:
    """Random data frame of `length` bytes total (incl. FCS) with a valid FCS."""
    if length < 5:
        raise ValueError("length >= 5")
    body = bytearray(rng.integers(0, 256, length - 2, dtype=np.uint8).tobytes())
    body[0] = 0x41  # data frame, PAN compression
    body[1] = 0x88  # short dst / short src, 2003
    return add_fcs(bytes(body))


def make_stream(
    psdus: list[bytes],
    fs: float = 8e6,
    snr_db: float = 30.0,
    cfo_hz: float = 0.0,
    drift_ppm: float = 0.0,
    if_hz: float = 0.0,
    gap_s: tuple[float, float] = (0.5e-3, 3e-3),
    seed: int = 0,
    amplitude: float = 0.3,
) -> tuple[np.ndarray, list[int]]:
    """Build a complex64 stream containing all PSDUs separated by random gaps.

    SNR is defined in a 2 MHz bandwidth. `if_hz` places the signal at that
    baseband frequency (e.g. -2e6 when the SDR is tuned 2 MHz above the channel).
    Returns (samples, start index of every frame).
    """
    rng = np.random.default_rng(seed)
    sps = fs / phy.CHIP_RATE
    pieces = []
    starts = []
    pos = 0
    for psdu in psdus:
        gap = int(rng.uniform(*gap_s) * fs)
        pieces.append(np.zeros(gap, dtype=np.complex128))
        pos += gap
        chips = phy.symbols_to_chips(phy.bytes_to_symbols(phy.build_ppdu(psdu)))
        n_samp = int(np.ceil((len(chips) + 1) * sps * (1 + drift_ppm * 1e-6)))
        t0 = rng.uniform(0, 1)  # sub-sample timing offset
        t = (np.arange(n_samp) + t0) / sps / (1 + drift_ppm * 1e-6)
        sig = oqpsk_at_times(chips, t) * np.exp(1j * rng.uniform(0, 2 * np.pi))
        pieces.append(sig)
        starts.append(pos)
        pos += n_samp
    pieces.append(np.zeros(int(gap_s[1] * fs), dtype=np.complex128))
    x = np.concatenate(pieces) * amplitude
    n = np.arange(len(x))
    x = x * np.exp(2j * np.pi * (cfo_hz + if_hz) / fs * n)
    noise_var = amplitude**2 * (fs / 2e6) / (10 ** (snr_db / 10))
    x = x + np.sqrt(noise_var / 2) * (rng.standard_normal(len(x)) + 1j * rng.standard_normal(len(x)))
    return x.astype(np.complex64), starts


def run_demod(demod, x: np.ndarray, chunk: int = 131072, rng=None) -> list:
    """Feed x in (optionally random-sized) chunks, flush, return frames."""
    frames = []
    i = 0
    while i < len(x):
        n = chunk if rng is None else int(rng.integers(chunk // 4, chunk * 2))
        frames += demod.process(x[i : i + n])
        i += n
    frames += demod.flush()
    return frames
