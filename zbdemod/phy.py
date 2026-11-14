"""IEEE 802.15.4 2450 MHz O-QPSK PHY: constants, chip tables, reference modulator.

Key facts used throughout the receiver:

* 250 kbit/s, 4 bits -> 1 symbol (62.5 ksym/s), 1 symbol -> 32 chips (2 Mchip/s).
* Chips are O-QPSK modulated with half-sine pulses: even chips on I, odd chips
  on Q delayed by one chip period Tc. This is mathematically MSK, so the
  instantaneous frequency is constant (+-Tc/4) during every chip interval
  [n*Tc, (n+1)*Tc]. Its sign is

      f_n = (-1)^(n+1) * a_n * a_(n-1),      a_n = 2*c_n - 1  (+-1)

  i.e. it depends only on two neighbouring chips. Inside a symbol, f_1..f_31
  are fully determined by the symbol; f_0 depends on the previous symbol's
  last chip, so the receiver ignores it.
* PPDU = preamble (4 x 0x00) | SFD (0xA7) | PHR (length, 7 bits) | PSDU.
  Bytes are sent low nibble first.
"""

from __future__ import annotations

import numpy as np

CHIP_RATE = 2_000_000
CHIPS_PER_SYMBOL = 32
SYMBOL_RATE = CHIP_RATE // CHIPS_PER_SYMBOL  # 62.5 ksym/s
PREAMBLE_BYTES = 4
SFD = 0xA7
MAX_PSDU = 127

#: Frequency deviation that corresponds to a normalised discriminator value of 1.0.
FREQ_UNIT_HZ = CHIP_RATE / 4  # 500 kHz

# Symbol 0 chip sequence c0..c31 (IEEE 802.15.4-2006, table 24).
_SYM0 = "11011001110000110101001000101110"


def channel_freq(channel: int) -> float:
    """Centre frequency [Hz] of a 2.4 GHz channel (11..26)."""
    if not 11 <= channel <= 26:
        raise ValueError(f"2.4 GHz channels are 11..26, got {channel}")
    return 2405e6 + 5e6 * (channel - 11)


def _build_chip_table() -> np.ndarray:
    base = np.array([int(c) for c in _SYM0], dtype=np.uint8)
    table = np.zeros((16, CHIPS_PER_SYMBOL), dtype=np.uint8)
    # Symbols 1..7: symbol 0 cyclically shifted right by 4 chips per step.
    for k in range(8):
        table[k] = np.roll(base, 4 * k)
    # Symbols 8..15: symbols 0..7 with the odd-indexed chips inverted.
    odd = np.zeros(CHIPS_PER_SYMBOL, dtype=np.uint8)
    odd[1::2] = 1
    table[8:] = table[:8] ^ odd
    return table


#: CHIPS[k] = 32 chips (0/1) of symbol k.
CHIPS = _build_chip_table()


def _build_msk_table(chips: np.ndarray) -> np.ndarray:
    a = 2.0 * chips.astype(np.float32) - 1.0
    f = np.zeros_like(a)
    j = np.arange(1, CHIPS_PER_SYMBOL)
    f[:, 1:] = ((-1.0) ** (j + 1)) * a[:, 1:] * a[:, :-1]
    # f[:, 0] depends on the previous symbol -> left at 0 (ignored).
    return f


#: MSK[k, j] = expected sign (+-1) of the frequency in chip interval j of symbol k
#: (j = 1..31; column 0 is zero). Note MSK[k + 8] == -MSK[k].
MSK = _build_msk_table(CHIPS)


def bytes_to_symbols(data: bytes) -> np.ndarray:
    arr = np.frombuffer(bytes(data), dtype=np.uint8)
    out = np.empty(2 * len(arr), dtype=np.uint8)
    out[0::2] = arr & 0x0F
    out[1::2] = arr >> 4
    return out


def symbols_to_bytes(symbols: np.ndarray) -> bytes:
    s = np.asarray(symbols, dtype=np.uint8)
    n = len(s) // 2
    return (s[0 : 2 * n : 2] | (s[1 : 2 * n : 2] << 4)).astype(np.uint8).tobytes()


def symbols_to_chips(symbols: np.ndarray) -> np.ndarray:
    return CHIPS[np.asarray(symbols, dtype=np.intp)].reshape(-1)


def build_ppdu(psdu: bytes) -> bytes:
    """SHR + PHR + PSDU as raw bytes (PSDU must already contain the FCS)."""
    if not 0 < len(psdu) <= MAX_PSDU:
        raise ValueError("PSDU length must be 1..127")
    return bytes(PREAMBLE_BYTES) + bytes([SFD, len(psdu)]) + bytes(psdu)


def modulate_chips(chips: np.ndarray, sps: int) -> np.ndarray:
    """O-QPSK with half-sine pulses. Returns complex64 baseband at sps samples/chip.

    Sample i corresponds to time i*Tc/sps; chip n's pulse starts at n*Tc and
    lasts 2*Tc (I for even n, Q for odd n).
    """
    a = 2.0 * np.asarray(chips, dtype=np.float32) - 1.0
    n = len(a)
    length = (n + 1) * sps
    imp_i = np.zeros(length, dtype=np.float32)
    imp_q = np.zeros(length, dtype=np.float32)
    imp_i[0 : n * sps : 2 * sps] = a[0::2]
    imp_q[sps : n * sps : 2 * sps] = a[1::2]
    pulse = np.sin(np.pi * np.arange(2 * sps) / (2 * sps)).astype(np.float32)
    i = np.convolve(imp_i, pulse)[:length]
    q = np.convolve(imp_q, pulse)[:length]
    return (i + 1j * q).astype(np.complex64)


def modulate_ppdu(psdu: bytes, sps: int) -> np.ndarray:
    """Complex baseband of a complete PPDU (SHR, PHR, PSDU)."""
    return modulate_chips(symbols_to_chips(bytes_to_symbols(build_ppdu(psdu))), sps)


def discriminator(y: np.ndarray, sps: int, prev: complex | None = None) -> np.ndarray:
    """Normalised FM discriminator: d[i] = angle(y[i] * conj(y[i-1])) * 2*sps/pi.

    With an ideal MSK signal d = +-1 inside every chip; a carrier offset df adds
    a constant df / FREQ_UNIT_HZ. d[0] uses `prev` (or is 0 when not given).
    """
    y = np.asarray(y)
    d = np.empty(len(y), dtype=np.float32)
    if len(y) == 0:
        return d
    d[1:] = np.angle(y[1:] * np.conj(y[:-1]))
    d[0] = 0.0 if prev is None else np.angle(y[0] * np.conj(prev))
    d *= 2.0 * sps / np.pi
    return d
