"""Minimal ctypes binding to libhackrf for streaming RX (no extra Python deps).

The DLL is looked up in: $HACKRF_DLL, PothosSDR, radioconda, SDRangel, URH, PATH.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import queue
import sys
import threading
from pathlib import Path

_CANDIDATE_DIRS = [
    r"C:\Program Files\PothosSDR\bin",
    os.path.expandvars(r"%USERPROFILE%\radioconda\Library\bin"),
    r"C:\radioconda\Library\bin",
    r"C:\Program Files\SDRangel",
    r"C:\Program Files\Universal Radio Hacker",
]


class HackRFError(RuntimeError):
    pass


class _Transfer(ctypes.Structure):
    _fields_ = [
        ("device", ctypes.c_void_p),
        ("buffer", ctypes.POINTER(ctypes.c_uint8)),
        ("buffer_length", ctypes.c_int),
        ("valid_length", ctypes.c_int),
        ("rx_ctx", ctypes.c_void_p),
        ("tx_ctx", ctypes.c_void_p),
    ]


_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(_Transfer))


def _load_library() -> ctypes.CDLL:
    names = ["hackrf.dll"] if sys.platform == "win32" else ["libhackrf.so.0", "libhackrf.dylib"]
    paths: list[Path] = []
    env = os.environ.get("HACKRF_DLL")
    if env:
        paths.append(Path(env))
    for d in _CANDIDATE_DIRS:
        for name in names:
            paths.append(Path(d) / name)
    for p in paths:
        if p.is_file():
            if sys.platform == "win32":
                os.add_dll_directory(str(p.parent))  # for libusb-1.0.dll next to it
            return ctypes.CDLL(str(p))
    found = ctypes.util.find_library("hackrf")
    if found:
        return ctypes.CDLL(found)
    raise HackRFError("libhackrf not found; set HACKRF_DLL to the full path of hackrf.dll")


class HackRF:
    """Streaming receiver. Samples arrive as raw int8 IQ `bytes` on `self.queue`."""

    def __init__(self, serial: str | None = None, queue_blocks: int = 512):
        self.lib = lib = _load_library()
        vp = ctypes.c_void_p
        lib.hackrf_init.restype = ctypes.c_int
        lib.hackrf_exit.restype = ctypes.c_int
        lib.hackrf_open.argtypes = [ctypes.POINTER(vp)]
        lib.hackrf_open_by_serial.argtypes = [ctypes.c_char_p, ctypes.POINTER(vp)]
        lib.hackrf_close.argtypes = [vp]
        lib.hackrf_start_rx.argtypes = [vp, _CALLBACK, vp]
        lib.hackrf_stop_rx.argtypes = [vp]
        lib.hackrf_is_streaming.argtypes = [vp]
        lib.hackrf_set_freq.argtypes = [vp, ctypes.c_uint64]
        lib.hackrf_set_sample_rate.argtypes = [vp, ctypes.c_double]
        lib.hackrf_set_baseband_filter_bandwidth.argtypes = [vp, ctypes.c_uint32]
        lib.hackrf_compute_baseband_filter_bw.argtypes = [ctypes.c_uint32]
        lib.hackrf_compute_baseband_filter_bw.restype = ctypes.c_uint32
        lib.hackrf_set_lna_gain.argtypes = [vp, ctypes.c_uint32]
        lib.hackrf_set_vga_gain.argtypes = [vp, ctypes.c_uint32]
        lib.hackrf_set_amp_enable.argtypes = [vp, ctypes.c_uint8]
        lib.hackrf_error_name.argtypes = [ctypes.c_int]
        lib.hackrf_error_name.restype = ctypes.c_char_p

        self._check(lib.hackrf_init(), "hackrf_init")
        self.dev = vp()
        if serial:
            rc = lib.hackrf_open_by_serial(serial.encode(), ctypes.byref(self.dev))
        else:
            rc = lib.hackrf_open(ctypes.byref(self.dev))
        if rc != 0:
            lib.hackrf_exit()
            self._check(rc, "hackrf_open")

        self.queue: queue.Queue[bytes] = queue.Queue(maxsize=queue_blocks)
        self.dropped_bytes = 0
        self.received_bytes = 0
        self._discard = 0
        self._lock = threading.Lock()
        self._cb = _CALLBACK(self._on_samples)  # keep a reference!
        self.streaming = False

    def _check(self, rc: int, what: str) -> None:
        if rc != 0:
            name = self.lib.hackrf_error_name(rc).decode(errors="replace")
            raise HackRFError(f"{what} failed: {name} ({rc})")

    # ------------------------------------------------------------- settings
    def configure(
        self,
        freq_hz: float,
        sample_rate: float = 8e6,
        lna_db: int = 32,
        vga_db: int = 20,
        amp: bool = False,
        bb_filter_hz: float | None = None,
    ) -> None:
        lib, dev = self.lib, self.dev
        self._check(lib.hackrf_set_sample_rate(dev, float(sample_rate)), "set_sample_rate")
        bw = bb_filter_hz if bb_filter_hz else 0.875 * sample_rate
        bw = lib.hackrf_compute_baseband_filter_bw(int(bw))
        self._check(lib.hackrf_set_baseband_filter_bandwidth(dev, bw), "set_baseband_filter")
        self.set_gains(lna_db, vga_db, amp)
        self._check(lib.hackrf_set_freq(dev, int(round(freq_hz))), "set_freq")
        self.bb_filter_hz = bw

    def set_gains(self, lna_db: int, vga_db: int, amp: bool) -> None:
        lna = max(0, min(40, int(lna_db))) // 8 * 8
        vga = max(0, min(62, int(vga_db))) // 2 * 2
        self._check(self.lib.hackrf_set_lna_gain(self.dev, lna), "set_lna_gain")
        self._check(self.lib.hackrf_set_vga_gain(self.dev, vga), "set_vga_gain")
        self._check(self.lib.hackrf_set_amp_enable(self.dev, 1 if amp else 0), "set_amp_enable")
        self.lna_db, self.vga_db, self.amp = lna, vga, amp

    def retune(self, freq_hz: float, settle_bytes: int = 0) -> None:
        """Change frequency while streaming; drops queued and `settle_bytes` of new data."""
        self._check(self.lib.hackrf_set_freq(self.dev, int(round(freq_hz))), "set_freq")
        with self._lock:
            self._discard = settle_bytes
            while True:
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    break

    # ------------------------------------------------------------ streaming
    def _on_samples(self, transfer) -> int:
        t = transfer.contents
        n = t.valid_length
        self.received_bytes += n
        with self._lock:
            if self._discard > 0:
                self._discard -= n
                return 0
        try:
            self.queue.put_nowait(ctypes.string_at(t.buffer, n))
        except queue.Full:
            self.dropped_bytes += n
        return 0

    def start(self) -> None:
        self._check(self.lib.hackrf_start_rx(self.dev, self._cb, None), "start_rx")
        self.streaming = True

    def is_streaming(self) -> bool:
        return self.lib.hackrf_is_streaming(self.dev) == 1

    def stop(self) -> None:
        if self.streaming:
            self.lib.hackrf_stop_rx(self.dev)
            self.streaming = False

    def close(self) -> None:
        self.stop()
        if self.dev:
            self.lib.hackrf_close(self.dev)
            self.dev = ctypes.c_void_p()
        self.lib.hackrf_exit()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
