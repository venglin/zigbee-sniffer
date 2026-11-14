"""PCAP writer: LINKTYPE_IEEE802_15_4_TAP (283) with FCS-type and channel TLVs.

Wireshark decodes this as IEEE 802.15.4 -> Zigbee NWK/APS/ZCL, verifies the
FCS and shows the channel number.
"""

from __future__ import annotations

import struct
import time
from typing import BinaryIO

LINKTYPE_IEEE802_15_4_TAP = 283
LINKTYPE_IEEE802_15_4_WITHFCS = 195


def _tlv(t: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", t, len(value)) + value + b"\x00" * pad


class PcapWriter:
    def __init__(self, f: BinaryIO, tap: bool = True):
        self.f = f
        self.tap = tap
        linktype = LINKTYPE_IEEE802_15_4_TAP if tap else LINKTYPE_IEEE802_15_4_WITHFCS
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        f.flush()

    def write(self, psdu: bytes, timestamp: float | None = None, channel: int | None = None) -> None:
        if timestamp is None:
            timestamp = time.time()
        if self.tap:
            tlvs = _tlv(0, bytes([1]))  # FCS type: 16-bit CRC
            if channel is not None:
                tlvs += _tlv(3, struct.pack("<HB", channel, 0))  # channel, page 0
            data = struct.pack("<BBH", 0, 0, 4 + len(tlvs)) + tlvs + psdu
        else:
            data = psdu
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)
        self.f.flush()
