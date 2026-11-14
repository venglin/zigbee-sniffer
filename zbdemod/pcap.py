"""PCAP writer: LINKTYPE_IEEE802_15_4_TAP (283) with FCS-type and channel TLVs.

Wireshark decodes this as IEEE 802.15.4 -> Zigbee NWK/APS/ZCL, verifies the
FCS and shows the channel number.

read_pcap() reads 802.15.4 frames back from PCAP or PCAPNG files (Wireshark,
tshark, zbdemod and other sniffers) for the network map.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterator

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


# ------------------------------------------------------------------ reading
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
LINKTYPE_IEEE802_15_4_NOFCS = 230
_READABLE = (
    LINKTYPE_IEEE802_15_4_WITHFCS,
    LINKTYPE_IEEE802_15_4_TAP,
    LINKTYPE_IEEE802_15_4_NOFCS,
    LINKTYPE_IEEE802_15_4_NONASK_PHY,
)


@dataclass
class Record:
    timestamp: float
    psdu: bytes  # MPDU including a 2-byte FCS (computed when the capture had none)
    fcs_ok: bool
    channel: int | None = None
    rssi_dbm: float | None = None


def _from_linktype(linktype: int, data: bytes, ts: float) -> Record | None:
    from .mac import add_fcs, fcs_ok

    channel = rssi = None
    fcs_len = 2
    if linktype == LINKTYPE_IEEE802_15_4_TAP:
        if len(data) < 4:
            return None
        hlen = struct.unpack_from("<H", data, 2)[0]
        pos = 4
        while pos + 4 <= hlen:
            t, ln = struct.unpack_from("<HH", data, pos)
            v = data[pos + 4 : pos + 4 + ln]
            if t == 0 and ln >= 1:
                fcs_len = {0: 0, 1: 2, 2: 4}.get(v[0], 2)
            elif t == 1 and ln >= 4:
                rssi = struct.unpack("<f", v[:4])[0]
            elif t == 3 and ln >= 2:
                channel = struct.unpack_from("<H", v)[0]
            pos += 4 + ln + (-ln) % 4
        data = data[hlen:]
    elif linktype == LINKTYPE_IEEE802_15_4_NOFCS:
        fcs_len = 0
    elif linktype == LINKTYPE_IEEE802_15_4_NONASK_PHY:
        data = data[6:]  # preamble, SFD, PHR
    if fcs_len == 0:
        return Record(ts, add_fcs(data), True, channel, rssi)
    if fcs_len == 4:  # 32-bit FCS (SUN PHYs): not ours, keep the frame with a 16-bit one
        return Record(ts, add_fcs(data[:-4]), True, channel, rssi)
    return Record(ts, bytes(data), fcs_ok(data), channel, rssi)


def read_pcap(f: BinaryIO) -> Iterator[Record]:
    """IEEE 802.15.4 frames from a PCAP or PCAPNG stream (as written by Wireshark,
    tshark, zbdemod or most 802.15.4 sniffers)."""
    head = f.read(4)
    if len(head) < 4:
        return
    if head == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(f, head)
        return
    magic = struct.unpack("<I", head)[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        e = ">"
        magic = struct.unpack(">I", head)[0]
    else:
        raise ValueError("not a PCAP/PCAPNG file")
    scale = 1e-9 if magic == 0xA1B23C4D else 1e-6
    rest = f.read(20)
    if len(rest) < 20:
        return
    linktype = struct.unpack(e + "I", rest[16:20])[0] & 0x0FFFFFFF
    if linktype not in _READABLE:
        raise ValueError(f"unsupported link-layer type {linktype} (not IEEE 802.15.4)")
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            return
        sec, frac, incl, _ = struct.unpack(e + "IIII", hdr)
        data = f.read(incl)
        if len(data) < incl:
            return
        rec = _from_linktype(linktype, data, sec + frac * scale)
        if rec is not None:
            yield rec


def _read_pcapng(f: BinaryIO, first: bytes) -> Iterator[Record]:
    e = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    head = first
    while True:
        if head is None:
            head = f.read(4)
        if len(head) < 4:
            return
        hdr = head + f.read(4)
        head = None
        if len(hdr) < 8:
            return
        if hdr[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte order lives in its body
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", hdr[4:8])[0]
            f.read(blen - 12)
            interfaces = []
            continue
        btype, blen = struct.unpack(e + "II", hdr)
        if blen < 12:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1:  # interface description
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            tick = 1e-6
            pos = 8
            while pos + 4 <= len(body):
                code, ln = struct.unpack_from(e + "HH", body, pos)
                if code == 0:
                    break
                if code == 9 and ln >= 1:  # if_tsresol
                    v = body[pos + 4]
                    tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                pos += 4 + ln + (-ln) % 4
            interfaces.append((linktype, tick))
        elif btype in (6, 3) and interfaces:  # enhanced / simple packet
            if btype == 6:
                iface, hi, lo, cap = struct.unpack_from(e + "IIII", body, 0)
                data = body[20 : 20 + cap]
            else:
                iface, hi, lo = 0, 0, 0
                data = body[4:]
            if iface >= len(interfaces):
                continue
            linktype, tick = interfaces[iface]
            if linktype not in _READABLE:
                continue
            rec = _from_linktype(linktype, data, ((hi << 32) | lo) * tick)
            if rec is not None:
                yield rec
