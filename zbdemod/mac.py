"""IEEE 802.15.4 MAC + Zigbee NWK/APS header parsing and FCS (CRC-16/KERMIT)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


def _make_crc_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC_TABLE = _make_crc_table()


def crc16(data: bytes) -> int:
    """ITU-T CRC-16 as used by 802.15.4 (poly 0x1021 reflected, init 0) = CRC-16/KERMIT."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc


def add_fcs(mhr_and_payload: bytes) -> bytes:
    return bytes(mhr_and_payload) + struct.pack("<H", crc16(mhr_and_payload))


def fcs_ok(psdu: bytes) -> bool:
    if len(psdu) < 3:
        return False
    return crc16(psdu[:-2]) == struct.unpack_from("<H", psdu, len(psdu) - 2)[0]


FRAME_TYPES = {0: "Beacon", 1: "Data", 2: "Ack", 3: "Cmd", 5: "Multipurpose", 6: "Frag", 7: "Ext"}

MAC_COMMANDS = {
    0x01: "Association Request",
    0x02: "Association Response",
    0x03: "Disassociation",
    0x04: "Data Request",
    0x05: "PAN ID Conflict",
    0x06: "Orphan Notification",
    0x07: "Beacon Request",
    0x08: "Coordinator Realignment",
    0x09: "GTS Request",
}

NWK_COMMANDS = {
    0x01: "Route Request",
    0x02: "Route Reply",
    0x03: "Network Status",
    0x04: "Leave",
    0x05: "Route Record",
    0x06: "Rejoin Request",
    0x07: "Rejoin Response",
    0x08: "Link Status",
    0x09: "Network Report",
    0x0A: "Network Update",
    0x0B: "End Device Timeout Request",
    0x0C: "End Device Timeout Response",
    0x0D: "Link Power Delta",
}

KEY_IDS = {0: "data key", 1: "network key", 2: "key-transport key", 3: "key-load key"}


def fmt_short(addr: int) -> str:
    return "0xffff" if addr == 0xFFFF else f"0x{addr:04x}"


def fmt_ext(raw: bytes) -> str:
    """Extended (IEEE) address: little endian on air, shown MSB first like Wireshark."""
    return ":".join(f"{b:02x}" for b in reversed(raw))


@dataclass
class MacFrame:
    frame_type: int
    security: bool
    pending: bool
    ack_request: bool
    pan_compression: bool
    version: int
    seq: int | None
    dst_pan: int | None = None
    dst: str | None = None
    src_pan: int | None = None
    src: str | None = None
    payload: bytes = b""
    info: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def type_name(self) -> str:
        return FRAME_TYPES.get(self.frame_type, f"Type{self.frame_type}")

    def summary(self) -> str:
        parts = [self.type_name]
        if self.seq is not None:
            parts.append(f"seq={self.seq}")
        if self.frame_type != 2:
            pan = self.dst_pan if self.dst_pan is not None else self.src_pan
            if pan is not None:
                parts.append(f"pan=0x{pan:04x}")
            if self.src or self.dst:
                parts.append(f"{self.src or '-'} -> {self.dst or '-'}")
        flags = "".join(
            c for c, on in (("S", self.security), ("P", self.pending), ("A", self.ack_request)) if on
        )
        if flags:
            parts.append(f"[{flags}]")
        parts.extend(self.info)
        if self.error:
            parts.append(f"!{self.error}")
        return " ".join(parts)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def rest(self) -> bytes:
        out = self.data[self.pos :]
        self.pos = len(self.data)
        return out


def _addr(r: _Reader, mode: int) -> str | None:
    if mode == 2:
        return fmt_short(r.u16())
    if mode == 3:
        return fmt_ext(r.take(8))
    return None


def parse(psdu: bytes, decode_zigbee: bool = True) -> MacFrame:
    """Parse an MPDU (PSDU including the 2-byte FCS)."""
    body = psdu[:-2]
    r = _Reader(body)
    try:
        fc = r.u16()
    except ValueError:
        return MacFrame(0, False, False, False, False, 0, None, error="too short")
    ftype = fc & 7
    mf = MacFrame(
        frame_type=ftype,
        security=bool(fc & 0x0008),
        pending=bool(fc & 0x0010),
        ack_request=bool(fc & 0x0020),
        pan_compression=bool(fc & 0x0040),
        version=(fc >> 12) & 3,
        seq=None,
    )
    dst_mode = (fc >> 10) & 3
    src_mode = (fc >> 14) & 3
    try:
        if not fc & 0x0100:  # sequence number suppression (2015 frames only)
            mf.seq = r.u8()
        if dst_mode:
            mf.dst_pan = r.u16()
            mf.dst = _addr(r, dst_mode)
        if src_mode:
            if not mf.pan_compression:
                mf.src_pan = r.u16()
            mf.src = _addr(r, src_mode)
        if fc & 0x0200:
            mf.info.append("(IEs not parsed)")
            mf.payload = r.rest()
            return mf
        if mf.security:
            mf.info.append("(MAC security)")
            mf.payload = r.rest()
            return mf
        mf.payload = r.rest()
        if ftype == 0:
            _parse_beacon(mf, decode_zigbee)
        elif ftype == 3 and mf.payload:
            cmd = mf.payload[0]
            mf.info.append(MAC_COMMANDS.get(cmd, f"cmd 0x{cmd:02x}"))
        elif ftype == 1 and decode_zigbee and mf.payload:
            mf.info.append(parse_nwk(mf.payload))
    except ValueError as exc:
        mf.error = str(exc)
    return mf


def _parse_beacon(mf: MacFrame, decode_zigbee: bool) -> None:
    r = _Reader(mf.payload)
    sf = r.u16()
    gts = r.u8()
    if gts & 7:
        if gts & 0x80:  # GTS permit
            r.take(1)
        r.take(3 * (gts & 7))
    pend = r.u8()
    r.take(2 * (pend & 7) + 8 * ((pend >> 4) & 7))
    coord = bool(sf & 0x4000)
    permit = bool(sf & 0x8000)
    mf.info.append(f"{'PAN-coord ' if coord else ''}assoc={'yes' if permit else 'no'}")
    zb = r.rest()
    if decode_zigbee and len(zb) >= 11 and zb[0] == 0:
        stack = zb[1] & 0x0F
        proto = zb[1] >> 4
        router_cap = bool(zb[2] & 0x04)
        depth = (zb[2] >> 3) & 0x0F
        ed_cap = bool(zb[2] & 0x80)
        epid = fmt_ext(zb[3:11])
        prof = {1: "Zigbee", 2: "ZigbeePRO"}.get(stack, f"stack{stack}")
        mf.info.append(
            f"{prof} v{proto} depth={depth} router_cap={int(router_cap)} "
            f"ed_cap={int(ed_cap)} epid={epid}"
        )


def parse_nwk(data: bytes) -> str:
    """One-line summary of a Zigbee NWK frame (and APS header when unencrypted)."""
    r = _Reader(data)
    try:
        fc = r.u16()
        ftype = fc & 3
        proto = (fc >> 2) & 0x0F
        if proto == 3:
            return "ZGP (Green Power)"
        if ftype == 3:
            return "Zigbee Inter-PAN " + _parse_aps(data[2:])
        if proto != 2:
            return f"(non-Zigbee payload, nwk-ver {proto})"
        dst = r.u16()
        src = r.u16()
        radius = r.u8()
        seq = r.u8()
        parts = [f"NWK {('Data', 'Cmd', 'Rsvd', 'Inter-PAN')[ftype]}"]
        parts.append(f"{fmt_short(src)}->{fmt_short(dst)} r={radius} nseq={seq}")
        if fc & 0x0800:
            parts.append(f"dstIEEE={fmt_ext(r.take(8))}")
        if fc & 0x1000:
            parts.append(f"srcIEEE={fmt_ext(r.take(8))}")
        if fc & 0x0100:
            r.u8()  # multicast control
        if fc & 0x0400:
            count = r.u8()
            r.u8()
            r.take(2 * count)
            parts.append(f"srcroute({count})")
        if fc & 0x0200:
            sc = r.u8()
            fcnt = struct.unpack("<I", r.take(4))[0]
            key_id = (sc >> 3) & 3
            ext_nonce = bool(sc & 0x20)
            sec = [f"enc({KEY_IDS[key_id]}", f"fc={fcnt}"]
            if ext_nonce:
                sec.append(f"src={fmt_ext(r.take(8))}")
            if key_id == 1:
                sec.append(f"kseq={r.u8()}")
            parts.append(" ".join(sec) + ")")
            return " ".join(parts)
        payload = r.rest()
        if ftype == 1 and payload:
            parts.append(NWK_COMMANDS.get(payload[0], f"cmd 0x{payload[0]:02x}"))
        elif ftype == 0:
            parts.append(_parse_aps(payload))
        return " ".join(parts)
    except ValueError:
        return "NWK (truncated)"


def _parse_aps(data: bytes) -> str:
    r = _Reader(data)
    try:
        fc = r.u8()
        ftype = fc & 3
        delivery = (fc >> 2) & 3
        name = ("Data", "Cmd", "Ack", "Inter-PAN")[ftype]
        parts = [f"APS {name}"]
        if ftype in (0, 2, 3):
            if ftype == 3 or delivery == 3:
                parts.append(f"group=0x{r.u16():04x}")
            elif not (ftype == 2 and fc & 0x10):
                parts.append(f"dep={r.u8()}")
            if not (ftype == 2 and fc & 0x10):
                cluster = r.u16()
                profile = r.u16()
                parts.append(f"cluster=0x{cluster:04x} profile=0x{profile:04x}")
                if ftype != 3:
                    parts.append(f"sep={r.u8()}")
        if ftype != 3:
            parts.append(f"cnt={r.u8()}")
        if fc & 0x20:
            parts.append("(APS encrypted)")
        return " ".join(parts)
    except ValueError:
        return "APS (truncated)"
