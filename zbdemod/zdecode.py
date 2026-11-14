"""Decrypted Zigbee NWK payloads: NWK commands, APS, ZDO and ZCL.

describe(nwk_frame, plaintext) returns an Inner with a one-line summary and the
structured fields the network map uses (neighbour tables with link costs, route
records, device announcements, ZCL Basic attributes...).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .mac import NWK_COMMANDS, fmt_ext, fmt_short

NETWORK_STATUS = {
    0x00: "No route available",
    0x01: "Tree link failure",
    0x02: "Non-tree link failure",
    0x03: "Low battery",
    0x04: "No routing capacity",
    0x05: "No indirect capacity",
    0x06: "Indirect transaction expiry",
    0x07: "Target device unavailable",
    0x08: "Target address unallocated",
    0x09: "Parent link failure",
    0x0A: "Validate route",
    0x0B: "Source route failure",
    0x0C: "Many-to-one route failure",
    0x0D: "Address conflict",
    0x0E: "Verify addresses",
    0x0F: "PAN identifier update",
    0x10: "Network address update",
    0x11: "Bad frame counter",
    0x12: "Bad key sequence number",
}

ZDO_CLUSTERS = {
    0x0000: "NWK_addr_req",
    0x0001: "IEEE_addr_req",
    0x0002: "Node_Desc_req",
    0x0003: "Power_Desc_req",
    0x0004: "Simple_Desc_req",
    0x0005: "Active_EP_req",
    0x0006: "Match_Desc_req",
    0x0013: "Device_annce",
    0x001F: "Parent_annce",
    0x0021: "Bind_req",
    0x0022: "Unbind_req",
    0x0031: "Mgmt_Lqi_req",
    0x0032: "Mgmt_Rtg_req",
    0x0034: "Mgmt_Leave_req",
    0x0036: "Mgmt_Permit_Joining_req",
    0x0038: "Mgmt_NWK_Update_req",
}
ZDO_CLUSTERS.update({c | 0x8000: n.replace("_req", "_rsp") for c, n in list(ZDO_CLUSTERS.items()) if n.endswith("_req")})
ZDO_CLUSTERS[0x8038] = "Mgmt_NWK_Update_notify"

ZCL_CLUSTERS = {
    0x0000: "Basic",
    0x0001: "Power Configuration",
    0x0002: "Device Temperature",
    0x0003: "Identify",
    0x0004: "Groups",
    0x0005: "Scenes",
    0x0006: "On/Off",
    0x0008: "Level Control",
    0x000A: "Time",
    0x0019: "OTA Upgrade",
    0x0020: "Poll Control",
    0x0021: "Green Power",
    0x0101: "Door Lock",
    0x0102: "Window Covering",
    0x0201: "Thermostat",
    0x0202: "Fan Control",
    0x0300: "Color Control",
    0x0400: "Illuminance Measurement",
    0x0402: "Temperature Measurement",
    0x0403: "Pressure Measurement",
    0x0405: "Humidity Measurement",
    0x0406: "Occupancy Sensing",
    0x0500: "IAS Zone",
    0x0702: "Metering",
    0x0B04: "Electrical Measurement",
    0x0B05: "Diagnostics",
    0x1000: "Touchlink",
}

ZCL_GLOBAL = {
    0x00: "Read Attributes",
    0x01: "Read Attributes Response",
    0x02: "Write Attributes",
    0x04: "Write Attributes Response",
    0x05: "Write Attributes No Response",
    0x06: "Configure Reporting",
    0x07: "Configure Reporting Response",
    0x08: "Read Reporting Configuration",
    0x09: "Read Reporting Configuration Response",
    0x0A: "Report Attributes",
    0x0B: "Default Response",
    0x0C: "Discover Attributes",
    0x0D: "Discover Attributes Response",
}

ZCL_COMMANDS = {  # cluster-specific, client -> server unless noted
    0x0003: {0x00: "Identify", 0x01: "Identify Query", 0x40: "Trigger Effect"},
    0x0006: {0x00: "Off", 0x01: "On", 0x02: "Toggle", 0x40: "Off With Effect",
             0x41: "On With Recall Global Scene", 0x42: "On With Timed Off"},
    0x0008: {0x00: "Move To Level", 0x01: "Move", 0x02: "Step", 0x03: "Stop",
             0x04: "Move To Level (On/Off)", 0x05: "Move (On/Off)", 0x06: "Step (On/Off)", 0x07: "Stop (On/Off)"},
    0x0300: {0x00: "Move To Hue", 0x03: "Move To Saturation", 0x06: "Move To Hue And Saturation",
             0x07: "Move To Color", 0x0A: "Move To Color Temperature", 0x47: "Stop Move Step"},
    0x0019: {0x00: "Image Notify", 0x01: "Query Next Image Request", 0x02: "Query Next Image Response",
             0x03: "Image Block Request", 0x05: "Image Block Response", 0x06: "Upgrade End Request",
             0x07: "Upgrade End Response"},
    0x0020: {0x00: "Check-in"},
}
ZCL_SERVER_COMMANDS = {0x0500: {0x00: "Zone Status Change Notification", 0x01: "Zone Enroll Request"}}

ZCL_ATTRIBUTES = {
    0x0000: {0x0000: "ZCLVersion", 0x0001: "ApplicationVersion", 0x0002: "StackVersion", 0x0003: "HWVersion",
             0x0004: "ManufacturerName", 0x0005: "ModelIdentifier", 0x0006: "DateCode", 0x0007: "PowerSource",
             0x4000: "SWBuildID"},
    0x0001: {0x0020: "BatteryVoltage", 0x0021: "BatteryPercentageRemaining"},
    0x0006: {0x0000: "OnOff"},
    0x0008: {0x0000: "CurrentLevel"},
    0x0300: {0x0003: "CurrentX", 0x0004: "CurrentY", 0x0007: "ColorTemperatureMireds"},
    0x0400: {0x0000: "MeasuredValue"},
    0x0402: {0x0000: "MeasuredValue"},
    0x0403: {0x0000: "MeasuredValue"},
    0x0405: {0x0000: "MeasuredValue"},
    0x0406: {0x0000: "Occupancy"},
    0x0500: {0x0000: "ZoneState", 0x0001: "ZoneType", 0x0002: "ZoneStatus"},
}

POWER_SOURCES = {0x00: "unknown", 0x01: "mains (single phase)", 0x02: "mains (3 phase)", 0x03: "battery",
                 0x04: "DC source", 0x05: "emergency mains (always on)", 0x06: "emergency mains (transfer switch)"}

LOGICAL_TYPES = {0: "coordinator", 1: "router", 2: "end_device"}
RELATIONSHIPS = {0: "parent", 1: "child", 2: "sibling", 3: "none", 4: "previous child"}


@dataclass
class Inner:
    kind: str  # nwk_cmd | zdo | zcl | aps_cmd | aps_ack | aps_encrypted | aps_data | error
    summary: str
    data: dict = field(default_factory=dict)


class _R:
    def __init__(self, b: bytes, pos: int = 0):
        self.b, self.pos = b, pos

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.b):
            raise ValueError("truncated")
        out = self.b[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def ext(self) -> str:
        return fmt_ext(self.take(8))

    def left(self) -> int:
        return len(self.b) - self.pos


def capability(cap: int) -> dict:
    return {
        "router": bool(cap & 0x02),
        "mains": bool(cap & 0x04),
        "rx_on_when_idle": bool(cap & 0x08),
    }


def _cap_text(c: dict) -> str:
    return ", ".join(
        ["router" if c["router"] else "end device", "mains" if c["mains"] else "battery"]
        + (["rx on idle"] if c["rx_on_when_idle"] else ["sleepy"])
    )


# ---------------------------------------------------------------- NWK cmds
def nwk_command(p: bytes) -> Inner:
    r = _R(p)
    cmd = r.u8()
    name = NWK_COMMANDS.get(cmd, f"NWK cmd 0x{cmd:02x}")
    d: dict = {"cmd": cmd, "name": name}
    text = name
    if cmd == 0x08:  # Link Status
        opts = r.u8()
        entries = []
        for _ in range(opts & 0x1F):
            addr = r.u16()
            st = r.u8()
            entries.append({"addr": addr, "in": st & 7, "out": (st >> 4) & 7})
        d.update(first=bool(opts & 0x20), last=bool(opts & 0x40), entries=entries)
        text += f" ({len(entries)} neighbours): " + ", ".join(
            f"{fmt_short(e['addr'])} in{e['in']}/out{e['out']}" for e in entries
        )
    elif cmd == 0x05:  # Route Record
        relays = [r.u16() for _ in range(r.u8())]
        d["relays"] = relays
        text += " via " + (" > ".join(fmt_short(a) for a in relays) if relays else "(direct)")
    elif cmd == 0x01:  # Route Request
        opts, rid, dst, cost = r.u8(), r.u8(), r.u16(), r.u8()
        mto = (opts >> 3) & 3
        d.update(id=rid, dst=dst, cost=cost, many_to_one=mto)
        text = ("Many-to-one Route Request" if mto else "Route Request") + f" id={rid}"
        if not mto:
            text += f" dst={fmt_short(dst)}"
    elif cmd == 0x02:  # Route Reply
        opts, rid, orig, resp, cost = r.u8(), r.u8(), r.u16(), r.u16(), r.u8()
        d.update(id=rid, originator=orig, responder=resp, cost=cost)
        text += f" id={rid} {fmt_short(orig)}<-{fmt_short(resp)} cost={cost}"
    elif cmd == 0x03:  # Network Status
        status, dst = r.u8(), r.u16()
        d.update(status=status, status_name=NETWORK_STATUS.get(status, f"0x{status:02x}"), dst=dst)
        text += f": {d['status_name']} ({fmt_short(dst)})"
    elif cmd == 0x04:  # Leave
        opts = r.u8()
        d.update(rejoin=bool(opts & 0x20), request=bool(opts & 0x40), remove_children=bool(opts & 0x80))
        text += " request" if d["request"] else ""
        text += " (rejoin)" if d["rejoin"] else ""
    elif cmd == 0x06:  # Rejoin Request
        d["capability"] = capability(r.u8())
        text += f" ({_cap_text(d['capability'])})"
    elif cmd == 0x07:  # Rejoin Response
        addr, status = r.u16(), r.u8()
        d.update(addr=addr, status=status)
        text += f" {fmt_short(addr)} status={status}"
    elif cmd == 0x0A:  # Network Update
        opts = r.u8()
        epid, upd, pan = r.ext(), r.u8(), r.u16()
        d.update(epid=epid, update_id=upd, new_pan=pan)
        text += f" new PAN 0x{pan:04x} (update {upd})"
    elif cmd == 0x0B:  # End Device Timeout Request
        t = r.u8()
        d["timeout_s"] = 10 if t == 0 else 60 * (1 << t)
        text += f" ({d['timeout_s'] // 60 or 10} {'min' if t else 's'})"
    return Inner("nwk_cmd", text, d)


# --------------------------------------------------------------------- APS
def aps(p: bytes) -> tuple[dict, bytes]:
    r = _R(p)
    fc = r.u8()
    ftype, delivery = fc & 3, (fc >> 2) & 3
    h: dict = {"type": ("data", "cmd", "ack", "inter-pan")[ftype], "delivery": delivery,
               "secured": bool(fc & 0x20)}
    if ftype in (0, 2) and not (ftype == 2 and fc & 0x10):
        if delivery == 3:
            h["group"] = r.u16()
        else:
            h["dst_ep"] = r.u8()
        h["cluster"], h["profile"] = r.u16(), r.u16()
        h["src_ep"] = r.u8()
    h["counter"] = r.u8()
    if fc & 0x80:  # extended header (fragmentation)
        ext = r.u8()
        if ext & 3:
            h["fragment"] = True
            r.u8()
    return h, p[r.pos :]


def _zcl_value(t: int, r: _R):
    if t in (0x10, 0x30) or 0x08 <= t <= 0x0F or 0x18 <= t <= 0x1F or 0x20 <= t <= 0x27 or t == 0x31:
        size = {0x10: 1, 0x30: 1, 0x31: 2}.get(t, (t & 7) + 1)
        v = int.from_bytes(r.take(size), "little")
        return bool(v) if t == 0x10 else v
    if 0x28 <= t <= 0x2F:
        size = (t & 7) + 1
        return int.from_bytes(r.take(size), "little", signed=True)
    if t == 0x39:
        return round(struct.unpack("<f", r.take(4))[0], 4)
    if t == 0x3A:
        return struct.unpack("<d", r.take(8))[0]
    if t in (0x41, 0x42):
        raw = r.take(r.u8())
        return raw.decode("utf-8", "replace").rstrip("\x00") if t == 0x42 else raw.hex()
    if t in (0x43, 0x44):
        raw = r.take(r.u16())
        return raw.decode("utf-8", "replace").rstrip("\x00") if t == 0x44 else raw.hex()
    if t in (0xE0, 0xE1, 0xE2, 0xEA):
        return r.u32()
    if t in (0xE8, 0xE9):
        return r.u16()
    if t == 0xF0:
        return r.ext()
    if t == 0xF1:
        return r.take(16).hex()
    raise ValueError(f"ZCL type 0x{t:02x} not decoded")


def _attr_text(cluster: int, attr: int, value) -> str:
    name = ZCL_ATTRIBUTES.get(cluster, {}).get(attr, f"0x{attr:04x}")
    if isinstance(value, str):
        return f'{name}="{value}"'
    if cluster in (0x0402, 0x0405) and attr == 0 and isinstance(value, int):
        return f"{name}={value / 100:g}{' °C' if cluster == 0x0402 else ' %'}"
    if cluster == 0x0001 and attr == 0x0021 and isinstance(value, int):
        return f"{name}={value / 2:g} %"
    if cluster == 0x0000 and attr == 0x0007 and isinstance(value, int):
        return f"{name}={POWER_SOURCES.get(value & 0x7F, value)}"
    if cluster == 0x0006 and attr == 0:
        return f"{name}={'on' if value else 'off'}"
    return f"{name}={value}"


def zcl(cluster: int, p: bytes) -> Inner:
    r = _R(p)
    fc = r.u8()
    specific = fc & 3 == 1
    from_server = bool(fc & 0x08)
    mfr = r.u16() if fc & 0x04 else None
    tsn, cmd = r.u8(), r.u8()
    cname = ZCL_CLUSTERS.get(cluster, f"cluster 0x{cluster:04x}")
    d: dict = {"cluster": cluster, "cluster_name": cname, "from_server": from_server, "specific": specific,
               "cmd": cmd, "manufacturer_code": mfr, "attributes": {}}
    if specific:
        table = (ZCL_SERVER_COMMANDS if from_server else ZCL_COMMANDS).get(cluster, {})
        name = table.get(cmd, f"cmd 0x{cmd:02x}")
        return Inner("zcl", f"ZCL {cname} {name}", d)
    name = ZCL_GLOBAL.get(cmd, f"global cmd 0x{cmd:02x}")
    d["name"] = name
    parts = []
    try:
        if cmd == 0x00:  # Read Attributes
            attrs = []
            while r.left() >= 2:
                attrs.append(r.u16())
            parts = [ZCL_ATTRIBUTES.get(cluster, {}).get(a, f"0x{a:04x}") for a in attrs]
        elif cmd in (0x01, 0x0A):  # Read Attributes Response / Report Attributes
            while r.left() >= 3:
                attr = r.u16()
                if cmd == 0x01 and r.u8() != 0:
                    continue  # unsupported attribute
                value = _zcl_value(r.u8(), r)
                d["attributes"][attr] = value
                parts.append(_attr_text(cluster, attr, value))
        elif cmd == 0x0B:  # Default Response
            c, status = r.u8(), r.u8()
            parts = [f"to cmd 0x{c:02x} status=0x{status:02x}"]
    except ValueError:
        parts.append("…")
    return Inner("zcl", f"ZCL {cname} {name}" + (" " + " ".join(parts) if parts else ""), d)


def zdo(cluster: int, p: bytes) -> Inner:
    r = _R(p)
    name = ZDO_CLUSTERS.get(cluster, f"ZDO 0x{cluster:04x}")
    d: dict = {"cluster": cluster, "name": name}
    text = f"ZDO {name}"
    if not p:
        return Inner("zdo", text, d)
    r.u8()  # transaction sequence number
    try:
        if cluster == 0x0013:  # Device_annce
            d.update(addr=r.u16(), ieee=r.ext(), capability=capability(r.u8()))
            text += f" {fmt_short(d['addr'])} {d['ieee']} ({_cap_text(d['capability'])})"
        elif cluster == 0x001F:  # Parent_annce
            d["children"] = [r.ext() for _ in range(r.u8())]
            text += f" ({len(d['children'])} children)"
        elif cluster in (0x8000, 0x8001):  # NWK_addr_rsp / IEEE_addr_rsp
            status = r.u8()
            if status == 0:
                d.update(ieee=r.ext(), addr=r.u16())
                text += f" {fmt_short(d['addr'])} = {d['ieee']}"
        elif cluster == 0x8002:  # Node_Desc_rsp
            status, addr = r.u8(), r.u16()
            if status == 0:
                desc = r.take(13)
                d.update(addr=addr, logical_type=LOGICAL_TYPES.get(desc[0] & 7),
                         manufacturer_code=struct.unpack_from("<H", desc, 3)[0])
                text += f" {fmt_short(addr)} {d['logical_type']} manufacturer=0x{d['manufacturer_code']:04x}"
        elif cluster == 0x8004:  # Simple_Desc_rsp
            status, addr, length = r.u8(), r.u16(), r.u8()
            if status == 0 and length:
                ep, profile, dev_id, _ver = r.u8(), r.u16(), r.u16(), r.u8()
                inc = [r.u16() for _ in range(r.u8())]
                out = [r.u16() for _ in range(r.u8())]
                d.update(addr=addr, endpoint=ep, profile=profile, device_id=dev_id, in_clusters=inc, out_clusters=out)
                text += f" {fmt_short(addr)} ep{ep} profile=0x{profile:04x} device=0x{dev_id:04x}"
        elif cluster == 0x8031:  # Mgmt_Lqi_rsp
            status = r.u8()
            if status == 0:
                total, start, count = r.u8(), r.u8(), r.u8()
                entries = []
                for _ in range(count):
                    epid, ieee, addr = r.ext(), r.ext(), r.u16()
                    b1, b2, depth, lqi = r.u8(), r.u8(), r.u8(), r.u8()
                    entries.append({
                        "epid": epid, "ieee": ieee, "addr": addr,
                        "type": LOGICAL_TYPES.get(b1 & 3, "unknown"),
                        "rx_on_when_idle": {0: False, 1: True}.get((b1 >> 2) & 3),
                        "relationship": RELATIONSHIPS.get((b1 >> 4) & 7, "none"),
                        "depth": depth, "lqi": lqi,
                    })
                d.update(total=total, start=start, entries=entries)
                text += f" {start + 1}-{start + count}/{total}: " + ", ".join(
                    f"{fmt_short(e['addr'])} {e['relationship']} lqi{e['lqi']}" for e in entries
                )
        elif cluster == 0x8032:  # Mgmt_Rtg_rsp
            status = r.u8()
            if status == 0:
                total, start, count = r.u8(), r.u8(), r.u8()
                routes = []
                for _ in range(count):
                    dst, st, nxt = r.u16(), r.u8(), r.u16()
                    routes.append({"dst": dst, "status": st & 7, "next_hop": nxt})
                d.update(total=total, start=start, routes=routes)
                text += f" {start + 1}-{start + count}/{total}: " + ", ".join(
                    f"{fmt_short(x['dst'])} via {fmt_short(x['next_hop'])}" for x in routes if x["status"] == 0
                )
        elif cluster == 0x0036:  # Mgmt_Permit_Joining_req
            d["duration"] = r.u8()
            text += f" {d['duration']} s"
        elif cluster == 0x0034:  # Mgmt_Leave_req
            d["ieee"] = r.ext()
            text += f" {d['ieee']}"
    except ValueError:
        text += " (truncated)"
    return Inner("zdo", text, d)


def describe(n, plaintext: bytes) -> Inner:
    """Summary and fields of a decrypted NWK payload (n: mac.NwkFrame)."""
    try:
        if n.ftype == 1:
            return nwk_command(plaintext)
        h, payload = aps(plaintext)
    except ValueError:
        return Inner("error", "(truncated)")
    if h["type"] == "cmd":
        return Inner("aps_encrypted" if h["secured"] else "aps_cmd",
                     "APS Cmd (APS encrypted)" if h["secured"] else "APS Cmd", h)
    if h["type"] == "ack":
        return Inner("aps_ack", f"APS Ack cnt={h['counter']}", h)
    if h["secured"]:
        return Inner("aps_encrypted", "APS Data (APS encrypted)", h)
    if h.get("fragment") or "cluster" not in h:
        return Inner("aps_data", "APS Data (fragment)", h)
    try:
        inner = zdo(h["cluster"], payload) if h["profile"] == 0 else zcl(h["cluster"], payload)
    except ValueError:
        inner = Inner("aps_data", f"APS Data cluster=0x{h['cluster']:04x} (truncated)")
    inner.data["aps"] = h
    return inner
