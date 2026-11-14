"""Network map: turns decoded frames into Zigbee networks, devices and links.

Everything here comes from the unencrypted parts of the frames, so it works
without the network key:

* MAC header: PAN ID, one-hop sender and receiver (a unicast MAC frame proves a
  radio link between the two), ACKs (the receiver heard it), Data Request polls
  (end device -> parent), association, beacons (router/coordinator, depth,
  extended PAN ID, permit join).
* NWK header: end-to-end source and destination, source routes (relay lists),
  IEEE addresses, and the auxiliary security header, whose source address is
  the IEEE address of the device that sent this hop. That maps short addresses
  to IEEE addresses (vendor OUI) for every device that transmits.
* Broadcast relays: every router decrements the NWK radius before it
  rebroadcasts, so a relay sent with radius R-1 of a broadcast originated with
  radius R was heard straight from the originator - a radio link - and in
  general R minus the relay radius is the relayer's hop count from the
  originator (e.g. hops to the coordinator for its many-to-one route requests).
* Patterns: a NWK command broadcast to all routers with radius 1 is a Link
  Status (routers only); a frame relayed on behalf of another device comes from
  a router; short address 0x0000 is the coordinator.
"""

from __future__ import annotations

import json
import re
import struct
import threading
import time
from collections import deque
from pathlib import Path

from . import mac

ACK_WINDOW = 0.010  # an ACK follows its frame within ~1 ms; allow timestamp slop
BROADCAST_WINDOW = 3.0  # relays (with passive-ack retries) follow the original within ~1 s
LOG_LENGTH = 200
EVENT_LENGTH = 100
EWMA = 0.3

# Role ranks: higher wins; router evidence overrides end-device evidence
# (a router may poll its parent while joining).
ROLES = ("unknown", "end_device", "router", "coordinator")

# Organisationally unique identifiers common in Zigbee devices (hint only).
OUI = {
    "00:0b:57": "Silicon Labs",
    "00:0d:6f": "Silicon Labs (Ember)",
    "00:12:4b": "Texas Instruments",
    "00:13:a2": "Digi International",
    "00:15:8d": "Xiaomi / Lumi",
    "00:17:88": "Philips / Signify",
    "00:1f:ee": "ubisys",
    "00:21:2e": "dresden elektronik",
    "54:ef:44": "Lumi United",
    "84:18:26": "OSRAM / LEDVANCE",
    "90:fd:9f": "Silicon Labs",
    "a4:c1:38": "Telink",
}


def vendor(ieee: str | None) -> str | None:
    return OUI.get(ieee[:8]) if ieee else None


def normalize_ieee(text: str) -> str | None:
    """'0x00178801...', '00:17:88:...', '00-17-...' -> '00:17:88:01:...' (MSB first)."""
    h = re.sub(r"[^0-9a-fA-F]", "", text[2:] if text.lower().startswith("0x") else text)
    if len(h) != 16:
        return None
    h = h.lower()
    return ":".join(h[i : i + 2] for i in range(0, 16, 2))


def load_names(path: str | Path) -> dict[str, str]:
    """Friendly device names, keyed by IEEE address ('aa:bb:..') or 'PAN/short'
    ('0x1a62/0x711f').

    Accepts a JSON object ({"00:17:88:01:02:03:04:05": "Kitchen lamp", ...}),
    a zigbee2mqtt configuration.yaml / devices.yaml (friendly_name entries) or a
    zigbee2mqtt database.db (manufacturer + model).
    """
    text = Path(path).read_text(encoding="utf-8")
    names: dict[str, str] = {}

    def put(key: str, name: str) -> None:
        key = key.strip().strip("'\"")
        ieee = normalize_ieee(key)
        if ieee:
            names[ieee] = name
        elif "/" in key:
            pan, short = key.split("/", 1)
            try:
                names[f"{int(pan, 16):04x}/{int(short, 16):04x}"] = name
            except ValueError:
                pass

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        for k, v in data.items():
            name = v.get("friendly_name") or v.get("name") if isinstance(v, dict) else v
            if isinstance(name, str):
                put(k, name)
        return names
    if '"ieeeAddr"' in text:  # zigbee2mqtt database.db: one JSON object per line
        for line in text.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") == "Coordinator":
                put(d.get("ieeeAddr", ""), "Coordinator")
            elif d.get("ieeeAddr"):
                label = " ".join(x for x in (d.get("manufName"), d.get("modelId")) if x)
                if label:
                    put(d["ieeeAddr"], label)
        return names
    # YAML: '0x00178801...':  followed by an indented  friendly_name: ...
    current = None
    for line in text.splitlines():
        m = re.match(r"^\s*['\"]?(0x[0-9a-fA-F]{16})['\"]?\s*:\s*$", line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r"^\s+friendly_name\s*:\s*['\"]?(.*?)['\"]?\s*$", line)
        if m and current:
            put(current, m.group(1))
            current = None
    return names


class Node:
    def __init__(self, nid: str, pan: int, short: int | None, ieee: str | None, now: float):
        self.id = nid
        self.pan = pan
        self.short = short
        self.ieee = ieee
        self.evidence: dict[str, str] = {}  # reason -> role
        self.tx = 0  # frames we heard it transmit (including ACKs)
        self.rx = 0  # frames addressed to it
        self.rssi: float | None = None
        self.snr: float | None = None
        self.cfo_khz: float | None = None
        self.lqi: float | None = None
        self.channel: int | None = None
        self.depth: int | None = None
        self.frame_counter: int | None = None
        self.permit_join: bool | None = None
        self.rx_on_when_idle: bool | None = None
        self.first_seen = now
        self.last_seen = now
        self.last_tx: float | None = None
        self.hops: dict[str, int] = {}  # originator id -> hop count (from broadcast relays)

    @property
    def role(self) -> str:
        roles = set(self.evidence.values())
        for r in reversed(ROLES):
            if r in roles:
                return r
        return "unknown"

    def add_role(self, role: str, reason: str) -> None:
        self.evidence.setdefault(reason, role)

    def heard(self, wall: float, rssi, snr, cfo_hz, lqi, channel) -> None:
        self.tx += 1
        self.last_tx = wall
        self.last_seen = max(self.last_seen, wall)
        if channel is not None:
            self.channel = channel

        def avg(old, new):
            return new if old is None else old + EWMA * (new - old)

        if rssi is not None:
            self.rssi = avg(self.rssi, rssi)
        if snr is not None:
            self.snr = avg(self.snr, snr)
        if cfo_hz is not None:
            self.cfo_khz = avg(self.cfo_khz, cfo_hz / 1e3)
        if lqi is not None:
            self.lqi = avg(self.lqi, lqi)

    def absorb(self, other: "Node") -> None:
        """Merge the statistics of another record of the same device."""
        for reason, role in other.evidence.items():
            self.evidence.setdefault(reason, role)
        self.tx += other.tx
        self.rx += other.rx
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        newer = (other.last_tx or 0) > (self.last_tx or 0)
        for attr in ("rssi", "snr", "cfo_khz", "lqi", "channel", "depth", "permit_join", "rx_on_when_idle"):
            if getattr(self, attr) is None or (newer and getattr(other, attr) is not None):
                setattr(self, attr, getattr(other, attr))
        if other.frame_counter is not None:
            self.frame_counter = max(self.frame_counter or 0, other.frame_counter)
        if newer:
            self.last_tx = other.last_tx
        for origin, h in other.hops.items():
            self.hops[origin] = min(h, self.hops.get(origin, h))
        self.ieee = self.ieee or other.ieee


class Link:
    """Undirected edge between two devices of one PAN."""

    def __init__(self, a: str, b: str, now: float):
        self.a, self.b = a, b
        self.frames = {a: 0, b: 0}  # unicast MAC frames sent by that end
        self.ack_requests = 0
        self.acked = 0
        self.route = 0  # times seen in a source route (inferred link)
        self.relay = 0  # broadcasts one end relayed straight from the other (radius R-1)
        self.parent: str | None = None  # id of the child when this is an end device's parent link
        self.first_seen = now
        self.last_seen = now


class Network:
    def __init__(self, pan: int, now: float):
        self.pan = pan
        self.channels: dict[int, float] = {}
        self.epid: str | None = None
        self.stack_profile: int | None = None
        self.permit_join_until: float | None = None
        self.zigbee = False
        self.security: bool | None = None
        self.key_seq: int | None = None
        self.frames = 0
        self.green_power = 0
        self.inter_pan = 0
        self.first_seen = now
        self.last_seen = now


class ChannelStats:
    def __init__(self):
        self.frames = 0
        self.bad = 0
        self.beacon_requests = 0
        self.noise_dbfs: float | None = None
        self.last: float | None = None


def _fmt_short(v: int | None) -> str | None:
    return None if v is None else f"0x{v:04x}"


class NetworkMap:
    """Thread-safe aggregate of everything heard. Feed it with add() / add_frame();
    snapshot() returns a JSON-serialisable view for the web UI."""

    def __init__(self, names: dict[str, str] | None = None, live: bool = True):
        self.names = names or {}
        self.live = live
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "lock", threading.Lock()):
            self.version = getattr(self, "version", 0) + 1
            self.networks: dict[int, Network] = {}
            self.nodes: dict[str, Node] = {}
            self.links: dict[tuple[str, str], Link] = {}
            self.flows: dict[tuple[str, str], list] = {}  # (src, dst) -> [count, first, last]
            self.channels: dict[int, ChannelStats] = {}
            self._ieee: dict[tuple[int, str], str] = {}
            self._alias: dict[str, str] = {}
            self._pending_ack: tuple | None = None
            self._bcast: dict[tuple[int, int, int], tuple[int, float]] = {}
            self.log: deque = deque(maxlen=LOG_LENGTH)
            self.events: deque = deque(maxlen=EVENT_LENGTH)
            self.total = self.bad = self.unattributed = 0
            self.clock = 0.0

    # ------------------------------------------------------------ input
    def add_frame(self, f, wall: float) -> None:
        """Add a demod.Frame received at wall-clock time `wall`."""
        self.add(
            f.psdu,
            wall,
            fcs_ok=f.fcs_ok,
            channel=f.channel,
            rssi=f.rssi_dbfs,
            snr=f.snr_db,
            cfo_hz=f.cfo_hz,
            lqi=f.lqi,
        )

    def add(self, psdu: bytes, wall: float, *, fcs_ok: bool = True, channel=None, rssi=None, snr=None,
            cfo_hz=None, lqi=None) -> None:
        with self.lock:
            self._add(psdu, wall, fcs_ok, channel, (rssi, snr, cfo_hz, lqi, channel))
            self.version += 1

    def channel_status(self, channel: int, noise_dbfs: float | None) -> None:
        with self.lock:
            self._chan(channel).noise_dbfs = noise_dbfs
            self.version += 1

    # --------------------------------------------------------- internals
    def _chan(self, ch: int) -> ChannelStats:
        if ch not in self.channels:
            self.channels[ch] = ChannelStats()
        return self.channels[ch]

    def _event(self, wall: float, text: str, node: str | None = None) -> None:
        self.events.append({"t": wall, "text": text, "node": node})

    def _get(self, nid: str | None) -> Node | None:
        while nid in self._alias:
            nid = self._alias[nid]
        return self.nodes.get(nid) if nid else None

    def _network(self, pan: int, channel, wall: float) -> Network:
        net = self.networks.get(pan)
        if net is None:
            net = self.networks[pan] = Network(pan, wall)
            where = f" on channel {channel}" if channel else ""
            self._event(wall, f"Network 0x{pan:04x} discovered{where}")
        net.last_seen = max(net.last_seen, wall)
        if channel is not None:
            net.channels[channel] = wall
        return net

    def _node(self, pan: int, addr: str | int, wall: float) -> Node:
        """Node for a short address (int or '0x....') or an IEEE address ('aa:..')."""
        if isinstance(addr, str) and ":" in addr:
            nid = self._ieee.get((pan, addr))
            node = self._get(nid)
            if node is None:
                nid = f"{pan:04x}/{addr}"
                node = self._get(nid)
            if node is None:
                node = self.nodes[nid] = Node(nid, pan, None, addr, wall)
                self._ieee[(pan, addr)] = nid
                self._new_node_event(node, wall)
        else:
            short = int(addr, 16) if isinstance(addr, str) else addr
            nid = f"{pan:04x}/{short:04x}"
            node = self._get(nid)
            if node is None:
                node = self.nodes[nid] = Node(nid, pan, short, None, wall)
                if short == 0:
                    node.add_role("coordinator", "short address 0x0000 (coordinator / trust center)")
                self._new_node_event(node, wall)
        node.last_seen = max(node.last_seen, wall)
        return node

    def _new_node_event(self, node: Node, wall: float) -> None:
        addr = _fmt_short(node.short) or node.ieee
        self._event(wall, f"New device {addr} in 0x{node.pan:04x}", node.id)

    def _learn_ieee(self, node: Node, ieee: str, wall: float) -> None:
        """node (known by short address) has IEEE address `ieee`: merge any other
        record of the same device (IEEE-only, or an older short address)."""
        if node.short is None:
            return
        if node.ieee and node.ieee != ieee:  # short address reassigned to another device
            self._ieee.pop((node.pan, node.ieee), None)
        node.ieee = ieee
        other = self._get(self._ieee.get((node.pan, ieee)))
        self._ieee[(node.pan, ieee)] = node.id
        if other is None or other is node:
            return
        if other.short is not None and other.short != node.short:
            self._event(wall, f"{ieee} moved from {_fmt_short(other.short)} to {_fmt_short(node.short)}", node.id)
        node.absorb(other)
        del self.nodes[other.id]
        self._alias[other.id] = node.id
        for key in [k for k in self.links if other.id in k]:
            link = self.links.pop(key)
            ends = [node.id if e == other.id else e for e in key]
            if ends[0] == ends[1]:
                continue
            target = self._link_between(self.nodes[ends[0]], self.nodes[ends[1]], link.first_seen)
            for end, n in link.frames.items():
                end = node.id if end == other.id else end
                target.frames[end] = target.frames.get(end, 0) + n
            target.ack_requests += link.ack_requests
            target.acked += link.acked
            target.route += link.route
            target.relay += link.relay
            target.parent = target.parent or (node.id if link.parent == other.id else link.parent)
            target.first_seen = min(target.first_seen, link.first_seen)
            target.last_seen = max(target.last_seen, link.last_seen)
        for key in [k for k in self.flows if other.id in k]:
            flow = self.flows.pop(key)
            nk = tuple(node.id if e == other.id else e for e in key)
            if nk[0] == nk[1]:
                continue
            cur = self.flows.setdefault(nk, [0, flow[1], flow[2]])
            cur[0] += flow[0]
            cur[1] = min(cur[1], flow[1])
            cur[2] = max(cur[2], flow[2])

    def _link_between(self, a: Node, b: Node, wall: float) -> Link:
        key = (a.id, b.id) if a.id < b.id else (b.id, a.id)
        link = self.links.get(key)
        if link is None:
            link = self.links[key] = Link(key[0], key[1], wall)
        link.last_seen = max(link.last_seen, wall)
        return link

    def _add(self, psdu: bytes, wall: float, fcs_ok: bool, channel, tx) -> None:
        self.clock = max(self.clock, wall)
        self.total += 1
        cs = self._chan(channel) if channel is not None else None
        if not fcs_ok:
            self.bad += 1
            if cs:
                cs.bad += 1
            return
        if cs:
            cs.frames += 1
            cs.last = wall
        m = mac.parse(psdu)
        self.log.append({"t": wall, "ch": channel, "rssi": tx[0], "text": m.summary()})
        if m.error:
            return
        if m.frame_type == 2:
            self._ack(m, wall, tx)
            return
        pan = next((p for p in (m.src_pan, m.dst_pan) if p is not None and p != 0xFFFF), None)
        if pan is None:
            self.unattributed += 1
            if m.frame_type == 3 and m.payload[:1] == b"\x07" and cs:
                cs.beacon_requests += 1
            self._pending_ack = None
            return
        net = self._network(pan, channel, wall)
        net.frames += 1
        src = self._node(pan, m.src, wall) if m.src else None
        dst = self._node(pan, m.dst, wall) if m.dst and m.dst != "0xffff" else None
        if src:
            src.heard(wall, *tx)
        if dst:
            dst.rx += 1
        link = None
        if src and dst and src is not dst:
            link = self._link_between(src, dst, wall)
            link.frames[src.id] = link.frames.get(src.id, 0) + 1
            if m.ack_request:
                link.ack_requests += 1
        self._pending_ack = (m.seq, src.id, dst.id, wall) if (link and m.ack_request) else None

        if m.frame_type == 0 and src:
            self._beacon(m, net, src, wall)
        elif m.frame_type == 3 and m.payload:
            self._mac_command(m, pan, src, dst, link, wall)
        elif m.frame_type == 1 and m.payload:
            self._nwk(m, net, src, dst, link, wall)

    def _ack(self, m, wall: float, tx) -> None:
        p, self._pending_ack = self._pending_ack, None
        if not p or m.seq != p[0] or not 0 <= wall - p[3] <= ACK_WINDOW:
            return
        src, dst = self._get(p[1]), self._get(p[2])
        if not src or not dst or src is dst:
            return
        dst.heard(wall, *tx)  # the ACK is transmitted by the receiver of the frame
        self._link_between(src, dst, wall).acked += 1

    def _beacon(self, m, net: Network, src: Node, wall: float) -> None:
        try:
            b = mac.decode_beacon(m.payload)
        except ValueError:
            return
        src.add_role("router", "sends beacons")
        if b.pan_coordinator:
            src.add_role("coordinator", "beacon with the PAN coordinator flag")
        src.permit_join = b.assoc_permit
        if b.assoc_permit:
            if not net.permit_join_until or net.permit_join_until < wall:
                self._event(wall, f"Permit join open in 0x{net.pan:04x} (beacon from {_fmt_short(src.short)})", src.id)
            net.permit_join_until = wall + 60
        if b.zigbee:
            net.zigbee = True
            net.epid = b.epid
            net.stack_profile = b.stack_profile
            src.depth = b.depth

    def _mac_command(self, m, pan: int, src: Node | None, dst: Node | None, link: Link | None, wall: float) -> None:
        cmd = m.payload[0]
        if cmd == 0x04 and src and src.short is not None:
            # Data Request from a short address: an end device polling its parent.
            # (Joining devices of any kind poll with their IEEE address.)
            src.add_role("end_device", "polls its parent (MAC Data Request)")
            if dst and link:
                dst.add_role("router", "parent of an end device")
                link.parent = src.id
        elif cmd == 0x01 and src and len(m.payload) >= 2:  # Association Request
            cap = m.payload[1]
            src.rx_on_when_idle = bool(cap & 0x08)
            if cap & 0x02:
                src.add_role("router", "joined as a router (association request)")
            else:
                src.add_role("end_device", "joined as an end device (association request)")
            self._event(wall, f"{src.ieee or _fmt_short(src.short)} asks to join 0x{pan:04x}", src.id)
        elif cmd == 0x02 and dst and dst.ieee and len(m.payload) >= 4:  # Association Response
            short, status = struct.unpack_from("<HB", m.payload, 1)
            if status == 0 and short < 0xFFF8:
                node = self._node(pan, short, wall)
                self._learn_ieee(node, dst.ieee, wall)
                self._event(wall, f"{dst.ieee} joined 0x{pan:04x} as 0x{short:04x}", node.id)

    def _nwk(self, m, net: Network, src: Node | None, dst: Node | None, link: Link | None, wall: float) -> None:
        try:
            n = mac.decode_nwk(m.payload)
        except ValueError:
            return
        if n == mac.NWK_GREEN_POWER:
            net.green_power += 1
            return
        if n == mac.NWK_INTER_PAN:
            net.inter_pan += 1
            if src:
                src.add_role("unknown", "sends Inter-PAN frames (e.g. Touchlink)")
            return
        if not isinstance(n, mac.NwkFrame):
            return
        pan = net.pan
        net.zigbee = True
        if n.secured:
            net.security = True
            if n.key_seq is not None:
                net.key_seq = n.key_seq
        elif net.security is None and n.ftype == 0:
            net.security = False
        # The aux security header names the device that sent this hop.
        if n.sec_src and src and src.short is not None:
            self._learn_ieee(src, n.sec_src, wall)
        if n.frame_counter is not None and src:
            src.frame_counter = max(src.frame_counter or 0, n.frame_counter)
        nsrc = self._node(pan, n.src, wall)
        if n.src_ieee:
            self._learn_ieee(nsrc, n.src_ieee, wall)
        ndst = self._node(pan, n.dst, wall) if n.dst < 0xFFF8 else None
        if ndst and n.dst_ieee:
            self._learn_ieee(ndst, n.dst_ieee, wall)
        src, dst = self._get(src.id) if src else None, self._get(dst.id) if dst else None
        if src and src.short is not None and src.short != n.src:
            src.add_role("router", "relays frames for other devices")
        if dst and dst.short is not None and ndst is not None and dst.short != n.dst:
            dst.add_role("router", "forwards frames to other devices")
        if src and src.short == n.src:
            if n.ftype == 1 and n.dst == 0xFFFC and n.radius == 1:
                src.add_role("router", "sends Link Status (NWK command to all routers, radius 1)")
            if n.end_device_initiator:
                src.add_role("end_device", "end device initiator flag in the NWK header")
                if dst and link:
                    link.parent = src.id
        if n.dst >= 0xFFF8 and src and src.short is not None:
            self._broadcast(pan, n, src, wall)
        if n.relay_index is not None and n.relays:
            path = [n.src, *reversed(n.relays), n.dst]
            for r in n.relays:
                self._node(pan, r, wall).add_role("router", "relay in a source route")
            for a, b in zip(path, path[1:]):
                if a != b and a < 0xFFF8 and b < 0xFFF8:
                    self._link_between(self._node(pan, a, wall), self._node(pan, b, wall), wall).route += 1
        nsrc = self._get(nsrc.id)
        ndst = self._get(ndst.id) if ndst else None
        if nsrc and ndst and nsrc is not ndst:
            flow = self.flows.setdefault((nsrc.id, ndst.id), [0, wall, wall])
            flow[0] += 1
            flow[2] = wall

    def _broadcast(self, pan: int, n, sender: Node, wall: float) -> None:
        key = (pan, n.src, n.seq)
        if sender.short == n.src:  # the originator's own transmission
            if len(self._bcast) > 4096:
                self._bcast = {k: v for k, v in self._bcast.items() if wall - v[1] < BROADCAST_WINDOW}
            self._bcast[key] = (n.radius, wall)
            return
        orig = self._bcast.get(key)
        if orig is None or not 0 <= wall - orig[1] < BROADCAST_WINDOW or n.radius >= orig[0]:
            return
        hops = orig[0] - n.radius
        origin = self._node(pan, n.src, wall)
        sender.hops[origin.id] = min(hops, sender.hops.get(origin.id, hops))
        if hops == 1:
            self._link_between(origin, sender, wall).relay += 1

    # ----------------------------------------------------------- output
    def snapshot(self) -> dict:
        with self.lock:
            now = time.time() if self.live else self.clock
            nodes = []
            per_net: dict[int, dict[str, int]] = {}
            for n in self.nodes.values():
                role = n.role
                counts = per_net.setdefault(n.pan, {"coordinator": 0, "router": 0, "end_device": 0, "unknown": 0})
                counts[role] += 1
                name = self.names.get(n.ieee or "") or (
                    self.names.get(f"{n.pan:04x}/{n.short:04x}") if n.short is not None else None
                )
                nodes.append(
                    {
                        "id": n.id,
                        "pan": n.pan,
                        "short": _fmt_short(n.short),
                        "ieee": n.ieee,
                        "vendor": vendor(n.ieee),
                        "name": name,
                        "role": role,
                        "evidence": [{"role": r, "reason": why} for why, r in n.evidence.items()],
                        "heard": n.tx > 0,
                        "tx": n.tx,
                        "rx": n.rx,
                        "rssi": n.rssi,
                        "snr": n.snr,
                        "cfo_khz": n.cfo_khz,
                        "lqi": n.lqi,
                        "channel": n.channel,
                        "depth": n.depth,
                        "frame_counter": n.frame_counter,
                        "hops": n.hops,
                        "permit_join": n.permit_join,
                        "rx_on_when_idle": n.rx_on_when_idle,
                        "first_seen": n.first_seen,
                        "last_seen": n.last_seen,
                        "last_tx": n.last_tx,
                    }
                )
            links = [
                {
                    "a": k[0],
                    "b": k[1],
                    "ab": l.frames.get(k[0], 0),
                    "ba": l.frames.get(k[1], 0),
                    "ack_requests": l.ack_requests,
                    "acked": l.acked,
                    "route": l.route,
                    "relay": l.relay,
                    "parent": l.parent,
                    "kind": "parent" if l.parent else ("radio" if sum(l.frames.values()) or l.relay else "route"),
                    "first_seen": l.first_seen,
                    "last_seen": l.last_seen,
                }
                for k, l in self.links.items()
            ]
            networks = []
            for pan, net in sorted(self.networks.items(), key=lambda kv: kv[1].first_seen):
                coord = self.nodes.get(f"{pan:04x}/0000")
                networks.append(
                    {
                        "pan": pan,
                        "id": f"{pan:04x}",
                        "channels": sorted(net.channels),
                        "channel": max(net.channels, key=net.channels.get) if net.channels else None,
                        "epid": net.epid,
                        "stack_profile": mac.STACK_PROFILES.get(net.stack_profile) if net.stack_profile else None,
                        "zigbee": net.zigbee,
                        "security": net.security,
                        "key_seq": net.key_seq,
                        "permit_join": bool(net.permit_join_until and net.permit_join_until > now),
                        "frames": net.frames,
                        "green_power": net.green_power,
                        "inter_pan": net.inter_pan,
                        "coordinator": coord.id if coord else None,
                        "first_seen": net.first_seen,
                        "last_seen": net.last_seen,
                        "nodes": sum(per_net.get(pan, {}).values()),
                        "roles": per_net.get(pan, {}),
                    }
                )
            return {
                "version": self.version,
                "now": now,
                "live": self.live,
                "totals": {"frames": self.total, "bad": self.bad, "unattributed": self.unattributed},
                "channels": {
                    str(ch): {
                        "frames": c.frames,
                        "bad": c.bad,
                        "beacon_requests": c.beacon_requests,
                        "noise_dbfs": c.noise_dbfs,
                        "last": c.last,
                    }
                    for ch, c in sorted(self.channels.items())
                },
                "networks": networks,
                "nodes": nodes,
                "links": links,
                "flows": [
                    {"src": k[0], "dst": k[1], "count": v[0], "first_seen": v[1], "last_seen": v[2]}
                    for k, v in self.flows.items()
                ],
                "log": list(self.log),
                "events": list(self.events),
            }
