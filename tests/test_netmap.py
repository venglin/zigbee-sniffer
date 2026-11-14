"""Network map: frame aggregation, PCAP reading, device names and the web server."""

import http.client
import io
import json
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from zbdemod import mac
from zbdemod.netmap import NetworkMap, load_names
from zbdemod.pcap import PcapWriter, read_pcap
from zbdemod.webmap import Control, start_server

ROOT = Path(__file__).resolve().parent.parent
PAN = 0x4242
P = f"{PAN:04x}"
COORD = "02:00:00:00:00:00:00:01"
ROUTER = "02:00:00:00:00:00:00:02"
TI_DEVICE = "00:12:4b:00:00:00:00:99"


# ------------------------------------------------------------- frame kit
def ext(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))[::-1]  # on air: little endian


def nwk(ftype, dst, src, radius, seq, *, sec_src=None, src_ieee=None, relays=None, edi=False):
    fc = ftype | (2 << 2)
    if src_ieee:
        fc |= 0x1000
    if relays is not None:
        fc |= 0x0400
    if edi:
        fc |= 0x2000
    if sec_src:
        fc |= 0x0200
    out = struct.pack("<HHHBB", fc, dst, src, radius, seq)
    if src_ieee:
        out += ext(src_ieee)
    if relays is not None:
        out += bytes([len(relays), len(relays) - 1]) + b"".join(struct.pack("<H", r) for r in relays)
    if sec_src:
        out += bytes([0x28]) + struct.pack("<I", 100 + seq) + ext(sec_src) + b"\x00"
    return out + b"\x5a" * 8


def data(seq, dst, src, payload, ack=True):
    return mac.add_fcs(struct.pack("<HBHHH", 0x8841 | (0x20 if ack else 0), seq, PAN, dst, src) + payload)


def ack(seq):
    return mac.add_fcs(bytes([0x02, 0x00, seq]))


def cmd(seq, dst, src, payload):
    return mac.add_fcs(struct.pack("<HBHHH", 0x8863, seq, PAN, dst, src) + payload)


def assoc_request(seq, dst, ieee, capability):
    fc = 0x0003 | 0x0020 | 0x0800 | 0xC000  # cmd, ack, dst short, src ext, no PAN compression
    return mac.add_fcs(struct.pack("<HBHHH", fc, seq, PAN, dst, 0xFFFF) + ext(ieee) + bytes([0x01, capability]))


def assoc_response(seq, dst_ieee, src_ieee, short):
    fc = 0x0003 | 0x0020 | 0x0040 | 0x0C00 | 0xC000  # cmd, ack, PAN compression, ext/ext
    body = struct.pack("<HBH", fc, seq, PAN) + ext(dst_ieee) + ext(src_ieee)
    return mac.add_fcs(body + bytes([0x02]) + struct.pack("<HB", short, 0))


def build(frames, **kw) -> dict:
    m = NetworkMap(live=False, **kw)
    for t, psdu, rssi in frames:
        m.add(psdu, t, channel=15, rssi=rssi)
    return m.snapshot()


def nodes(snap):
    return {n["id"]: n for n in snap["nodes"]}


def link(snap, a, b):
    key = tuple(sorted((f"{P}/{a:04x}", f"{P}/{b:04x}")))
    return next((x for x in snap["links"] if (x["a"], x["b"]) == key), None)


# ----------------------------------------------------------------- model
def test_unicast_ack_makes_a_confirmed_link_and_times_the_receiver():
    snap = build(
        [
            (100.000, data(1, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 1, sec_src=COORD)), -30.0),
            (100.002, ack(1), -25.0),
            (100.100, data(2, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 2, sec_src=COORD)), -30.0),
            (100.600, ack(2), -25.0),  # too late: not this frame's ACK
        ]
    )
    n = nodes(snap)
    coord, dev = n[f"{P}/0000"], n[f"{P}/0001"]
    assert coord["role"] == "coordinator" and coord["ieee"] == COORD and coord["tx"] == 2
    assert dev["heard"] and dev["tx"] == 1 and dev["rssi"] == pytest.approx(-25.0) and dev["rx"] == 2
    lk = link(snap, 0, 1)
    assert lk["kind"] == "radio" and lk["acked"] == 1 and lk["ack_requests"] == 2
    assert (lk["ab"], lk["ba"]) == (2, 0)
    assert snap["flows"] == [
        {"src": f"{P}/0000", "dst": f"{P}/0001", "count": 2, "first_seen": 100.0, "last_seen": 100.1}
    ]
    assert snap["networks"][0]["security"] is True and snap["networks"][0]["channels"] == [15]


def test_roles_from_polls_link_status_and_end_device_flag():
    snap = build(
        [
            (1.0, cmd(1, 0x0001, 0x1001, bytes([0x04])), -40.0),  # Data Request: end device -> parent
            (2.0, data(2, 0xFFFF, 0x0002, nwk(1, 0xFFFC, 0x0002, 1, 5, sec_src=ROUTER), ack=False), -35.0),
            (3.0, data(3, 0x0001, 0x1002, nwk(0, 0x0000, 0x1002, 30, 6, edi=True)), -50.0),
        ]
    )
    n = nodes(snap)
    assert n[f"{P}/1001"]["role"] == "end_device"
    assert n[f"{P}/0001"]["role"] == "router"  # parent; also forwards 0x1002's frame
    assert n[f"{P}/0002"]["role"] == "router"  # Link Status
    assert n[f"{P}/1002"]["role"] == "end_device"
    assert link(snap, 0x0001, 0x1001)["parent"] == f"{P}/1001"
    assert link(snap, 0x0001, 0x1002)["kind"] == "parent"
    assert n[f"{P}/0002"]["ieee"] == ROUTER
    roles = snap["networks"][0]["roles"]
    assert roles["end_device"] == 2 and roles["router"] == 2


def test_broadcast_relay_radius_gives_links_and_hop_counts():
    orig = nwk(1, 0xFFFC, 0x0000, 10, 9, src_ieee=COORD)
    snap = build(
        [
            (0.000, data(1, 0xFFFF, 0x0000, orig, ack=False), -30.0),
            (0.010, data(2, 0xFFFF, 0x0003, nwk(1, 0xFFFC, 0x0000, 9, 9, src_ieee=COORD), ack=False), -31.0),
            (0.020, data(3, 0xFFFF, 0x0004, nwk(1, 0xFFFC, 0x0000, 8, 9, src_ieee=COORD), ack=False), -32.0),
            (9.000, data(4, 0xFFFF, 0x0005, nwk(1, 0xFFFC, 0x0000, 9, 9, src_ieee=COORD), ack=False), -33.0),
        ]
    )
    n = nodes(snap)
    assert link(snap, 0x0000, 0x0003)["relay"] == 1 and link(snap, 0x0000, 0x0003)["kind"] == "radio"
    assert n[f"{P}/0003"]["hops"] == {f"{P}/0000": 1}
    assert link(snap, 0x0000, 0x0004) is None and n[f"{P}/0004"]["hops"] == {f"{P}/0000": 2}
    assert link(snap, 0x0000, 0x0005) is None and n[f"{P}/0005"]["hops"] == {}  # outside the window
    assert all(n[f"{P}/{a:04x}"]["role"] == "router" for a in (3, 4, 5))  # they relay


def test_source_route_relays_become_inferred_links():
    frame = data(1, 0x0005, 0x0000, nwk(0, 0x0007, 0x0000, 30, 1, relays=[0x0006, 0x0005]))
    snap = build([(1.0, frame, -30.0)])
    assert link(snap, 0x0000, 0x0005)["kind"] == "radio" and link(snap, 0x0000, 0x0005)["route"] == 1
    assert link(snap, 0x0005, 0x0006)["kind"] == "route"
    assert link(snap, 0x0006, 0x0007)["kind"] == "route"
    assert link(snap, 0x0000, 0x0007) is None
    n = nodes(snap)
    assert n[f"{P}/0005"]["role"] == n[f"{P}/0006"]["role"] == "router"
    assert not n[f"{P}/0007"]["heard"]


def test_association_merges_the_ieee_record_into_the_new_short_address():
    snap = build(
        [
            (1.0, assoc_request(1, 0x0000, TI_DEVICE, 0x8E), -45.0),  # FFD, rx on when idle
            (1.001, ack(1), -30.0),
            (1.2, assoc_response(2, TI_DEVICE, COORD, 0x0042), -30.0),
            (2.0, data(3, 0x0000, 0x0042, nwk(0, 0x0000, 0x0042, 30, 1, sec_src=TI_DEVICE)), -44.0),
        ]
    )
    n = nodes(snap)
    dev = n[f"{P}/0042"]
    assert f"{P}/{TI_DEVICE}" not in n
    assert dev["ieee"] == TI_DEVICE and dev["vendor"] == "Texas Instruments"
    assert dev["role"] == "router" and dev["rx_on_when_idle"] is True
    assert dev["tx"] == 2  # association request + data frame
    assert any("joined" in e["text"] and "0x0042" in e["text"] for e in snap["events"])


def test_synthetic_example_map():
    m = NetworkMap(live=False)
    with open(ROOT / "examples" / "synthetic.pcap", "rb") as f:
        for rec in read_pcap(f):
            m.add(rec.psdu, rec.timestamp, fcs_ok=rec.fcs_ok, channel=rec.channel)
    snap = m.snapshot()
    (net,) = snap["networks"]
    assert net["pan"] == 0x1234 and net["epid"] == "dd:dd:dd:dd:dd:dd:dd:dd" and net["channels"] == [15]
    assert net["permit_join"] and net["stack_profile"] == "ZigbeePRO" and net["security"]
    n = {d["short"]: d for d in snap["nodes"]}
    assert n["0x0000"]["role"] == "coordinator" and n["0x0000"]["ieee"] == "02:00:00:00:00:00:00:01"
    assert n["0x0001"]["role"] == "router" and n["0x0001"]["ieee"] == "02:00:00:00:00:00:00:02"
    (lk,) = snap["links"]
    assert lk["acked"] == 2 and (lk["ab"], lk["ba"]) == (1, 1)
    assert snap["channels"]["15"]["beacon_requests"] == 1
    json.dumps(snap)  # serialisable


def test_bad_fcs_counts_but_adds_nothing():
    m = NetworkMap(live=False)
    frame = bytearray(data(1, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 1)))
    frame[-1] ^= 0xFF
    m.add(bytes(frame), 1.0, fcs_ok=False, channel=20)
    snap = m.snapshot()
    assert snap["totals"]["bad"] == 1 and snap["nodes"] == [] and snap["channels"]["20"]["bad"] == 1


# ---------------------------------------------------------------- pcap io
def test_read_pcap_round_trip_tap_and_plain():
    frames = [ack(7), data(1, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 1))]
    for tap in (True, False):
        buf = io.BytesIO()
        w = PcapWriter(buf, tap=tap)
        for i, f in enumerate(frames):
            w.write(f, 1000.25 + i, channel=17)
        recs = list(read_pcap(io.BytesIO(buf.getvalue())))
        assert [r.psdu for r in recs] == frames and all(r.fcs_ok for r in recs)
        assert recs[1].timestamp == pytest.approx(1001.25)
        assert recs[0].channel == (17 if tap else None)


def _pcapng(linktype: int, packets: list[tuple[int, bytes]]) -> bytes:
    def block(btype, body):
        body += b"\x00" * ((-len(body)) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", linktype, 0, 0))
    for ts_us, pkt in packets:
        out += block(6, struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(pkt), len(pkt)) + pkt)
    return out


def test_read_pcapng_without_fcs():
    frame = data(1, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 1))
    raw = _pcapng(230, [(1_700_000_000_500_000, frame[:-2])])  # LINKTYPE_IEEE802_15_4_NOFCS
    (rec,) = read_pcap(io.BytesIO(raw))
    assert rec.psdu == frame and rec.fcs_ok and rec.timestamp == pytest.approx(1_700_000_000.5)


def test_read_pcap_rejects_other_link_types():
    raw = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet
    with pytest.raises(ValueError):
        list(read_pcap(io.BytesIO(raw)))


# ------------------------------------------------------------------ names
def test_load_names_json_yaml_and_z2m_database(tmp_path):
    js = tmp_path / "names.json"
    js.write_text(json.dumps({"0x00124B0000000099": "Kitchen", f"0x{PAN:04x}/0x0001": "Hall"}))
    yml = tmp_path / "configuration.yaml"
    yml.write_text("devices:\n  '0x0200000000000002':\n    friendly_name: 'Living room'\n    retain: false\n")
    db = tmp_path / "database.db"
    db.write_text(
        '{"id":1,"type":"Coordinator","ieeeAddr":"0x0200000000000001","nwkAddr":0}\n'
        '{"id":2,"type":"Router","ieeeAddr":"0x00124b0000000099","manufName":"ACME","modelId":"Bulb 9"}\n'
    )
    assert load_names(js) == {TI_DEVICE: "Kitchen", f"{P}/0001": "Hall"}
    assert load_names(yml) == {ROUTER: "Living room"}
    assert load_names(db) == {COORD: "Coordinator", TI_DEVICE: "ACME Bulb 9"}
    snap = build(
        [(1.0, data(1, 0x0001, 0x0042, nwk(0, 0x0001, 0x0042, 30, 1, sec_src=TI_DEVICE)), -40.0)],
        names=load_names(js),
    )
    n = nodes(snap)
    assert n[f"{P}/0042"]["name"] == "Kitchen" and n[f"{P}/0001"]["name"] == "Hall"


# ------------------------------------------------------------- web server
def _request(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    out = r.status, r.getheader("Content-Type"), r.read()
    c.close()
    return out


def test_web_server_api():
    model = NetworkMap(live=False)
    model.add(data(1, 0x0001, 0x0000, nwk(0, 0x0001, 0x0000, 30, 1)), 1.0, channel=15)
    srv = start_server(model, Control("pcap", [15], 5.0), "127.0.0.1", 0)
    port = srv.server_address[1]
    try:
        status, ctype, body = _request(port, "GET", "/")
        assert status == 200 and ctype.startswith("text/html") and b"app.js" in body
        for asset in ("/app.js", "/style.css"):
            assert _request(port, "GET", asset)[0] == 200
        status, ctype, body = _request(port, "GET", "/api/state")
        snap = json.loads(body)
        assert status == 200 and snap["source"]["mode"] == "pcap" and len(snap["nodes"]) == 2
        assert _request(port, "GET", f"/api/state?v={snap['version']}")[0] == 204
        assert _request(port, "GET", "/api/state", headers={"Host": "attacker.example:8088"})[0] == 403
        assert _request(port, "GET", "/../netmap.py")[0] == 404
        json_hdr = {"Content-Type": "application/json"}
        assert _request(port, "POST", "/api/tune", b'{"channels": [20]}', json_hdr)[0] == 409  # not live
        assert _request(port, "POST", "/api/reset", b"{}", {"Content-Type": "text/plain"})[0] == 415
        assert _request(port, "POST", "/api/reset", b"{}", json_hdr)[0] == 200
        assert model.snapshot()["nodes"] == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_web_server_tunes_a_live_capture():
    ctl = Control("live", [11], 5.0)
    srv = start_server(NetworkMap(), ctl, "127.0.0.1", 0)
    port = srv.server_address[1]
    hdr = {"Content-Type": "application/json"}
    try:
        status, _, body = _request(port, "POST", "/api/tune", b'{"channels": "11-13", "dwell": 2}', hdr)
        assert status == 200 and json.loads(body)["channels"] == [11, 12, 13]
        assert ctl.plan() == (1, [11, 12, 13], 2.0)
        assert _request(port, "POST", "/api/tune", b'{"channels": [27]}', hdr)[0] == 400
        assert _request(port, "POST", "/api/tune", b'{"channels": [15], "dwell": 0}', hdr)[0] == 400
        assert ctl.plan()[0] == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_map_command_serves_a_pcap():
    proc = subprocess.Popen(
        [sys.executable, "-m", "zbdemod", "map", "--read", str(ROOT / "examples" / "synthetic.pcap"),
         "--no-browser", "--port", "0"],
        cwd=ROOT,
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        text=True,
    )
    try:
        port = None
        deadline = time.time() + 60
        while port is None and time.time() < deadline:
            line = proc.stderr.readline()
            if not line:
                break
            m = re.search(r"http://localhost:(\d+)/", line)
            if m:
                port = int(m.group(1))
        assert port, "no URL printed"
        snap = {}
        while time.time() < deadline:
            snap = json.loads(_request(port, "GET", "/api/state")[2])
            if snap["totals"]["frames"] == 7:
                break
            time.sleep(0.2)
        assert snap["totals"]["frames"] == 7 and snap["networks"][0]["pan"] == 0x1234
    finally:
        proc.terminate()
        proc.wait(10)
