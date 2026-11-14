"""NWK decryption with configured keys, decrypted payload parsing and its use in the map."""

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from zbdemod import mac, zdecode
from zbdemod.netmap import NetworkMap
from zbdemod.zcrypto import AES128, KeyRing, ccm_star_decrypt, ccm_star_encrypt, encrypt_nwk, load_keys

ROOT = Path(__file__).resolve().parent.parent
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_KEY = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
PAN = 0x4242
P = f"{PAN:04x}"
DEV = {0x0000: "02:00:00:00:00:00:00:01", 0x0001: "02:00:00:00:00:00:00:02",
       0x0002: "02:00:00:00:00:00:00:03", 0x0042: "00:12:4b:00:00:00:00:99"}


def ext(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))[::-1]


def secured(ftype, dst, src, payload, *, radius=30, seq=1, counter=100, sender=None, key=KEY):
    """Encrypted NWK frame as sent by `sender` (short address of the hop's transmitter)."""
    header = struct.pack("<HHHBB", ftype | (2 << 2) | 0x0200, dst, src, radius, seq)
    aux = bytes([0x28]) + struct.pack("<I", counter) + ext(DEV[src if sender is None else sender]) + b"\x00"
    return encrypt_nwk(key, header, aux, payload)


def mac_frame(seq, dst, src, nwk, ack=True):
    return mac.add_fcs(struct.pack("<HBHHH", 0x8841 | (0x20 if ack else 0), seq, PAN, dst, src) + nwk)


def link_status(entries, first=True, last=True):
    opts = len(entries) | (0x20 if first else 0) | (0x40 if last else 0)
    return bytes([0x08, opts]) + b"".join(struct.pack("<HB", a, (o << 4) | i) for a, i, o in entries)


def aps_zdo(cluster, body):
    return struct.pack("<BBHHBB", 0x08, 0, cluster, 0x0000, 0, 7) + bytes([0x11]) + body  # broadcast delivery


def aps_zcl(cluster, zcl):
    return struct.pack("<BBHHBB", 0x00, 1, cluster, 0x0104, 1, 9) + zcl


# -------------------------------------------------------------- AES / CCM*
def test_aes128_fips197():
    assert AES128(bytes(range(16))).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex() \
        == "69c4e0d86a7b0430d8cdb78070b4c55a"
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert AES128(key).encrypt_block(bytes.fromhex("3243f6a8885a308d313198a2e0370734")).hex() \
        == "3925841d02dc09fbdc118597196a0b32"


def test_ccm_rfc3610_packet_vector_1():
    key = bytes.fromhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
    nonce = bytes.fromhex("00000003020100A0A1A2A3A4A5")
    pkt = bytes(range(31))
    out = ccm_star_encrypt(key, nonce, pkt[:8], pkt[8:], 8)
    assert out.hex().upper() == "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0"
    assert ccm_star_decrypt(key, nonce, pkt[:8], out, 8) == pkt[8:]
    tampered = bytes([out[0] ^ 1]) + out[1:]
    assert ccm_star_decrypt(key, nonce, pkt[:8], tampered, 8) is None


def test_keyring_decrypts_only_with_the_right_key():
    payload = link_status([(0x0000, 1, 3)])
    data = secured(1, 0xFFFC, 0x0001, payload, radius=1)
    n = mac.decode_nwk(data)
    assert n.secured and n.header_len == 8 and n.aux_len == 14
    ring = KeyRing([OTHER_KEY, KEY])
    assert ring.decrypt_nwk(data, n) == payload and ring.ok == 1
    assert KeyRing([OTHER_KEY]).decrypt_nwk(data, n) is None
    assert KeyRing([KEY[::-1]]).decrypt_nwk(data, n) == payload  # byte-reversed key in the config
    flipped = data[:-1] + bytes([data[-1] ^ 0x80])
    assert ring.decrypt_nwk(flipped, mac.decode_nwk(flipped)) is None


def test_mac_summary_with_keys():
    frame = mac_frame(5, 0xFFFF, 0x0001, secured(1, 0xFFFC, 0x0001, link_status([(0x0000, 1, 3)]), radius=1), False)
    assert "Link Status" not in mac.parse(frame).summary()
    s = mac.parse(frame, keys=KeyRing([KEY])).summary()
    assert "| Link Status (1 neighbours): 0x0000 in1/out3" in s
    assert "[no key matches]" in mac.parse(frame, keys=KeyRing([OTHER_KEY])).summary()


# ----------------------------------------------------------------- key files
def test_load_keys_formats(tmp_path):
    hex_key = KEY.hex()
    colon = ":".join(f"{b:02X}" for b in KEY)
    (tmp_path / "keys.txt").write_text(f"# my network\n{colon}\n\n{OTHER_KEY.hex()}  # old key\n")
    assert load_keys(tmp_path / "keys.txt") == [KEY, OTHER_KEY]
    (tmp_path / "k.json").write_text(json.dumps({"network_key": list(KEY)}))
    assert load_keys(tmp_path / "k.json") == [KEY]
    (tmp_path / "k2.json").write_text(json.dumps({"keys": [hex_key, "0x" + OTHER_KEY.hex()]}))
    assert load_keys(tmp_path / "k2.json") == [KEY, OTHER_KEY]
    inline = ", ".join(str(b) for b in KEY)
    (tmp_path / "z2m.yaml").write_text(f"homeassistant: true\nadvanced:\n  pan_id: 6754\n  network_key: [{inline}]\n")
    assert load_keys(tmp_path / "z2m.yaml") == [KEY]
    block = "".join(f"    - {b}\n" for b in KEY)
    (tmp_path / "z2m2.yaml").write_text(f"advanced:\n  network_key:\n{block}  channel: 11\n")
    assert load_keys(tmp_path / "z2m2.yaml") == [KEY]
    (tmp_path / "gen.yaml").write_text("advanced:\n  network_key: GENERATE\n")
    assert load_keys(tmp_path / "gen.yaml") == []


# ------------------------------------------------------------- payload parse
def test_describe_nwk_commands_zdo_and_zcl():
    n = mac.NwkFrame(ftype=1, dst=0, src=0x0001, radius=30, seq=1)
    rr = zdecode.describe(n, bytes([0x05, 0x02]) + struct.pack("<HH", 0x0002, 0x0003))
    assert rr.data["relays"] == [2, 3] and "Route Record via 0x0002 > 0x0003" in rr.summary
    ns = zdecode.describe(n, bytes([0x03, 0x00]) + struct.pack("<H", 0x1234))
    assert "No route available (0x1234)" in ns.summary
    lv = zdecode.describe(n, bytes([0x04, 0x20]))
    assert lv.data["rejoin"] and not lv.data["request"]
    n.ftype = 0
    annce = zdecode.describe(n, aps_zdo(0x0013, struct.pack("<H", 0x0042) + ext(DEV[0x0042]) + bytes([0x80])))
    assert annce.kind == "zdo" and annce.data["ieee"] == DEV[0x0042]
    assert annce.data["capability"] == {"router": False, "mains": False, "rx_on_when_idle": False}
    report = zdecode.describe(n, aps_zcl(0x0402, bytes([0x18, 0x05, 0x0A]) + struct.pack("<HBh", 0x0000, 0x29, 2153)))
    assert report.summary == "ZCL Temperature Measurement Report Attributes MeasuredValue=21.53 °C"
    on = zdecode.describe(n, aps_zcl(0x0006, bytes([0x01, 0x06, 0x01])))
    assert on.summary == "ZCL On/Off On" and not on.data["from_server"]
    aps_sec = zdecode.describe(n, bytes([0x21]) + b"\x00" * 12)
    assert aps_sec.kind == "aps_encrypted"


def test_mgmt_lqi_response_parse():
    entry = ext("dd:dd:dd:dd:dd:dd:dd:dd") + ext(DEV[0x0042]) + struct.pack("<HBBBB", 0x0042, 0x02 | (1 << 4), 0x02, 2, 180)
    body = bytes([0x00, 1, 0, 1]) + entry
    n = mac.NwkFrame(ftype=0, dst=0, src=0x0001, radius=30, seq=1)
    d = zdecode.describe(n, aps_zdo(0x8031, body)).data
    (e,) = d["entries"]
    assert e["addr"] == 0x0042 and e["type"] == "end_device" and e["relationship"] == "child" and e["lqi"] == 180


# ------------------------------------------------------------------ map
def build(frames, keys=(KEY,)):
    m = NetworkMap(live=False, keys=KeyRing(list(keys)) if keys else None)
    for t, psdu in frames:
        m.add(psdu, t, channel=15, rssi=-40.0)
    return m.snapshot()


def links(snap):
    return {(lk["a"], lk["b"]): lk for lk in snap["links"]}


def test_link_status_gives_router_links_with_costs_and_drops_stale_neighbours():
    ls1 = link_status([(0x0000, 1, 1), (0x0002, 3, 5)])
    ls2 = link_status([(0x0000, 2, 1)])
    snap = build([
        (1.0, mac_frame(1, 0xFFFF, 0x0001, secured(1, 0xFFFC, 0x0001, ls1, radius=1, counter=1), False)),
    ])
    lk = links(snap)
    assert lk[(f"{P}/0000", f"{P}/0001")]["cost"] == 1
    far = lk[(f"{P}/0001", f"{P}/0002")]
    assert far["kind"] == "neighbor" and far["cost"] == 5
    assert far["reported"][0]["by"] == f"{P}/0001" and (far["reported"][0]["in"], far["reported"][0]["out"]) == (3, 5)
    roles = {n["id"]: n["role"] for n in snap["nodes"]}
    assert roles[f"{P}/0002"] == "router" and snap["networks"][0]["decrypted"] == 1

    snap = build([
        (1.0, mac_frame(1, 0xFFFF, 0x0001, secured(1, 0xFFFC, 0x0001, ls1, radius=1, counter=1), False)),
        (16.0, mac_frame(2, 0xFFFF, 0x0001, secured(1, 0xFFFC, 0x0001, ls2, radius=1, counter=2), False)),
    ])
    lk = links(snap)
    assert (f"{P}/0001", f"{P}/0002") not in lk  # no longer reported, never heard
    assert lk[(f"{P}/0000", f"{P}/0001")]["cost"] == 2


def test_announce_lqi_table_and_basic_attributes_feed_the_map():
    annce = aps_zdo(0x0013, struct.pack("<H", 0x0042) + ext(DEV[0x0042]) + bytes([0x80]))
    entry = ext("dd:dd:dd:dd:dd:dd:dd:dd") + ext(DEV[0x0042]) + struct.pack("<HBBBB", 0x0042, 0x02 | (1 << 4), 0x02, 2, 180)
    lqi = struct.pack("<BBHHBB", 0x00, 0, 0x8031, 0x0000, 0, 8) + bytes([0x12, 0x00, 1, 0, 1]) + entry
    basic = aps_zcl(0x0000, bytes([0x18, 0x01, 0x01])
                    + struct.pack("<HBBB", 0x0004, 0, 0x42, 4) + b"ACME"
                    + struct.pack("<HBBB", 0x0005, 0, 0x42, 9) + b"Demo Lamp"
                    + struct.pack("<HBBB", 0x0007, 0, 0x30, 1))
    snap = build([
        (1.0, mac_frame(1, 0xFFFF, 0x0042, secured(0, 0xFFFD, 0x0042, annce, counter=1), False)),
        (2.0, mac_frame(2, 0x0000, 0x0001, secured(0, 0x0000, 0x0001, lqi, counter=2))),
        (3.0, mac_frame(3, 0x0000, 0x0001, secured(0, 0x0000, 0x0001, basic, counter=3))),
    ])
    nodes = {n["id"]: n for n in snap["nodes"]}
    child = nodes[f"{P}/0042"]
    assert child["role"] == "end_device" and child["ieee"] == DEV[0x0042] and child["mains"] is False
    assert any("Device Announce" in e["reason"] for e in child["evidence"])
    lk = links(snap)[(f"{P}/0001", f"{P}/0042")]
    assert lk["parent"] == f"{P}/0042" and lk["reported"][0]["lqi"] == 180
    lamp = nodes[f"{P}/0001"]
    assert (lamp["manufacturer"], lamp["model"], lamp["mains"]) == ("ACME", "Demo Lamp", True)
    assert lamp["clusters"] == ["Basic"]
    assert any(e["text"] == "0x0001 is ACME Demo Lamp" for e in snap["events"])
    assert any("announced itself: end device, battery" in e["text"] for e in snap["events"])


def test_wrong_key_counts_failures_and_adds_nothing():
    frame = mac_frame(1, 0xFFFF, 0x0001, secured(1, 0xFFFC, 0x0001, link_status([(0x0002, 1, 1)]), radius=1), False)
    snap = build([(1.0, frame)], keys=(OTHER_KEY,))
    net = snap["networks"][0]
    assert net["decrypted"] == 0 and net["mic_failed"] == 1
    assert snap["links"] == [] and snap["decryption"]["keys"] == 1


def test_synthetic_example_decrypts_end_to_end():
    res = subprocess.run(
        [sys.executable, "-m", "zbdemod", "file", "examples/synthetic.cs8", "--keys", "examples/synthetic.key"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, res.stderr
    assert 'ModelIdentifier="Demo Lamp"' in res.stdout
    assert "Link Status (1 neighbours): 0x0000 in1/out1" in res.stdout
    assert "decrypting with 1 configured network key" in res.stderr


def test_missing_key_file_is_an_error(tmp_path):
    empty = tmp_path / "none.txt"
    empty.write_text("# nothing here\n")
    with pytest.raises(SystemExit):
        from zbdemod.zcrypto import load_keyring

        load_keyring(str(empty))
