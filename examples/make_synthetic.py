"""Generate examples/synthetic.cs8 (+ .json sidecar): a short, fully synthetic
HackRF-style recording (int8 IQ, 8 Msps, LO 2 MHz above channel 15) with a few
typical Zigbee frames. All addresses are made up, and the NWK frames are
encrypted with the made-up network key in examples/synthetic.key.

    python examples/make_synthetic.py
    python -m zbdemod file examples/synthetic.cs8 --pcap examples/synthetic.pcap
    python -m zbdemod file examples/synthetic.cs8 --keys examples/synthetic.key
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from zbdemod import mac, sim  # noqa: E402
from zbdemod.zcrypto import encrypt_nwk, load_keys  # noqa: E402

HERE = Path(__file__).resolve().parent
KEY = load_keys(HERE / "synthetic.key")[0]
PAN = 0x1234
EPID = bytes.fromhex("dd dd dd dd dd dd dd dd".replace(" ", ""))
COORD_EXT = bytes.fromhex("0200000000000001")[::-1]  # shown as 02:00:00:00:00:00:00:01
ROUTER_EXT = bytes.fromhex("0200000000000002")[::-1]


def beacon_request(seq: int) -> bytes:
    return mac.add_fcs(bytes([0x03, 0x08, seq, 0xFF, 0xFF, 0xFF, 0xFF, 0x07]))


def zigbee_beacon(seq: int) -> bytes:
    hdr = bytes([0x00, 0x80, seq]) + struct.pack("<HH", PAN, 0x0000)
    superframe = struct.pack("<H", 0xCFFF)  # BO=SO=15, PAN coordinator, association permitted
    payload = bytes([0x00, 0x22, 0x84]) + EPID + b"\xff\xff\xff" + b"\x00"
    return mac.add_fcs(hdr + superframe + b"\x00\x00" + payload)


def nwk_secured(frame_type: int, dst: int, src: int, radius: int, nseq: int, counter: int,
                src_ext: bytes, payload: bytes, extra_fc: int = 0, ieee: bytes = b"") -> bytes:
    fc = frame_type | (2 << 2) | 0x0200 | extra_fc  # protocol v2, security
    header = struct.pack("<HHHBB", fc, dst, src, radius, nseq) + ieee
    aux = bytes([0x28]) + struct.pack("<I", counter) + src_ext + b"\x00"  # network key, ext. nonce, kseq 0
    return encrypt_nwk(KEY, header, aux, payload)


def aps_zcl(cluster: int, counter: int, zcl: bytes) -> bytes:
    """APS unicast data frame, Home Automation profile, endpoint 1 -> 1."""
    return struct.pack("<BBHHBB", 0x00, 1, cluster, 0x0104, 1, counter) + zcl


def zcl_string(attr: int, text: str) -> bytes:
    return struct.pack("<HBBB", attr, 0, 0x42, len(text)) + text.encode()


def data_frame(seq: int, dst: int, src: int, nwk: bytes, ack: bool = True) -> bytes:
    fc = 0x8841 | (0x0020 if ack else 0)  # data, PAN compression, short/short
    return mac.add_fcs(struct.pack("<HBHHH", fc, seq, PAN, dst, src) + nwk)


def ack(seq: int) -> bytes:
    return mac.add_fcs(bytes([0x02, 0x00, seq]))


def main() -> None:
    read_basic = aps_zcl(0x0000, 0x10, bytes([0x00, 0x01, 0x00]) + struct.pack("<HH", 0x0004, 0x0005))
    basic_rsp = aps_zcl(0x0000, 0x42, bytes([0x18, 0x01, 0x01])
                        + zcl_string(0x0004, "ACME") + zcl_string(0x0005, "Demo Lamp"))
    link_status = bytes([0x08, 0x61, 0x00, 0x00, 0x11])  # first+last, 1 entry: 0x0000 in 1, out 1
    frames = [
        beacon_request(0x10),
        zigbee_beacon(0x55),
        data_frame(0x21, 0x0001, 0x0000, nwk_secured(0, 0x0001, 0x0000, 30, 7, 1000, COORD_EXT, read_basic)),
        ack(0x21),
        data_frame(0x09, 0x0000, 0x0001, nwk_secured(0, 0x0000, 0x0001, 30, 4, 501, ROUTER_EXT, basic_rsp)),
        ack(0x09),
        data_frame(0x0A, 0xFFFF, 0x0001,
                   nwk_secured(1, 0xFFFC, 0x0001, 1, 5, 502, ROUTER_EXT, link_status, 0x1000, ROUTER_EXT),
                   ack=False),
    ]
    fs = 8e6
    # The ACK follows its data frame after the 802.15.4 turnaround (12 symbols = 192 us).
    x, _ = sim.make_stream(frames, fs=fs, snr_db=15, cfo_hz=-35e3, drift_ppm=25, if_hz=-2e6,
                           gap_s=(192e-6, 1.5e-3), seed=7)
    iq = np.empty(2 * len(x), dtype=np.int8)
    iq[0::2] = np.clip(np.round(x.real * 127), -128, 127)
    iq[1::2] = np.clip(np.round(x.imag * 127), -128, 127)
    out = HERE / "synthetic.cs8"
    iq.tofile(out)
    meta = {"format": "cs8", "sample_rate": fs, "channel": 15, "offset_hz": 2e6,
            "lo_freq": 2425e6 + 2e6, "start_time": 1767225600.0, "synthetic": True}
    out.with_suffix(".cs8.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"wrote {out} ({len(iq) / 1e3:.0f} kB, {len(x) / fs * 1e3:.1f} ms, {len(frames)} frames)")


if __name__ == "__main__":
    main()
