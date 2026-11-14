import io
import struct

import numpy as np
import pytest

from zbdemod import mac, phy, sim
from zbdemod.demod import Demodulator
from zbdemod.pcap import PcapWriter


def test_chip_table_matches_standard():
    ref = {
        0: "11011001110000110101001000101110",
        1: "11101101100111000011010100100010",
        8: "10001100100101100000011101111011",
        15: "11001001011000000111011110111000",
    }
    for k, s in ref.items():
        assert "".join(map(str, phy.CHIPS[k])) == s


def test_msk_law_matches_modulator():
    rng = np.random.default_rng(0)
    c = rng.integers(0, 2, 640).astype(np.uint8)
    sps = 4
    d = phy.discriminator(phy.modulate_chips(c, sps), sps)
    C = np.concatenate(([0], np.cumsum(d)))
    n = np.arange(1, len(c) - 1)
    measured = (C[(n + 1) * sps + 1] - C[n * sps + 1]) / sps
    a = 2.0 * c - 1
    np.testing.assert_allclose(measured, ((-1.0) ** (n + 1)) * a[n] * a[n - 1], atol=1e-5)


def test_crc_ieee_example():
    # IEEE 802.15.4 example acknowledgment frame: MHR 02 00 6a -> FCS 0x79e4
    assert mac.crc16(bytes([0x02, 0x00, 0x6A])) == 0x79E4
    assert mac.fcs_ok(bytes([0x02, 0x00, 0x6A, 0xE4, 0x79]))


def test_symbol_roundtrip():
    data = bytes(range(256))
    assert phy.symbols_to_bytes(phy.bytes_to_symbols(data)) == data


@pytest.mark.parametrize("detector,method", [("diff", "coherent"), ("disc", "coherent"), ("disc", "disc")])
@pytest.mark.parametrize(
    "kw,offset",
    [
        (dict(snr_db=30), 0.0),
        (dict(snr_db=20, cfo_hz=150e3, drift_ppm=100), 0.0),
        (dict(snr_db=12, cfo_hz=-120e3, drift_ppm=-80, if_hz=-2e6), 2e6),
    ],
)
def test_demodulates_synthetic_stream(kw, offset, detector, method):
    rng = np.random.default_rng(42)
    psdus = [sim.random_mpdu(rng, n) for n in (5, 11, 40, 127, 77, 127, 20)]
    x, starts = sim.make_stream(psdus, seed=9, **kw)
    d = Demodulator(fs=8e6, offset_hz=offset, method=method, detector=detector)
    frames = sim.run_demod(d, x, rng=rng)
    assert [f.psdu for f in frames if f.fcs_ok] == psdus
    tol = 2e3 if method == "coherent" else 15e3
    for f in frames:
        assert abs(f.cfo_hz - kw.get("cfo_hz", 0)) < tol
        assert abs(f.drift_ppm - kw.get("drift_ppm", 0)) < 40 or len(f.psdu) < 20
    # PHR start = frame start + 10 SHR symbols (5 bytes), within a few samples
    for fr, s in zip(frames, starts):
        assert abs(fr.sample - (s + 10 * 32 * 4)) < 64


def test_coherent_decoder_is_more_sensitive():
    """At 1 dB SNR (2 MHz) the discriminator decoder is hopeless, the coherent one is not."""
    rng = np.random.default_rng(5)
    psdus = [sim.random_mpdu(rng, int(n)) for n in rng.integers(10, 128, 30)]
    x, _ = sim.make_stream(psdus, seed=4, snr_db=1, cfo_hz=60e3, drift_ppm=50, if_hz=-2e6)
    counts = {}
    for method in ("coherent", "disc"):
        got = {f.psdu for f in sim.run_demod(Demodulator(offset_hz=2e6, method=method), x) if f.fcs_ok}
        counts[method] = sum(p in got for p in psdus)
    assert counts["coherent"] >= 24, counts
    assert counts["disc"] <= 3, counts


def test_diff_detector_is_more_sensitive():
    """At -3 dB SNR the chip-differential detector still finds the frames, the
    discriminator detector does not (both feeding the coherent decoder)."""
    rng = np.random.default_rng(8)
    psdus = [sim.random_mpdu(rng, int(n)) for n in rng.integers(10, 128, 30)]
    x, _ = sim.make_stream(psdus, seed=6, snr_db=-3, cfo_hz=-90e3, drift_ppm=-60, if_hz=-2e6)
    counts = {}
    for det in ("diff", "disc"):
        d = Demodulator(offset_hz=2e6, detector=det)
        got = {f.psdu for f in sim.run_demod(d, x) if f.fcs_ok}
        counts[det] = sum(p in got for p in psdus)
    assert counts["diff"] >= 24, counts
    assert counts["disc"] <= 6, counts


def test_side_lobe_alignment_is_resolved():
    """Detections forced one or two symbols early/late must still decode
    (the coherent decoder checks whole-symbol SFD alignment)."""
    rng = np.random.default_rng(2)
    psdu = sim.random_mpdu(rng, 30)
    x, _ = sim.make_stream([psdu], seed=3, snr_db=15)
    for shift in (-2, -1, 1, 2):
        d = Demodulator()
        orig = d._detected

        def shifted(q, corr, aux, d=d, orig=orig, shift=shift):
            return orig(q + shift * d.sym_len, corr, aux)

        d._detected = shifted
        frames = sim.run_demod(d, x)
        assert psdu in [f.psdu for f in frames if f.fcs_ok], shift


def test_invalid_detector_method_combination():
    with pytest.raises(ValueError):
        Demodulator(method="disc", detector="diff")


def test_back_to_back_ack():
    """An ACK 192 us (12 symbols) after a data frame must also be decoded."""
    rng = np.random.default_rng(3)
    data = sim.random_mpdu(rng, 60)
    ack = mac.add_fcs(bytes([0x02, 0x00, data[2]]))
    x, _ = sim.make_stream([data, ack], gap_s=(192e-6, 200e-6), snr_db=25, seed=1)
    frames = sim.run_demod(Demodulator(), x)
    assert [f.psdu for f in frames] == [data, ack]


def test_noise_only_produces_nothing():
    rng = np.random.default_rng(0)
    x = (rng.standard_normal(2 * 2_000_000) * 0.05).astype(np.float32).view(np.complex64)
    assert sim.run_demod(Demodulator(), x) == []


def test_mac_parse_beacon_request_and_nwk():
    # Beacon request: cmd frame, dst short 0xffff, PAN 0xffff, no src
    br = mac.add_fcs(bytes([0x03, 0x08, 0x55, 0xFF, 0xFF, 0xFF, 0xFF, 0x07]))
    m = mac.parse(br)
    assert m.type_name == "Cmd" and "Beacon Request" in m.summary() and m.seq == 0x55
    # Data frame carrying an encrypted Zigbee NWK frame
    nwk = struct.pack("<HHHBB", 0x0208, 0xFFFD, 0x0000, 30, 7)  # data, ver 2, security
    nwk += bytes([0x28]) + struct.pack("<I", 1234) + bytes(range(8)) + bytes([0]) + b"\xaa" * 10
    frame = mac.add_fcs(bytes([0x41, 0x88, 0x01, 0x34, 0x12, 0xFF, 0xFF, 0x00, 0x00]) + nwk)
    s = mac.parse(frame).summary()
    assert "pan=0x1234" in s and "0x0000 -> 0xffff" in s
    assert "NWK Data 0x0000->0xfffd" in s and "fc=1234" in s and "kseq=0" in s


def test_pcap_layout():
    buf = io.BytesIO()
    w = PcapWriter(buf)
    w.write(b"\x02\x00\x6a\xe4\x79", 1.5, channel=15)
    raw = buf.getvalue()
    assert struct.unpack_from("<I", raw, 20)[0] == 283
    caplen = struct.unpack_from("<I", raw, 24 + 8)[0]
    pkt = raw[40 : 40 + caplen]
    hdr_len = struct.unpack_from("<H", pkt, 2)[0]
    assert hdr_len % 4 == 0 and pkt[hdr_len:] == b"\x02\x00\x6a\xe4\x79"
