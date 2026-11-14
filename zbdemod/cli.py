"""Command line front end.

    python -m zbdemod live   -c 15 [--pcap out.pcap]      live decoding
    python -m zbdemod live   -c 15 --pcap - | wireshark -k -i -    live into Wireshark
    python -m zbdemod scan   [-c 11-26] [--dwell 5]        hop channels, find networks
    python -m zbdemod record -c 15 -d 10 -o cap.cs8        save raw IQ (+ .json sidecar)
    python -m zbdemod file   cap.cs8 [--pcap out.pcap]     decode a recording
    python -m zbdemod map    [-c 11-26] [--read cap.pcap]  live network map in the browser
    python -m zbdemod selftest                             synthetic end-to-end test
    python -m zbdemod extcap-install                       add the Wireshark capture interface
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

from . import mac, phy
from .demod import Demodulator, Frame
from .pcap import PcapWriter

DEFAULT_FS = 8e6
DEFAULT_OFFSET = 2e6  # tune LO 2 MHz above the channel -> keeps the HackRF DC spike out


# ------------------------------------------------------------------ helpers
def parse_channels(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    for ch in out:
        phy.channel_freq(ch)  # validates
    return out


def int8_to_complex(raw: bytes | np.ndarray) -> np.ndarray:
    a = np.frombuffer(raw, dtype=np.int8) if isinstance(raw, (bytes, bytearray)) else raw
    a = a[: len(a) // 2 * 2]
    return (a.astype(np.float32) * (1 / 128)).view(np.complex64)


class PipeClosed(Exception):
    """The PCAP consumer (Wireshark, tshark, a pipe) went away."""


def release_dead_stdout() -> None:
    """After the reader of a '--pcap -' stream went away, point stdout at the null
    device so Python does not complain about flushing the dead pipe at exit."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _pipe_closed(printer: "Printer", verbose: bool = True) -> None:
    if verbose:
        print("# PCAP output closed by the reader", file=sys.stderr)
    if printer.pcap is not None and printer.pcap.f is getattr(sys.stdout, "buffer", None):
        release_dead_stdout()


class Printer:
    """Prints a summary line per frame and writes frames to the PCAP (if any).

    out:   text stream for frame lines (stderr when the PCAP goes to stdout)
    quiet: no text output at all (Wireshark extcap mode)
    """

    def __init__(
        self,
        show_hex: bool,
        pcap: PcapWriter | None,
        zigbee: bool = True,
        out=None,
        quiet: bool = False,
        pcap_bad: bool = False,
    ):
        self.show_hex = show_hex
        self.pcap = pcap
        self.zigbee = zigbee
        self.out = out or sys.stdout
        self.quiet = quiet
        self.pcap_bad = pcap_bad
        self.count = 0

    def frame(self, f: Frame, wall: float) -> None:
        self.count += 1
        if not self.quiet:
            ts = time.strftime("%H:%M:%S", time.localtime(wall)) + f".{int((wall % 1) * 1000):03d}"
            ch = f"ch{f.channel}" if f.channel else "    "
            status = "" if f.fcs_ok else " BAD-FCS"
            desc = mac.parse(f.psdu, self.zigbee).summary() if f.fcs_ok else ""
            print(
                f"{ts} {ch} {f.rssi_dbfs:6.1f}dBFS snr{f.snr_db:5.1f} cfo{f.cfo_hz / 1e3:+7.1f}k "
                f"lqi{f.lqi:4d} len{len(f.psdu):4d}{status}  {desc}",
                file=self.out,
                flush=True,
            )
            if self.show_hex or not f.fcs_ok:
                print("    " + f.psdu.hex(" "), file=self.out, flush=True)
        if self.pcap and (f.fcs_ok or self.pcap_bad):
            try:
                self.pcap.write(f.psdu, wall, f.channel)
            except (BrokenPipeError, OSError) as exc:
                raise PipeClosed(str(exc)) from exc


def open_pcap(path: str | None) -> PcapWriter | None:
    """PCAP writer for a file name, or for stdout when path is '-'."""
    if not path:
        return None
    if path == "-":
        return PcapWriter(sys.stdout.buffer)
    return PcapWriter(open(path, "wb"))


def make_printer(args, quiet: bool = False) -> Printer:
    pcap = open_pcap(args.pcap)
    out = sys.stderr if args.pcap == "-" else sys.stdout
    return Printer(args.hex, pcap, out=out, quiet=quiet, pcap_bad=args.bad)


def make_demod(args, channel: int | None, offset: float, fs: float) -> Demodulator:
    return Demodulator(
        fs=fs,
        offset_hz=offset,
        threshold=args.threshold,
        keep_bad_fcs=args.bad,
        channel=channel,
        method=args.method,
        detector=args.detector,
    )


# --------------------------------------------------------------- live/scan
def _open_hackrf(args, channel: int):
    from .hackrf import HackRF

    dev = HackRF(serial=args.serial)
    lo = phy.channel_freq(channel) + args.offset
    dev.configure(lo, args.fs, args.lna, args.vga, args.amp)
    return dev


class _Stream:
    """Pulls blocks from the HackRF queue and feeds the demodulator."""

    def __init__(self, dev, fs: float):
        self.dev = dev
        self.fs = fs
        self.t0: float | None = None
        self.samples = 0
        self.clip = 0
        self.peak_sum = 0

    def reset_clock(self) -> None:
        self.t0 = None
        self.samples = 0

    def next_iq(self, timeout: float = 1.0) -> np.ndarray | None:
        import queue as _q

        try:
            blocks = [self.dev.queue.get(timeout=timeout)]
        except _q.Empty:
            return None
        while len(blocks) < 8:
            try:
                blocks.append(self.dev.queue.get_nowait())
            except _q.Empty:
                break
        raw = np.frombuffer(b"".join(blocks), dtype=np.int8)
        if self.t0 is None:
            self.t0 = time.time() - len(raw) / 2 / self.fs
        self.samples += len(raw) // 2
        self.clip += int(np.count_nonzero((raw == 127) | (raw == -128)))
        return int8_to_complex(raw)


def _status(demod: Demodulator, dev, stream: _Stream, extra: str = "") -> None:
    nf = demod.noise_floor
    nf_s = f"{10 * np.log10(nf):.1f}dBFS" if nf else "?"
    clip = 100.0 * stream.clip / max(1, 2 * stream.samples)
    dropped = 100.0 * dev.dropped_bytes / max(1, dev.received_bytes)
    print(
        f"# noise {nf_s}  clip {clip:.3f}%  detections {demod.stats['detections']}  "
        f"ok {demod.stats['ok']}  badFCS {demod.stats['bad_fcs']}  dropped {dropped:.1f}%  {extra}",
        file=sys.stderr,
        flush=True,
    )


def run_live(args, printer: Printer, verbose: bool = True) -> int:
    """Receive one channel with the HackRF until Ctrl+C, the duration, or the
    PCAP consumer closing its end (Wireshark stopping the capture)."""
    channel = args.channel
    dev = _open_hackrf(args, channel)
    demod = make_demod(args, channel, args.offset, args.fs)
    stream = _Stream(dev, args.fs)
    if verbose:
        print(
            f"# HackRF: ch{channel} {phy.channel_freq(channel) / 1e6:.0f} MHz, LO "
            f"{(phy.channel_freq(channel) + args.offset) / 1e6:.3f} MHz, fs {args.fs / 1e6:g} Msps, "
            f"LNA {dev.lna_db} dB, VGA {dev.vga_db} dB, amp {'on' if dev.amp else 'off'}, "
            f"BB filter {dev.bb_filter_hz / 1e6:g} MHz.  Ctrl+C to stop.",
            file=sys.stderr,
        )
    dev.start()
    t_end = time.time() + args.duration if args.duration else None
    t_stat = time.time() + args.status
    busy = 0.0
    t_begin = time.time()
    rc = 0
    try:
        while t_end is None or time.time() < t_end:
            iq = stream.next_iq()
            if iq is None:
                if not dev.is_streaming():
                    print("# HackRF stopped streaming", file=sys.stderr)
                    rc = 1
                    break
                continue
            t = time.perf_counter()
            for f in demod.process(iq):
                printer.frame(f, stream.t0 + f.sample / args.fs)
            busy += time.perf_counter() - t
            if verbose and args.status and time.time() > t_stat:
                load = 100 * busy / (time.time() - t_begin)
                _status(demod, dev, stream, f"cpu {load:.0f}%")
                t_stat = time.time() + args.status
    except KeyboardInterrupt:
        pass
    except PipeClosed:
        _pipe_closed(printer, verbose)
    finally:
        dev.close()
    if verbose:
        _status(demod, dev, stream)
    return rc


def cmd_live(args) -> int:
    return run_live(args, make_printer(args))


def cmd_scan(args) -> int:
    channels = parse_channels(args.channels)
    dev = _open_hackrf(args, channels[0])
    printer = make_printer(args)
    stream = _Stream(dev, args.fs)
    summary = {ch: {"frames": 0, "bad": 0, "pans": set(), "srcs": set()} for ch in channels}
    settle = int(0.08 * args.fs) * 2  # bytes to drop after retune
    print(
        f"# scanning channels {channels}, {args.dwell:g} s each, {args.loops} loop(s). Ctrl+C to stop.",
        file=sys.stderr,
    )
    dev.start()
    try:
        for _ in range(args.loops):
            for ch in channels:
                dev.retune(phy.channel_freq(ch) + args.offset, settle)
                demod = make_demod(args, ch, args.offset, args.fs)
                stream.reset_clock()
                t_end = time.time() + args.dwell
                while time.time() < t_end:
                    iq = stream.next_iq()
                    if iq is None:
                        continue
                    for f in demod.process(iq):
                        printer.frame(f, stream.t0 + f.sample / args.fs)
                        s = summary[ch]
                        if f.fcs_ok:
                            s["frames"] += 1
                            m = mac.parse(f.psdu)
                            pan = m.dst_pan if m.dst_pan is not None else m.src_pan
                            if pan is not None:
                                s["pans"].add(pan)
                            if m.src:
                                s["srcs"].add(m.src)
                        else:
                            s["bad"] += 1
                nf = demod.noise_floor
                print(
                    f"# ch{ch}: {summary[ch]['frames']} frames"
                    f" (noise {10 * np.log10(nf):.1f} dBFS)" if nf else f"# ch{ch}: no data",
                    file=sys.stderr,
                    flush=True,
                )
    except KeyboardInterrupt:
        pass
    except PipeClosed:
        _pipe_closed(printer)
    finally:
        dev.close()
    out = printer.out
    print("\nchannel  MHz   frames  PAN IDs              devices(src)", file=out)
    for ch in channels:
        s = summary[ch]
        pans = ",".join(f"0x{p:04x}" for p in sorted(s["pans"])) or "-"
        print(
            f"  {ch:3d}   {phy.channel_freq(ch) / 1e6:.0f}  {s['frames']:6d}  {pans:20s} {len(s['srcs'])}",
            file=out,
        )
    return 0


def cmd_record(args) -> int:
    from .hackrf import HackRF

    channel = args.channel
    lo = phy.channel_freq(channel) + args.offset
    out = Path(args.output)
    n_bytes = int(args.duration * args.fs) * 2
    with HackRF(serial=args.serial) as dev:
        dev.configure(lo, args.fs, args.lna, args.vga, args.amp)
        meta = {
            "format": "cs8",
            "sample_rate": args.fs,
            "lo_freq": lo,
            "channel": channel,
            "offset_hz": args.offset,
            "lna_db": dev.lna_db,
            "vga_db": dev.vga_db,
            "amp": dev.amp,
            "start_time": time.time(),
        }
        written = 0
        dev.start()
        with open(out, "wb") as f:
            while written < n_bytes:
                blk = dev.queue.get(timeout=5)
                blk = blk[: n_bytes - written]
                f.write(blk)
                written += len(blk)
        dropped = dev.dropped_bytes
    out.with_suffix(out.suffix + ".json").write_text(json.dumps(meta, indent=2))
    print(f"wrote {written / 2 / args.fs:.2f} s ({written / 1e6:.0f} MB) to {out}; dropped {dropped} bytes")
    return 0


def cmd_file(args) -> int:
    return decode_file(args, make_printer(args))


def decode_file(args, printer: Printer, verbose: bool = True) -> int:
    """Decode a recording (args.input) using its .json sidecar when present."""
    path = Path(args.input)
    meta = {}
    side = path.with_suffix(path.suffix + ".json")
    if side.is_file():
        meta = json.loads(side.read_text())
    fs = args.fs or meta.get("sample_rate", DEFAULT_FS)
    offset = args.offset if args.offset is not None else meta.get("offset_hz", 0.0)
    channel = args.channel or meta.get("channel")
    fmt = args.format or meta.get("format") or ("cf32" if path.suffix in (".cf32", ".cfile", ".fc32") else "cs8")
    t_start = meta.get("start_time", path.stat().st_mtime - path.stat().st_size / (2 if fmt == "cs8" else 8) / fs)
    demod = make_demod(args, channel, offset, fs)
    if verbose:
        print(f"# {path}: {fmt}, fs {fs / 1e6:g} Msps, offset {offset / 1e6:g} MHz, ch {channel}", file=sys.stderr)
    item = 2 if fmt == "cs8" else 8
    chunk = 1 << 20
    t = time.perf_counter()
    total = 0
    with open(path, "rb") as f:
        while True:
            raw = f.read(chunk * item)
            if not raw:
                break
            if fmt == "cs8":
                iq = int8_to_complex(raw)
            else:
                iq = np.frombuffer(raw[: len(raw) // 8 * 8], dtype=np.complex64)
            total += len(iq)
            for fr in demod.process(iq):
                printer.frame(fr, t_start + fr.sample / fs)
    for fr in demod.flush():
        printer.frame(fr, t_start + fr.sample / fs)
    dt = time.perf_counter() - t
    if verbose:
        print(
            f"# {total / fs:.2f} s of signal in {dt:.2f} s ({total / fs / dt:.1f}x real time); "
            f"stats {demod.stats}",
            file=sys.stderr,
        )
    return 0


def cmd_selftest(args) -> int:
    from . import sim

    rng = np.random.default_rng(1)
    psdus = [sim.random_mpdu(rng, int(n)) for n in rng.integers(5, 128, args.frames)]
    n = len(psdus)
    print(f"{n} random frames (5..127 B) per run, fs 8 Msps, LO offset 2 MHz, CFO 80 kHz, clock 60 ppm")
    configs = [("diff", "coherent"), ("disc", "coherent"), ("disc", "disc")]
    print("  SNR (2 MHz)  " + "".join(f"{det + '+' + m:>18s}" for det, m in configs))
    print("               " + "".join(f"{s:>18s}" for s in ("(default)", "", "")))
    for snr in (-6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 7):
        x, _ = sim.make_stream(psdus, fs=8e6, snr_db=snr, cfo_hz=80e3, drift_ppm=60, if_hz=-2e6, seed=snr + 10)
        row = []
        for det, method in configs:
            d = Demodulator(fs=8e6, offset_hz=2e6, method=method, detector=det)
            got = {f.psdu for f in sim.run_demod(d, x, rng=rng) if f.fcs_ok}
            ok = sum(p in got for p in psdus)
            row.append(f"{ok:3d}/{n} ({100 * ok / n:3.0f}%)")
        print(f"  {snr:+3d} dB     " + "".join(f"{r:>18s}" for r in row))
    return 0


# --------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zbdemod", description="IEEE 802.15.4 / Zigbee demodulator for HackRF One")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, radio: bool):
        sp.add_argument(
            "--pcap",
            help="write decoded frames to a PCAP file; '-' streams PCAP to stdout "
            "(e.g. | wireshark -k -i -), frame lines then go to stderr",
        )
        sp.add_argument("--hex", action="store_true", help="print frame bytes")
        sp.add_argument("--bad", action="store_true", help="also report frames with bad FCS")
        sp.add_argument(
            "--method",
            choices=["coherent", "disc"],
            default="coherent",
            help="symbol decoder: coherent (default, ~4 dB more sensitive) or disc (FM discriminator)",
        )
        sp.add_argument(
            "--detector",
            choices=["diff", "disc"],
            default=None,
            help="SHR detector: diff (chip-differential, default for coherent, ~3 dB more "
            "sensitive) or disc (FM discriminator; the only one for --method disc)",
        )
        sp.add_argument(
            "--threshold",
            type=float,
            default=None,
            help="SHR correlation threshold 0..1 (default 0.22 diff / 0.30 disc+coherent / 0.45 disc)",
        )
        if radio:
            sp.add_argument("--fs", type=float, default=DEFAULT_FS, help="sample rate [Hz] (default 8e6)")
            sp.add_argument("--offset", type=float, default=DEFAULT_OFFSET, help="LO offset [Hz] (default 2e6)")
            # Lower gains leave the int8 ADC quantisation noise dominant (measured:
            # 32/20 -> noise -52 dBFS, ~3x fewer frames). Lower VGA if clip% > 0.1.
            sp.add_argument("--lna", type=int, default=40, help="LNA gain 0-40 dB, step 8 (default 40)")
            sp.add_argument("--vga", type=int, default=30, help="VGA gain 0-62 dB, step 2 (default 30)")
            sp.add_argument("--amp", action="store_true", help="enable the +14 dB RF amplifier")
            sp.add_argument("--serial", help="HackRF serial number")

    sp = sub.add_parser("live", help="decode a channel live")
    sp.add_argument("-c", "--channel", type=int, required=True, help="channel 11..26")
    sp.add_argument("-d", "--duration", type=float, default=0, help="stop after N seconds")
    sp.add_argument("--status", type=float, default=10, help="status line every N s (0 = off)")
    common(sp, True)
    sp.set_defaults(func=cmd_live)

    sp = sub.add_parser("scan", help="hop over channels and count frames")
    sp.add_argument("-c", "--channels", default="11-26", help="e.g. 11-26 or 11,15,20,25")
    sp.add_argument("--dwell", type=float, default=5.0, help="seconds per channel")
    sp.add_argument("--loops", type=int, default=1)
    common(sp, True)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("record", help="record raw int8 IQ to a file")
    sp.add_argument("-c", "--channel", type=int, required=True)
    sp.add_argument("-d", "--duration", type=float, required=True, help="seconds")
    sp.add_argument("-o", "--output", required=True)
    common(sp, True)
    sp.set_defaults(func=cmd_record)

    sp = sub.add_parser("file", help="decode a recording (cs8 / cf32)")
    sp.add_argument("input")
    sp.add_argument("--fs", type=float, help="sample rate (default: sidecar or 8e6)")
    sp.add_argument("--offset", type=float, help="LO offset of the recording (default: sidecar or 0)")
    sp.add_argument("--channel", type=int)
    sp.add_argument("--format", choices=["cs8", "cf32"])
    common(sp, False)
    sp.set_defaults(func=cmd_file)

    sp = sub.add_parser(
        "map",
        help="map of the Zigbee networks in range, live in the browser",
        description="Serve a live map of the networks, devices and radio links heard "
        "(HackRF, recordings or PCAP files) and open it in the browser.",
    )
    sp.add_argument(
        "-c",
        "--channels",
        help="channel(s) for the HackRF: 15, or 11-26 / 11,15,20,25 to hop (default 11); "
        "can be changed from the page",
    )
    sp.add_argument("--dwell", type=float, default=5.0, help="seconds per channel when hopping (default 5)")
    sp.add_argument(
        "--read",
        action="append",
        metavar="PCAP",
        help="build the map from a PCAP/PCAPNG capture instead of the HackRF (repeatable)",
    )
    sp.add_argument(
        "--file",
        action="append",
        metavar="REC",
        help="build the map from a raw IQ recording (.cs8/.cf32 + .json sidecar) instead of the HackRF (repeatable)",
    )
    sp.add_argument(
        "--names",
        help="device names: JSON {\"<IEEE>\": \"name\"}, or zigbee2mqtt's configuration.yaml / database.db",
    )
    sp.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to serve the page on (default 127.0.0.1: this computer only)",
    )
    sp.add_argument("--port", type=int, default=8088, help="HTTP port (default 8088, next free one if taken)")
    sp.add_argument("--no-browser", action="store_true", help="do not open the browser")
    sp.add_argument("-v", "--verbose", action="store_true", help="also print every frame")
    common(sp, True)
    sp.set_defaults(func=cmd_map)

    sp = sub.add_parser("selftest", help="synthetic end-to-end test (no hardware)")
    sp.add_argument("--frames", type=int, default=100)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser(
        "extcap-install",
        help="install the Wireshark extcap interface (Zigbee capture from Wireshark's interface list)",
    )
    sp.add_argument("--dir", help="extcap folder (default: Wireshark's personal extcap folder)")
    sp.add_argument("--uninstall", action="store_true", help="remove the interface")
    sp.set_defaults(func=cmd_extcap_install)
    return p


def cmd_map(args) -> int:
    from . import webmap

    return webmap.main(args)


def cmd_extcap_install(args) -> int:
    from . import extcap

    return extcap.install(args.dir, uninstall=args.uninstall)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except PipeClosed:  # e.g. 'zbdemod file x.cs8 --pcap - | tshark -c 3 -r -'
        release_dead_stdout()
        return 0


if __name__ == "__main__":
    sys.exit(main())
