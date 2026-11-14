"""Wireshark extcap interface: live Zigbee capture from Wireshark's interface list.

After `zbdemod extcap-install`, Wireshark lists "Zigbee / IEEE 802.15.4 (HackRF One)"
as a capture interface. Its options dialog sets the channel, gains and receiver
options; decoded frames then appear in Wireshark live. A recording can be
selected instead of the HackRF.

extcap protocol (see the Wireshark Developer's Guide, "Extcap"):

    --extcap-interfaces                          list interfaces
    --extcap-dlts   --extcap-interface IF        link-layer type of IF
    --extcap-config --extcap-interface IF        options for the capture dialog
    --capture       --extcap-interface IF --fifo PATH [options]
                                                 write a PCAP stream to PATH
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from . import __version__, phy
from .pcap import LINKTYPE_IEEE802_15_4_TAP, PcapWriter

INTERFACE = "zbdemod"
DISPLAY = "Zigbee / IEEE 802.15.4 (HackRF One)"
HELP_URL = "https://github.com/venglin/zigbee-sniffer"
WRAPPER = "zbdemod-extcap"
DEFAULT_CHANNEL = 11


# ----------------------------------------------------------------- protocol
def interfaces_text() -> str:
    return (
        f"extcap {{version={__version__}}}{{help={HELP_URL}}}\n"
        f"interface {{value={INTERFACE}}}{{display={DISPLAY}}}\n"
    )


def dlts_text() -> str:
    return f"dlt {{number={LINKTYPE_IEEE802_15_4_TAP}}}{{name=IEEE802_15_4_TAP}}{{display=IEEE 802.15.4 TAP}}\n"


def config_text() -> str:
    lines = [
        "arg {number=0}{call=--channel}{display=Channel}"
        "{tooltip=IEEE 802.15.4 channel in the 2.4 GHz band}{type=selector}{group=Radio}"
    ]
    for ch in range(11, 27):
        default = "true" if ch == DEFAULT_CHANNEL else "false"
        lines.append(
            f"value {{arg=0}}{{value={ch}}}{{display={ch} ({phy.channel_freq(ch) / 1e6:.0f} MHz)}}"
            f"{{default={default}}}"
        )
    lines += [
        "arg {number=1}{call=--lna}{display=LNA gain (dB)}{tooltip=0-40 dB in 8 dB steps}"
        "{type=integer}{range=0,40}{default=40}{group=Radio}",
        "arg {number=2}{call=--vga}{display=VGA gain (dB)}"
        "{tooltip=0-62 dB in 2 dB steps; lower it if signals clip}"
        "{type=integer}{range=0,62}{default=30}{group=Radio}",
        "arg {number=3}{call=--amp}{display=RF amplifier (+14 dB)}"
        "{tooltip=HackRF front-end amplifier; often damaged, leave off if signals vanish}"
        "{type=boolflag}{default=false}{group=Radio}",
        "arg {number=4}{call=--serial}{display=HackRF serial number}"
        "{tooltip=Empty = first HackRF found}{type=string}{group=Radio}",
        "arg {number=5}{call=--bad}{display=Include frames with a bad FCS}"
        "{tooltip=Wireshark marks them as having a wrong FCS}{type=boolflag}{default=false}{group=Receiver}",
        "arg {number=6}{call=--method}{display=Symbol decoder}{type=selector}{group=Receiver}",
        "value {arg=6}{value=coherent}{display=coherent (most sensitive)}{default=true}",
        "value {arg=6}{value=disc}{display=FM discriminator}{default=false}",
        "arg {number=7}{call=--threshold}{display=Detection threshold}"
        "{tooltip=0 = default for the decoder (0.22 coherent, 0.45 discriminator)}"
        "{type=double}{range=0,1}{default=0}{group=Receiver}",
        "arg {number=8}{call=--file}{display=Decode a recording instead of the HackRF}"
        "{tooltip=.cs8 or .cf32 file made with 'zbdemod record' (uses its .json sidecar)}"
        "{type=fileselect}{mustexist=true}{group=Input}",
    ]
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zbdemod-extcap", description="Wireshark extcap for zigbee-sniffer")
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-version")
    p.add_argument("--extcap-interface")
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--extcap-capture-filter")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--fifo")
    p.add_argument("--channel", type=int, default=DEFAULT_CHANNEL)
    p.add_argument("--lna", type=int, default=40)
    p.add_argument("--vga", type=int, default=30)
    p.add_argument("--amp", action="store_true")
    p.add_argument("--serial", default="")
    p.add_argument("--bad", action="store_true")
    p.add_argument("--method", choices=["coherent", "disc"], default="coherent")
    p.add_argument("--threshold", type=float, default=0.0)
    p.add_argument("--file", default="")
    return p


def main(argv: list[str] | None = None) -> int:
    args, _unknown = build_parser().parse_known_args(argv)
    if args.extcap_interfaces:
        sys.stdout.write(interfaces_text())
        return 0
    if args.extcap_interface and args.extcap_interface != INTERFACE:
        print(f"unknown interface {args.extcap_interface!r}", file=sys.stderr)
        return 1
    if args.extcap_dlts:
        sys.stdout.write(dlts_text())
        return 0
    if args.extcap_config:
        sys.stdout.write(config_text())
        return 0
    if args.capture:
        if not args.fifo:
            print("--capture needs --fifo", file=sys.stderr)
            return 1
        return capture(args)
    build_parser().print_help(sys.stderr)
    return 1


# ------------------------------------------------------------------ capture
def _raise_interrupt(signum, frame) -> None:
    raise KeyboardInterrupt


def _stop_with_parent() -> None:
    """Raise KeyboardInterrupt in the main thread when we should stop, so the
    HackRF is closed cleanly: on SIGTERM (Wireshark on Linux/macOS), or when the
    parent process dies (Windows: Wireshark terminates the .bat wrapper's cmd.exe,
    which would otherwise leave this process running with the HackRF open)."""
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _raise_interrupt)
        except ValueError:  # not in the main thread
            pass
    if sys.platform != "win32":
        return
    import _thread
    import ctypes

    SYNCHRONIZE = 0x00100000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    handle = kernel32.OpenProcess(SYNCHRONIZE, 0, os.getppid())
    if not handle:
        return

    def watch() -> None:
        kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        _thread.interrupt_main()

    threading.Thread(target=watch, daemon=True).start()


def capture(args) -> int:
    from . import cli

    try:
        fifo = open(args.fifo, "wb", buffering=0)
    except OSError as exc:
        print(f"cannot open {args.fifo}: {exc}", file=sys.stderr)
        return 1
    writer = PcapWriter(fifo)
    printer = cli.Printer(False, writer, quiet=True, pcap_bad=args.bad)
    common = dict(
        threshold=args.threshold or None,
        bad=args.bad,
        method=args.method,
        detector=None,
        hex=False,
    )
    if args.file:
        ns = SimpleNamespace(input=args.file, fs=None, offset=None, channel=None, format=None, **common)
        try:
            cli.decode_file(ns, printer, verbose=False)
        except cli.PipeClosed:
            pass
        except (OSError, ValueError) as exc:
            print(f"cannot decode {args.file}: {exc}", file=sys.stderr)
            return 1
        return 0

    from .hackrf import HackRFError

    ns = SimpleNamespace(
        channel=args.channel,
        offset=cli.DEFAULT_OFFSET,
        fs=cli.DEFAULT_FS,
        lna=args.lna,
        vga=args.vga,
        amp=args.amp,
        serial=args.serial or None,
        duration=0,
        status=0,
        **common,
    )
    _stop_with_parent()
    try:
        return cli.run_live(ns, printer, verbose=False)
    except HackRFError as exc:
        print(f"HackRF: {exc}", file=sys.stderr)
        return 1


# ------------------------------------------------------------------ install
def find_tshark() -> str | None:
    for cand in (
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ):
        if cand and Path(cand).is_file():
            return cand
    return None


def personal_extcap_dir() -> Path:
    """Wireshark's personal extcap folder (asked from tshark when available)."""
    tshark = find_tshark()
    if tshark:
        try:
            out = subprocess.run([tshark, "-G", "folders"], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines():
                if line.startswith("Personal Extcap path:"):
                    return Path(line.split(":", 1)[1].strip())
        except (OSError, subprocess.SubprocessError):
            pass
    if sys.platform == "win32":
        return Path(os.environ["APPDATA"]) / "Wireshark" / "extcap"
    return Path.home() / ".local" / "lib" / "wireshark" / "extcap"


def wrapper_text(python: str, package_parent: str, windows: bool) -> str:
    if windows:
        return (
            "@echo off\r\n"
            "rem Wireshark extcap wrapper for zigbee-sniffer (written by 'zbdemod extcap-install')\r\n"
            f'set "PYTHONPATH={package_parent};%PYTHONPATH%"\r\n'
            f'"{python}" -m zbdemod.extcap %*\r\n'
        )
    return (
        "#!/bin/sh\n"
        "# Wireshark extcap wrapper for zigbee-sniffer (written by 'zbdemod extcap-install')\n"
        f'PYTHONPATH="{package_parent}${{PYTHONPATH:+:$PYTHONPATH}}" exec "{python}" -m zbdemod.extcap "$@"\n'
    )


def install(target: str | None = None, uninstall: bool = False) -> int:
    windows = sys.platform == "win32"
    folder = Path(target) if target else personal_extcap_dir()
    path = folder / (WRAPPER + (".bat" if windows else ""))
    if uninstall:
        if path.exists():
            path.unlink()
            print(f"removed {path}")
        else:
            print(f"nothing to remove ({path} does not exist)")
        return 0
    folder.mkdir(parents=True, exist_ok=True)
    package_parent = str(Path(__file__).resolve().parent.parent)
    text = wrapper_text(sys.executable, package_parent, windows)
    if windows:
        path.write_bytes(text.encode("mbcs"))
    else:
        path.write_text(text)
        path.chmod(0o755)
    print(f"installed {path}")
    print(f"Restart Wireshark (or use Capture > Refresh Interfaces) and pick '{DISPLAY}'.")
    print("Uninstall with: zbdemod extcap-install --uninstall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
